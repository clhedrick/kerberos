This is a git repository on github.

To get it use

git clone https://github.com/clhedrick/kerberos.git

# Summary

This is support code for Kerberos and IPA, created as part of a project
to fully Kerberize the Rutgers CS department. We are specifically interested
in secure NFS. However the software here may be useful outside our
context. 

Aside from accounts, which is a system to automatically create and remove 
accounts based on user roles and what classes they are in, the rest of this
is software to workaround limitations in the way Linux supports Kerberos, 
and inconsistencies between the various tools.

The majority of work is the second category: making tools work together.
Many Kerberos-related tools work fine on their own. They just don't work
together. Here are notes on the specific pieces we've had to do:

## accounts

This is a system for creating groups and accounts based on what role
someone is in and what courses they are registered for. It's based on
rules, and designed to be portable to other environments. It might be useful for academic departments
elsewhere, though it would need minor changes. (If someone else actually
wants to use it, I'd be happy to work with them.)

Assumptions: user roles and course registration are avaiable in LDAP, with
additional role information in an SQL database. Specific queries are 
defined in the configuraiton file. You'd probably have to adjust Java code
slightly depending upon the format of our course identifiers.

It can be set to require people responsible for groups to review 
membership annually.

## credserv and kgetcred

Kerberos works cleanly for interactive logins, but how do you get credentials
for cron jobs? The usual documentation tells users to create key tables. There
are two issues with this (1) security; if someone can get your key table, they can 
be you anywhere at any time, and you'll probably never know it (2) at least with
IPA, users with two factor authentication can't use key tables.

We use a Kerberized client-server application. Credserv is the server. Kgetcred
will get Kerberos credentials for a specified user. It must be called by root.
The user must register that they want root to be able to get credentials for them
on specific machine. The credentials are by default not forwardable and have the IP
address of that machine built in. This provides a much more controlled approach than
a key table. The server duplicates some of the KDC code, and generates credentials
itself. That allows it to work for users with one-time passwords. Such users
should think carefully before using this, but there are situations where it 
makes sense. 

There's a pam version of kgetcred, which we use for cron jobs. The user
doesn't need to know how this works. Pam will see to it that cron issues
credentials for their job, as long as they have registered that they
want to cron to work on that machine.

This may also be useful as a sample if you want to know how to call
LDAP from C using GSSAPI authentication. The documentation for this is
not very easy to understand.

## renewd

Our users tend to stay logged in a lot. We don't want them to have their
credentials expire. (Remember, our home directories are on Kerberized NFS.)
Renewd renews active credentials. It knows which ones are active by looking
at KRB5CCNAME for all current processes (using /proc). Only credentials
registered at login (by pam_reg_cc) are renewed. 

Renewd also removes credentials that are no longer used. We want to limit
exposure of users to root. As long as you're logged in, you have a credential
cache, which root can read and use. But as soon as you log out, we want
to remove it. (We also run rpc.gssd with the option -T 600. That causes it
to recheck credentials every 10 minutes. So after logout, access to your
files via NFS is removed within 10 min.)

We're trying to simplify the way this is done, so renewd and pam_reg_cc
are likely to change. The code in both is specific to the credential
cache mechanism. Currently it supports /tmp files and KEYRING. KCM will
be supported when I'm convinced it is ready for use.

This may also be useful as a sample if you want to know how to call LDAP using
GSSAPI authenticaton from C. 

## pam_kmkhomedir and mkhomedird

There's a pam module pam_mkhomedir, that will create home directories
the first time you login. For local directories this works fine, since
root can do the mkdir. For Kerberized NFS, it fails, as root has no
special access. We have a kerberized client-server setup. mkhomedird
runs on the file server (or another system where the file system is
mounted without Kerberos). pam_kmkhomedir calls it if your home directory
doesn't exist. This can also be used for file systems other than 
home directories, with appropriate options.

## gssd-wrapper

This is only relevant to you if users have more than one Kerberos
principal. We have separate principals for administrative use. I.e.
user foo also has a principal foo-admin. (It should be foo/admin,
but IPA won't support that.) If KRB5CCNAME is set to a collection,
e.g. KEYRING:persistent:NNN, kinit will create a new credential
cache, but leave the existing one. So you can switch with kswitch.
(This is particularly useful with one-time passwords, where it's 
sort of a pain to type in your password.) 

Unfortunately this causes problems with NFS. If your principal 
expires (or gssd needs to recheck is, as ours does every 10 min),
it will use your current primary principal. If you've just 
switched to foo-admin, it will try to set up an NFS context with
that principal, and presumably fail. gssd-wrapper intercepts the
call to gssapi, and tell gssapi to look for the correct principal
in your collection. As long as there's an active principal for
foo, it will be used, even if the current primary principal is
foo-admin.

This would be trivial to fix in gssd itself, but we can't get 
anyone's attention. We fix it with a small library that is 
added into gssd with LD_PRELOAD.

## krenew-wrap

This is a hack for ssh. Ssh passes your Kerberos credentials
to the other system. but the way Kerberos works, you end up
with credentials that don't necessarily have a very long 
lifetime. Suppose your credentials last for 12 hours, and 11.75
hours into that you ssh to another system. On that system you
now have credentials that last for 15 min. Renewd is going to
have to renew them evey 15 min, which is silly (and renewd
won't even do it).

This wrapper causes ssh to renew your credentials before
passing them to the other end, assuming they are renewable.
That way you end up with credentials with their full lifetime.

## pam-reg-cc

This does two things: (1) It registers credentials to be
renewed by renewd. See above (2) It normalizes them to work
around issues in sshd.

Depending upon your version of sshd, you have one of two
problems 

(1) With Centos, if /etc/krb5.conf is set to 
KEYRING, it puts credentials in the keyring, but sets
KRB5CCNAME to the specific credential, e.g.
KEYRING:persistent:123:krb_ccache_VtilcGC. For kinit
and kswitch to work properly, you want to set it to
the collection, i.e. KEYRING:persistent:123. pam_reg_cc
will fix up KRB5CCNAME in this case

(2) With Ubuntu, sshd puts credentials in a file in /tmp,
even if /etc/krb5.conf specifies KEYRING. pam_reg_cc
will move the credentials into the place defined in
/etc/krb5.conf, and set KRB5CCNAME to the collection.

## skinit

If you use a one-time password, kinit won't work in the
usual way. You need an initial credential cache, which
you pass with the -T argument. skinit works just like
kinit, but it works with one-time passwords. It gets
an anonymous credential cache and passes the name as -T.
It kills the cache once you have your credentials.

There are two ways to get the anonymous credentials. 
If your system supports kinit -n, that can be used.
Otherwise it uses a special option to kgetcred and
credserv generates the credentials and returns them.
The kgetcred version is probably best, since kinit -n
depends upon a certificate that will have to be
renewed annually and distributed to every client.

## radius-wrap

This is designed to allowo Freeradius to support one-time passwords.
Freeradius supports Kerberos authentication, but it won't work
with users who have one-time passwords. This small module is
designed to be used with LD_PRELOAD. It interposes code around
krb5_get_init_creds_password to handle one-time passwords, as
long as all factors can put on one line. (E.g. with IPA you
can put your 6-digit one-time password at the end of your
normal password, on the same line.)

This is also a simple example of how to write code to process
one-time passwords in C.


