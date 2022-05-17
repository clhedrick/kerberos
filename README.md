This is a git repository on github.

To get it use

git clone https://github.com/clhedrick/kerberos.git

# Summary

This is support code for Kerberos and IPA, created as part of a
project to fully Kerberize the Rutgers CS department. We are
specifically interested in secure NFS. However the software here may
be useful outside our context.

Aside from accounts, which is a system to automatically create and
remove accounts based on user roles and what classes they are in, the
rest of this is software to workaround limitations in the way Linux
supports Kerberos, and inconsistencies between the various tools.

The majority of work is the second category: making tools work
together.  Many Kerberos-related tools work fine on their own. They
just don't work together. Here are notes on the specific pieces we've
had to do:

## I am trying to simplify how some of this works. There is a directory
"new" that has new versions, currently a renew script that doesn't depend
upon any pam modules.

However you might still want to use pam-fixcc to fix up the location
of the ticket when you ssh. Ssh ignore /etc/krb5.conf, always putting
the ticket in /tmp. This is a probem if you commonly use kinit with
another principal, e.g. temporarily kinit as an administrative
principal. Unless do something special, it will overwrite your normal
ticket. KEYRING, KCM, or even DIR is a better place for your primary
ticket.

## accounts

This is a system for creating groups and accounts based on what role
someone is in and what courses they are registered for. It's based on
rules, and designed to be portable to other environments. It might be useful for academic departments
elsewhere, though it would need minor changes. (If someone else actually
wants to use it, I'd be happy to work with them.)

It also has support to manage DHCP entries in LDAP. Our customizations to the IPA command allow this data to be managed from the commandline using "ipa" as well as the web app. The IPA command doesn't support every aspect of the DHCP schema, but it supports the most common features. The web app supp9orts only what we actually use, which is a subset.

Assumptions: user roles and course registration are avaiable in a University LDAP server, with
additional role information in an SQL database run by our department. Specific queries are 
defined in the configuraiton file, so the data you're interested in could be different. You'd probably have to adjust Java code
slightly depending upon the format of our course identifiers.

It can be set to require people responsible for groups to review 
membership periodically (we're doing it annually).

## credserv and kgetcred

Kerberos works cleanly for interactive logins, but how do you get
credentials for cron jobs? The usual documentation tells users to
create key tables. There are two issues with this (1) security; if
someone can get your key table, they can be you anywhere at any time,
and you'll probably never know it (2) at least with IPA, users with
two factor authentication can't use key tables.

We use a Kerberized client-server application. Credserv is the
server. Kgetcred is the client. Kgetcred is intended to be called at
the beginning of the cron job to get credentials and put them in
KRB5CCNAME. However the same code is available in a pam module.  If
you use that, users won't need to call kgetcred themselves. Kgetcred
also has options that let the user authorized systems that can do
this.

Kgetcred will get Kerberos credentials for a specified user and put
them in the cache defined by KRB5CCNAME. It must be called by root.
The user must register that they want root to be able to get
credentials for them on specific machine. The credentials are by
default not forwardable and have the IP address of that machine built
in. This provides a much more controlled approach than a key
table. The server duplicates some of the KDC code, and generates
credentials itself. That allows it to work for users with one-time
passwords. Such users should think carefully before using this, but
there are situations where it makes sense.

There's a pam version of kgetcred, which we use for cron jobs. The
user doesn't need to know how this works. Pam will see to it that cron
issues credentials for their job, as long as they have registered that
they want to cron to work on that machine.

This may also be useful as a sample if you want to know how to call
LDAP from C using GSSAPI authentication. The documentation for this is
not very easy to understand.

## renewd

[this will be replaced by new/renewd]

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

We're trying to simplify the way this is done, so renewd and
pam_reg_cc are likely to change. The code in both is specific to the
credential cache mechanism, e.g, temp file, KEYRING, KCM. There's a
library in common that has all the code that depends upon the
mechanism. It should be possible to add a new one just by changing
that library. Currently only types used on Linux are supported.

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

## ccselect-plugin

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
that principal, and presumably fail. 

ccselect-plugin contains a plugin that will cause GSSAPI to pick the
principal that's based on your username when the service is nfs

This replaces gssd-wrap, which accomplished the same thing. 
However gssd-wrap was sort of a hack, that could conceivably
be broken by code changes. This uses a documented interface.

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

[this is not needed with new/renewd]

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
will fix up KRB5CCNAME in this case. (The code will
actually work with any collection type. It uses a library
that understands the specifics of various collection types.)

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

This is designed to allow Freeradius to support one-time passwords.
Freeradius supports Kerberos authentication, but it won't work
with users who have one-time passwords. This small module is
designed to be used with LD_PRELOAD. It interposes code around
krb5_get_init_creds_password to handle one-time passwords, as
long as all factors can put on one line. (E.g. with IPA you
can put your 6-digit one-time password at the end of your
normal password, on the same line.)

This is also a simple example of how to write code to process
one-time passwords in C.

## dhcp-ldap

Instructions for integrating the ISC dhcpd. Our accounts application
will manage DHCP data in LDAP. This has setup instructions and a 
patch for the LDAP server.

## rquotad

This has nothing to do with Kerberos. It is a patch to rpc.rquotad to
support quotas for ZFS file systems.  This particular version supports
just ZFS, though supporting a mix of file system types would be easy.

## svcgssd

Fixes a bug that causes group changes not to show up on Kerberized NFS servers

## nvidia-wrap

Nothing do with kerberos. Program for use on systems where SLURM controls
access to GPUs. We want interactive users to be able to use nvidia-smi
to see GPU use, even though only Slurm jobs actually have access to the
GPUs. This changes cgroup to one that can open gpus and then runs 
nvidia-smi with no arguments. Must be installed setuid root

## guacamole-auth and rdp

Make guacamole work with two factor auth.

guacamole-auth is an authentication plugin that uses /usr/libexec/skinit to
authenticate and ldap to find the list of hosts. /usr/libexec/skinit
does kinit -k -t /etc/krb5.keytab to set up a temporary ccache and
kinit -T pointing to that cache. This is needed for two factor auth.

The kerberos ticket is stored in /var/spool/guacamole with a name that
includes a random uuid. That uuid is sent as the password.

rdp/pam_krdp calls a service rdpserv on the guacamole server passing it
the username and uuid. It gets back the ticket from /var/spool/guacamole.

This only works for 2 hours after login. At some point we need to expire
the credentials, since we have no way to tell how long guacamole still
thinks there's a session. there should be a cron job to kill the
tickets in /var/spool/guacamole after 2 hours.

However I've reconsidered whether I really want to do this. FOr the
moment all I'm using is guacamole-auth. In this version it checks for
OTP users and clears their passwords. That causes the end system to
give a normal password prompt. WIthout this they get a confusing error.
