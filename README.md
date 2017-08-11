This is a git repository on github.

To get it use

git clone https://github.com/clhedrick/kerberos.git

# Goals

1. Secure NFS. Make sure users can't install systems at an IP where
we've exported a file system and then access all files.

Also, because Kerberized NFS checks on a per-user basis, even if
someone becomes root on a machine, they can't compromise user files. A
user should only be exposed on a system where they are actually logged
in, or on which they run cron jobs. There's not much better I can do.

This should make it safe to allow faculty to mount our file systems on
machines they run.

2. Secure ssh. We allow ssh without passwords based on IP
address. This has obvious problems if users fake an IP address or
become root. A user must now have an actual ticket. We can still
restrict which groups of systems can access others, probably used
netgroup-based configuration in sshd_config.

# Challenges

1. Make Kerberos transparent. I'm dealing with this by supporting all
ways into a machine through pam, and by having a daemon that will keep
their credentials renewed as long as they have processes.

2. Support for multiple machine types. This is hard. Without
two-factor, Linux, Mac, and probably Windows (though I haven't tried)
can support it. Two factor uses recent features. Currently the key
part, kgetcred, works on Centos 5 - 7, and OS X (using the Macports
version of Kerberos). Windows turns out not to need this code, though
we depend upon special features in the GINA that we use.

Keeping Kerberos credentials working is more challenging than it
sounds. By default Centos puts credentials in a collection,
KEYRING:persistent:NNN where NNN is the UID. However if you kinit to
some other principal, e.g. to do administrative work, things get
complex. If KRB5CCNAME is set to a specific cache, kinit will replace
your credentials with the new one. A better approach is to set it to
the collection. Then kinit will generate a new credential cache. You
can switch between then using kswitch. However NFS will always look at
the primary cache. So if you're logged in as user, but are currently
switched to credentials for user-admin, NFS will try to use the
user-admin credentials, and you'll lose access to your home directory.

The only completely clean way to do this appears to be to keep a
second copy of the primary credentials. I put it in
/var/lib/gssproxy/clients, where gssproxy will use it. Then you can do
whatever you like with your main collection and it won't cause
problems with NFS.

# Suggested configuration

sssd for authentication for Centos 7, the vendor's pam_krb5 on other
systems. This will handle most users.

For users with 2FA, they can log into a Centos 7 system, then ssh to
an older machine. Credentials obtained with 2FA can still be forwarded
to older systems.

For older systems we could also use pam_ldap after pam_krb5. That
would let 2FA users login.  The only disadvantage to ldap is that it
won't give users Kerberos tickets.

## Which software do you need

At a mininum, to keep credentials alive you need renewd, pam_reg_cc
(which registered credentials to be renewed, and creates the copy in
/var/lib/gssproxy/clients), and krenew-wrap, which wraps ssh in a
script that adds a custom library.

krenew-wrap is needed because the credentials forwarded by ssh often
have very short lifetimes. The wrapper renews the credentials before
forwarding them. The same thing could be done by a script

kinit -R; ssh "$@"

However kinit has a race condition during renewal, and my interposed
library does not.

If you want a secure way to do cron jobs, you need kgetcred (including
the pam module) and credserv.

If you want to be able to kinit with two factor authentication, you
need skinit, and also kgetcred and credserv (unless your kint supports
the -n option. I use kgetcred to get anonymous tickets, since IPA
currently doesn't support kinit -n).

# Design issues

Policies need to be chosen carefully to support our goals. In particular, Kerberos policies need to be adjusted. I'm using a nearly infinite renew time, to support very long sessions. 

Currently we're using the default 1 day ticket lifetime. However there's a
danger with that. The kernel normally keeps NFS contexts alive until the
ticket it uses expires. That means that after you log out, someone who can
use your uid (i.e. someone who is root) can access your files for up to a day.
That's more exposure than we hoped for.

To avoid this, we do two things: (1) renewd remove credentials within a couple
of minutes after you logout. But that's not enough if the kernel still has
them cached. So we run rpc.gssd with the argunent -t 600. That causes it to
recheck all of its contexts every 10 minutes. So when you logout, access to
files using your uid will go away at most 12 minutes later, but usually sooner.

# Programs 

## renewd

Many users stay logged in more or less forever. However our default
ticket lifetime is a day. Without default parameters, renewd will
renew tickets every 12 hours, as long as the user is still logged in.

Renewd also removes tickets after the user logs out, without a couple
of minutes.

Renewd depends upon pam_reg_cc to tell it what tickets it should look
at.

## credserv and kgetcred

What do we do about users who need to run cron jobs or daemons? Our
students often have assignments that require this. The usual answer is
a keytable. But if someone becomes root, they can take anyone's
keytable. And having a user's key table permanetly exposes them on all
systems.

So instead kgetcred works with a server (credserv) to issue tickets
for cron jobs. The user registers with credserv, using "kgetcred -r".
Credserv records the fact that root is allowed to get credentials
for that user on that host. The tickets are issued by credserv and
forwarded to kgetcred. The tickets are (by default) not forwardable
and locked to the IP address of the client.

kgetcred -a also simulates kinit -n. It gets credentials for an
unprivileged user. This can be used for kinit -T, to support two
factor kinit.

There is a version of the same code as kgetcred, but made into a pam
module. We install that for cron. That means that cron will get 
tickets for the user automatically. The only thing the user needs to
do is register with "kgetcred -r".

## skinit

Kinit for users with OTP. 

With one time passwords, kinit requires "armor." skinit gets a ticket
for anonymous.user, using kgetcred -a, and uses it to armor the
request. Arguments are just passed on to the main kinit call.

If your setup supports kinit -n, you might prefer to modify skinit to
use that rather than kgetcred -a.

## pam_kgetcred

This effectively calls kgetcred with default arguments, using a cache
name of /tmp/krb5cc_UID_xxxxxx.  It also sets KRB5CCNAME to the cache
name. It's designed to be used with crond.  The user has to register
using kgetcred -r to indicate that they want to run cron jobs on the
current system. At that point pam_kgetcred when called from crond will
set up credentials for them.

## pam_reg_cc

This registers the value of KRB5CCNAME (if any) so that renewd will
renew it. It also puts a second copy of the credentials in
/var/lib/gssproxy/clients, as explained above. If KRB5CCNAME is set to
a specific cache in the KEYRING, it will reset it to point to the
whole collection. That provides a consistent experience, since
normally ssh will set it differently depending upon how you login.

## mkhomedird and pam_kmkhomedir

In an NFS environment, pam_mkhomedir won't work, because root won't be
able to change ownership of new directories to the user. I have
created a server, which should run on the file server, and a pam
client to create home directories when necessary. They use a
Kerberized protocol between them.

## krenew_wrap.so

We have an issue with ssh. Ssh sends a ticket to the other
machine. But the lifetime of the ticket is only the amount of time
left on the current ticket. Suppose you start out with a ticket that's
good for an hour. 55 minutes into that you ssh to another machine. The
ticket on that machine will only be good for 5 min.

This makes automatic renewal difficult, because you'd have to renew it
every couple of minutes. Our process running very 50 min wouldn't
catch it.

To fix this, we also ssh to renew the ticket right before connecting
to the other machine. That gives you a ticket with the full
lifetime. Because renewing is not an atomic process, if you're unlucky
this could make NFS fail. (If it happens to recheck your credentials
at the exact same time ssh is renewing them.) So instead our code
creates a new, temporary cache in memory, and puts the renewed tickets
there.

This is done with an interposer library that adds code right after
krb5_init_context. To use it ssh should be a script that calls the
original program.

#!/bin/sh

LD_PRELOAD=/usr/libexec/krenew-wrap.so exec /usr/bin/ssh.real "$@"

## pam

The issue here is two factor authentication. Freeipa doesn't currently
support anonymous credentials with PKINIT.  I've modified Russ
Allbery's pam_krb5 to generate a temporary credential file based on
/etc/krb5.keytab. That can be used to armor transactions.

This handles ssh and login, but not things like screen savers. However
I really only need pam_krb5 for ways into machines, because they have
to set up a credentials cache. For a screen saver I can use
pam_ldap. The Freeipa LDAP server support two factor authentication.

I also made a minor patch to avoid an unnecessary second password prompt.

However we are probably going to use sssd rather than this. By the
time we roll this out for users, the systems should be updated to at
least Centos 7.



