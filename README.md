This is a git repository on github.

To get it use

git clone https://github.com/clhedrick/kerberos.git

# Goals

1. Secure NFS. Make sure users can't install systems at an IP where we've exported a file system and then access all files.

Also, because Kerberized NFS checks on a per-user basis, even if someone becomes root on a machine, they can't compromise user files. A user should only be exposed on a system where they are actually logged in, or on which they run cron jobs. There's not much better I can do.

This should make it safe to allow faculty to mount our file systems on machines they run.

2. Secure ssh. We allow ssh without passwords based on IP address. This has obvious problems if users fake an IP address or become root. A user must now have an actual ticket. We can still restrict which groups of systems can access others, probably used netgroup-based configuration in sshd_config.

# Challenges

1. Make Kerberos transparent. I'm dealing with this by supporting all ways into a machine through pam, and by having a daemon that will keep their credentials renewed as long as they have processes.

2. Support for multiple machine types. This is hard. Without two-factor, Linux, Mac, and probably Windows (though I haven't tried) can support it. Two factor uses recent features. Currently the key part, kgetcred, works on Centos 5 - 7, and OS X (using the Macports version of Kerberos). Windows turns out not to need this code, though we depend upon special features in the GINA that we use.

Keeping Kerberos credentials working is more challenging than it sounds. By default Centos puts credentials in a collection, KEYRING:persistent:NNN where NNN is the UID. However if you kinit to some other principal, e.g. to do administrative work, things get complex. If KRB5CCNAME is set to a specific cache, kinit will replace your credentials with the new one. A better approach is to set it to the collection. Then kinit will generate a new credential cache. You can switch between then using kswitch. However NFS will always look at the primary cache. So if you're logged in as user, but are currently switched to credentials for user-admin, NFS will try to use the user-admin credentials, and you'll lose access to your home directory.

The only completely clean way to do this appears to be to keep a second copy of the primary credentials. I put it in
/var/lib/gssproxy/clients, where gssproxy will use it. Then you can do whatever you like with your main collection and it won't cause problems with NFS.

# Suggested configuration

sssd for authentication for Centos 7, the vendor's pam_krb5 on other systems. This will handle most users.

For users with 2FA, they can log into a Centos 7 system, then ssh to an older machine. Credentials obtained with 2FA can still be forwarded to older systems.

For older systems we could also use pam_ldap after pam_krb5. That would let 2FA users login.
The only disadvantage to ldap is that it won't give users Kerberos tickets.

## Which software do you need

At a mininum, to keep credentials alive you need renewd, pam_reg_cc (which registered credentials to be renewed, and creates the copy in /var/lib/gssproxy/clients), and krenew-wrap, which wraps ssh in a script that adds a custom library.

krenew-wrap is needed because the credentials forwarded by ssh often have very short lifetimes. The wrapper renews the
credentials before forwarding them. The same thing could be done by a script

kinit -R; ssh "$@"

However kinit has a race condition during renewal, and my interposed library does not.

If you want a secure way to do cron jobs, you need kgetcred (including the pam module) and credserv.

If you want to be able to kinit with two factor authentication, you need skinit, and also kgetcred and credserv (unless your kint supports the -n option. I use kgetcred to get anonymous tickets, since IPA currently doesn't support kinit -n).

# Design issues

Policies need to be chosen carefully to support our goals. In particular, Kerberos policies need to be adjusted. I'm using a nearly infinite renew time, to support very long sessions. However credentials should probably be set to expire fairly quickly (in /etc/krb5.conf.) Currently for testing it's set to a day, but in production it should probably be an hour. The issue is that once you access a file over NFS, access is cached. The cached permission will last as long as the original ticket was valid. When a user logs out, we'd like his access to expire fairly quickly. Simply destroying the credentials won't cut off NFS access. That only happens when the ticket expires and isn't renewed. Since we're doing automatic renew, a fairly short expiration should be fine.

# Programs 

## renewd

Many users stay logged in more or less forever. We don't want long ticket lifetimes, because that leaves their NFS
connections exposed after they logout. So instead the plan is to expire in 1 hour, but have a daemon that
renews tickets for anyone with a job currently running. The code currently renews only caches that have been registered
in the session keyring using either pam_reg_cc (whose only purpose is register the current cache) or pam_kgetcred (which
is intended for use with cron to get a credential cache and register it). The session keyring is automatically deleted
at the end of the session, so this saves us from having to track sessions.

## credserv and kgetcred

What do we do about users who need to run cron jobs or daemons? Our students often have assignments that require
this. The usual answer is a keytable. But if someone becomes root, they can take anyone's keytable. And having a user's key table permanetly exposes them on all systems.

So instead the plan is to have them register a keytab on a central server, using the administrative
functions of kgetcred, specifyibg the
host where they'll be using a cron job. credserv / kgetcred will generate credentials based on the keytab and
put it on their system. They will be locked to an ip address and not forwardable. This is about the best protection
I can think of.

kgetcred -a also simulates kinit -n. It gets credentials for an unprivileged user. This can be used for kinit -T,
to support two factor kinit.

In most cases users won't need to call kgetcred to get credentials. We expect that pam_kgetcred will be used

## skinit

Kinit for users with OTP. 

With one time passwords, kinit requires "armor." skinit gets a ticket for anonymous.user, using kgetcred -a,
and uses it to armor
the request. Arguments are just passed on to the main kinit call. 

If your setup supports kinit -n, you might prefer to use that rather than kgetcred -a.

## pam_kgetcred

This effectively calls kgetcred with default arguments, using a cache name of /tmp/krb5cc_UID_cron.
It also sets KRB5CCNAME to the cache name, and registers it for renewd. It's design to be used with crond.
The user has to register using kgetcred -r to indicate that they want to run cron jobs on the current
system. At that point pam_kgetcred when called from crond will set up credentials for them.

## pam_reg_cc

This registers the value of KRB5CCNAME (if any) so that renewd will renew it. It also puts a second copy of
the credentials in /var/lib/gssproxy/clients, as explained above. If KRB5CCNAME is set to a specific cache
in the KEYRING, it will reset it to point to the whole collection. That provides a consistent experience,
since normally ssh will set it differently depending upon how you login.

## mkhomedird and pam_kmkhomedir

In an NFS environment, pam_mkhomedir won't work, because root won't be able to change ownership of
new directories to the user. I have created a server, which should run on the file server, and a
pam client to create home directories when necessary. They use a Kerberized protocol between them.

## krenew_wrap.so

We have an issue with ssh. Ssh sends a ticket to the other machine. But the lifetime of the ticket 
is only the amount of time left on the current ticket. Suppose you start out with a ticket that's
good for an hour. 55 minutes into that you ssh to another machine. The ticket on that machine will
only be good for 5 min. 

This makes automatic renewal difficult, because you'd have to renew it every couple of minutes. Our
process running very 50 min wouldn't catch it.

To fix this, we also ssh to renew the ticket right before connecting to the other machine. That gives
you a ticket with the full lifetime. Because renewing is not an atomic process, if you're unlucky
this could make NFS fail. (If it happens to recheck your credentials at the exact same time ssh is
renewing them.) So instead our code creates a new, temporary cache in memory, and puts the renewed
tickets there. 

This is done with an interposer library that adds code right after krb5_init_context. To use it
ssh should be a script that calls the original program.

#!/bin/sh

LD_PRELOAD=/usr/libexec/krenew-wrap.so exec /usr/bin/ssh.real "$@"

## pam

The issue here is two factor authentication. Freeipa doesn't currently support anonymous credentials with PKINIT.
I've modified Russ Allbery's pam_krb5 to generate a temporary credential file based on /etc/krb5.keytab. That can
be used to armor transactions.

This handles ssh and login, but not things like screen savers. However I really only need pam_krb5 for ways into 
machines, because they have to set up a credentials cache. For a screen saver I can use pam_ldap. The Freeipa
LDAP server support two factor authentication.

I also made a minor patch to avoid an unnecessary second password prompt.

However we are probably going to use sssd rather than this. By the time we roll this out for users, the systems
should be updated to at least Centos 7.

# Recommended setup

We want to support the concept of a cache collection, so we can have
a primary cache with our normal credentials, but other caches with
administrative credentials. Getting the right options is tricky, because
of how NFS uses the KEYRING.

NFS expects credentials for your normal username to be in whatever
cache is named as the default in krb5.conf. If you are using the KEYRING,
you'll normally set the default cache in krb5.conf to KEYRING:persistent:%{uid}.
That is, you'll end up with KRB5CCNAME set to a collection.

When krb5.conf is set to use collections, NFS (actually rpc.gssd) uses the
primary cache in the collection to authenticate the user. That's normally
fine. But if the user kinit's as another principal (e.g. an administrator),
and NFS reevaluates credentials, the NFS access will fail.

NFS only rechecks credentials when the old ones expire. So this may not
happen very often. But if your primary credential is wrong at that time, you will lose
access to NFS until the credentials expire. That's why pam_reg_cc puts a copy
of your primary credentials in /var/lib/gssproxy/clients.

We suggest setting up cron jobs to use credentials in /tmp, to avoid this
kind of issue. But for interactive jobs, where a user might kinit as 
a different principal, there are dangers to setting KRB5CCNAME to a file
in /tmp. By default, kinit will overwrite whatever credentials are in
the file. Hence we think it's safer to use a collection, even though it's
subject to issues as well, and depend upon the second copy in /var/lib/gssproxy/clients.

For cron jobs we recommend configuring pam_kgetcred to use ccname=FILE:/tmp/krb5cc_%{uid}_XXXXXX.
That makes them independent of what's going on in interactive sessions.
If the user kinits to admin, and changes their primary cache, you don't
want it impacting any batch jobs that are running.


