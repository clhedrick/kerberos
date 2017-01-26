This is a git repository on github.

To get it use

git clone https://github.com/clhedrick/kerberos.git

I'm keeping a copy on /staff/src for consistency with other software, but the primary
repository is github. If you need to change it please ask hedrick to add you to the
repository.

Note that much of this is based on various code by Russ Allbery.

# Goals

1. Secure NFS. Make sure users can't install systems at an IP where we've exported a file system and then access all files.

Also, because Kerberized NFS checks on a per-user basis, even if someone becomes root on a machine, they can't compromise user files. A user should only be exposed on a system where they are actually logged in, or on which they run cron jobs. There's not much better I can do.

This should make it safe to allow faculty to mount our file systems on machines they run.

2. Secure ssh. We allow ssh without passwords based on IP address. This has obvious problems if users fake an IP address or become root. A user must now have an actual ticket. We can still restrict which groups of systems can access others, probably used netgroup-based configuration in sshd_config.

# Challenges

1. Make Kerberos transparent. I'm dealing with this by supporting all ways into a machine through pam, and by having a daemon that will keep their credentials renewed as long as they have processes.

2. Support for multiple machine types. This is hard. Without two-factor, Linux, Mac, and probably Windows (though I haven't tried) can support it. Two factor uses recent features. Currently it only works on Centos 7 and possibly 6. It should work on recent versions of other distributions as well. Unfortunately Apple is not using the standard MIT Kerberos, so I don't know when they'll support 2FA.

Suggested configuration:

pam_krb5, mine on Centos 7, the vendor's on other systems. This will handle most users.

For users with 2FA, they can ssh into the machine from a Centos 7 system, or we can supply a script that ssh's to such a machine and then ssh's back. That will do the 2FA and put a ticket on the machine. I'm using a script like that on my Mac.

We can also use pam_ldap. The ldap server on the kdc supports 2FA for binding to LDAP if the user is configured to require it. The only disadvantage to ldap is that it won't give users Kerberos tickets.

# Design issues

Policies need to be chosen carefully to support our goals. In particular, Kerberos policies need to be adjusted. I'm using a nearly infinite renew time, to support very long sessions. However credentials should probably be set to expire fairly quickly (in /etc/krb5.conf.) Currently for testing it's set to a day, but in production it should probably be an hour. The issue is that once you access a file over NFS, access is cached. The cached permission will last as long as the original ticket was valid. When a user logs out, we'd like his access to expire fairly quickly. Since we're doing automatic renew, a fairly short expiration should be fine.

# Programs 

## renewd

Many users stay logged in more or less forever. We don't want long ticket lifetimes, because that leaves their NFS
connections exposed after they logout. So instead the plan is to expire in 1 hour, but have a daemon that
renews tickets for anyone with a job currently running. The code currently support only Linux KEYRING, because
it's easier to make the process race-free that way. It could be extended to support other types with a bit of work

## credserv and kgetcred

What do we do abotu users who need to run cron jobs or daemons? Our students often have assignments that require
this. THe usual answer is a keytable. But if someone becomes root, they can take anyone's keytable. And having a user's key table permanetly exposes them on all systems.

So instead the plan is to have them register a keytab on a central server (through a web application) and specify the
host where they'll be using a cron job. credserv / kgetcred will generate credentials based on the keytab and
put it on their system. They will be locked to an ip address and not forwardable. This is about the best protection
I can think of.

## pam

The issue here is two factor authentication. Freeipa doesn't currently support anonymous credentials with PKINIT.
I've modified Russ Allbery's pam_krb5 to generate a temporary credential file based on /etc/krb5.keytab. That can
be used to armor transactions.

This handles ssh and login, but not things like screen savers. However I really only need pam_krb5 for ways into 
machines, because they have to set up a credentials cache. For a screen saver I can use pam_ldap. The Freeipa
LDAP server support two factor authentication.

I also made a minor patch to avoid an unnecessary second password prompt.

