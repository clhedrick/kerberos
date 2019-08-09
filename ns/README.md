This has nothing to do with Kerberos. It's a command to run whatever
you give it in a separate per-user network namespace.  It's designed
for gazebo, since gazebo uses localhost for its various pieces to tali
to each other. We want students to be able to run gazebo without
interfering with other students, and without other students being able
to watch their session.

runinns.c is a setuid program that runs whatever you pass as its
argument in a namespace associated with the user. If the namespace
doesn't exist, it calls /usr/libexec/create.py to create it.

A cron job should run /usr/libexec/killns.py periodically to kill
namespaces that are no longer in use.

This assumes that iptables is active, because it needs an iptables
entry to set up a NAT so the namespace can contact the Internet. It
will enable IP forwarding on the system, or that won't work. If you
have more than one Ethernet interface you should talk with your
networks staff before doing that.

