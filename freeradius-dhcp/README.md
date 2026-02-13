## DHCP

(Note that this is now in production at Rutgers. If anyone
is interested in the ansible role I can include it.)

We put DHCP information in LDAP. This repo has an
implementation for Freeradius 3. I'll add Freeradius 4
when it's released, though we use the Ubuntu package,
which likely won't move to version 4 for quite a while.

implementing this:
* Adding the DHCP schema to the LDAP servers
* Adding the Rutgers additions to the schema
* Add the dhcp module to IPA so that you can use the ipa command
* Configure the freeradius server to serve DHCP

The schema changes are in dhcp-ldap, which otherwise is out
of date as it supports the old ISC server. See the .ldif files
* dhcp.ldif - the standard dhcp scheme
* dhcpn.ldif and dhcp2n.ldif - Rutgers changes
* index.sh - indexes the new attributes

freeradius-ldap/dhcp.py is the IPA plugin. it goes in
/usr/lib/python3.9/site-packages/ipaserver/plugins/
You have to restart httpd after adding it.

the rest of freeradius-ldap are configuration files.
If this is all you use it for you'll want to remove
sites default and inner-tunnel and module eap.

Note that you'll have to fix the IP address for the
server, which is in several files. Look for 128.6.60.
(We use ansible, which automatically adds in the
right address.)

I only implement that options and statements that we
use. It's easy to add others.
 * Look in
  /usr/share/freeradius/dictionary.dhcp to find the
  variable name used within freeradius
 * modify policy.d/dhcp to map the LDAP version
   to the DHCP variable. We use the same option
   and statement names as in dhcpd.
 * modify the dhcp IPA plugin to add them to the
   syntax check. there's a table, so it's easy to add

WARNING: The encoding for the DNS search list is complex, and can't be
done in the freeradius config language. So I cheat. I check the first
item in the list, and then pick from 3 precoded options that cover all
of our systems. These are for Rutgers.

To do it for yours, use an online encoder such as
https://jjjordan.github.io/dhcp119/.  For that
one the Zyxel version is the best. Just take the
hex string and replace ours in policy.d/dhcp
