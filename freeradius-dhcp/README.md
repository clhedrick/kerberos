## DHCP

We put DHCP information in LDAP.

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

