dsconf -D "cn=Directory Manager" ldap://krb1.cs.rutgers.edu backend index add --attr csRutgersEduDhcpIpNumber --index-type eq userRoot
dsconf -D "cn=Directory Manager" ldap://krb1.cs.rutgers.edu backend index add --attr csRutgersEduDhcpIpStart --index-type eq userROot
dsconf -D "cn=Directory Manager" ldap://krb1.cs.rutgers.edu backend index add --attr csRutgersEduDhcpIpEnd --index-type eq --reindex userRoot

