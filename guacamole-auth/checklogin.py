#!/usr/bin/python3
import ldap
import sys

try:
  connection = ldap.initialize('ldaps://krb2.cs.rutgers.edu ldaps://krb1.cs.rutgers.edu ldaps://krb4.cs.rutgers.edu')
  binddn = 'uid=ldap.admin,cn=users,cn=accounts,dc=cs,dc=rutgers,dc=edu'
  bindpw = 'abcde12345!'
  basedn = 'cn=accounts,dc=cs,dc=rutgers,dc=edu'

  connection.protocol_version = ldap.VERSION3
  connection.simple_bind_s(binddn, bindpw) 
  resultid = connection.search_s(basedn, ldap.SCOPE_SUBTREE, f'(&(uid={sys.argv[1]})(memberof=cn=login-ilab,cn=groups,cn=accounts,dc=cs,dc=rutgers,dc=edu))', ['dn',])

except:
    sys.exit(1)

if len(resultid) == 1:
    sys.exit(0)
else:
    sys.exit(1)
    



