#include <ldap.h>

void mylog (int level, const char *format, ...)  __attribute__ ((format (printf, 2, 3)));
LDAP *krb_ldap_open(krb5_context context, char *service, char *hostname, char *realm);
int getLdapData(krb5_context context, LDAP *ld, char* realm,  char *user, struct berval ***rules, struct berval***keytab, char **dn);
void freeLdapData(struct berval **rules, struct berval **keytab, char *dn);
int addRule(LDAP *ld, char *dn, char *rule);
int deleteRule(LDAP *ld, char *dn, char *rule);
int replaceKeytab(LDAP *ld, char *dn, struct berval *newkeytab);
int base64encode(const void* data_buf, size_t dataLength, char* result, size_t resultSize);
int base64decode (char *in, size_t inLen, unsigned char *out, size_t *outLen);

