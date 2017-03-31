#define PAM_SM_SESSION
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <keyutils.h>

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  const char *ccname = pam_getenv(pamh, "KRB5CCNAME");
  key_serial_t serial;
  int i;

  if (!ccname) 
    return PAM_SUCCESS;  // nothing to do

  // if user asked us to use collection, and KRB5CCNAME is set to a
  // specific cc, fix it to use the collection
  for (i = 0; i < argc; i++) {
    if (strcmp(argv[i], "usecollection") == 0 &&
	strncmp(ccname, "KEYRING:", 8) == 0) {
      // count colons in ccname
      int numcolon = 0; 
      int count = 0;
      const char *cp;
      for (cp = ccname; *cp; cp++) {
	if (*cp == ':')
	  numcolon++;
	if (numcolon == 3)
	  break;
      }
      // look for something like KEYRING:persistent:%{uid}:%{uid}      
      if (numcolon == 3) {
	int cclen = (cp - ccname);
	char *prop = NULL;
	if (asprintf(&prop, "%s=%.*s", "KRB5CCNAME", cclen, ccname) > 0)
	  pam_putenv(pamh, prop);
	if (prop)
	  free(prop);
      }
    }
    break;
  }

  serial = add_key("user", "krbrenewd:ccname", ccname, strlen(ccname) + 1, KEY_SPEC_SESSION_KEYRING);
  if (serial == -1)
    printf("Problem registering your Kerberos credentials. They may expire during your session. %m\n");
  // we are presumably root at this point, but have to change permission to allow
  // it to be read by a different root session
  
  if (keyctl_setperm(serial, 0x3f3f0000))
    printf("Problem setting permissiosn for your Kerberos credentials. They may expire during your session. %m\n");

  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
} 

