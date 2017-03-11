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

  if (!ccname) 
    return PAM_SUCCESS;  // nothing to do

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

