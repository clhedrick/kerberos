#define PAM_SM_SESSION
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <keyutils.h>
#include <syslog.h>
#include "krb5.h"
#include "com_err.h"
#include <pwd.h>

/*

Post process credential cache

We know of three cases:

sshd: uses the primary, even if it's wrong principal
  sets KRB5CCMAME to cache
sssd: uses a cache with matching principal, doesn't change primary
  set KRB5CCNAME to collection
cache in /tmp: sets KRB5CCNAME to the file

So code here:

if KRB5CCNAME is cache, it's primary {
  record it for renewal
  set KRB5CCNAME to collection
} else {
  find cache that matches prinicpal
  set it primary
  record it for renewal
  set KRB5CCNAME to collection
}
for /tmp, just register the name}

*/

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  const char *ccname = pam_getenv(pamh, "KRB5CCNAME");
  key_serial_t serial;
  int i;
  const char *username;
  char *fullname = NULL;
  char *cccopy = NULL;
  int ret;
  krb5_context context = NULL;
  int usecollection = 0;

  pam_syslog(pamh, LOG_ERR, "ccname %s", ccname);

  if (!ccname) 
    return PAM_SUCCESS;  // nothing to do

  for (i = 0; i < argc; i++) {
    if (strcmp(argv[i], "usecollection") == 0)
      usecollection = 1;
  }

  if (strncmp(ccname, "KEYRING:", 8) == 0) {
    int numcolon = 0; 
    int count = 0;
    const char *cp;

    // all the funny business happens for keyring

    // get some basic Kerberos stuff

    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) 
      return PAM_AUTHINFO_UNAVAIL;

    // do we have collection? Count colons

    for (cp = ccname; *cp; cp++) {
      if (*cp == ':')
	numcolon++;
      if (numcolon == 3)
	break;
    }

    if (numcolon == 2) {
      // have collection
      krb5_ccache ccache = NULL;
      krb5_principal userprinc = NULL;
      char *default_realm = NULL;
      struct passwd * pwd = NULL;
      uid_t olduid;
      gid_t oldgid;

      olduid = getuid();
      oldgid = getgid();

      // switch uid and gid to get access to credentials
      pwd = getpwnam(username);
      if (!pwd) goto err;

      setresgid(pwd->pw_gid, pwd->pw_gid, -1);
      setresuid(pwd->pw_uid, pwd->pw_uid, -1);

      // basic kerberos setup
      ret = krb5_init_context(&context);
      if (ret) goto err;

      ret = krb5_get_default_realm(context, &default_realm);
      if (ret) goto err;
    
      ret = krb5_build_principal(context, &userprinc, strlen(default_realm), default_realm, username, NULL);
      if (ret) goto err;
      
      // find cache that matches principal
      ret = krb5_cc_cache_match(context, userprinc, &ccache);
      if (ret) goto err;      

      ret = krb5_cc_get_full_name(context, ccache, &fullname);
      if (ret) goto err;      
      
      // make it primary
      ret = krb5_cc_switch(context, ccache); 
      if (ret) goto err;

    err:
      if (ret)
	pam_syslog(pamh, LOG_ERR, "%s", error_message(ret));

      if (ccache)
	krb5_cc_close(context, ccache);
      if (userprinc)
	krb5_free_principal(context, userprinc);
      if (default_realm)
	krb5_free_default_realm(context, default_realm);

      setresuid(olduid, olduid, -1);
      setresgid(oldgid, oldgid, -1);

      // end of collection
    } else if (usecollection) {
      // have specific cache
      char *prop = NULL;

      // reset environment to collection
      if (asprintf(&prop, "%s=%.*s", "KRB5CCNAME", cp-ccname, ccname) > 0) {
	// ccname will no longer be valid after the putenv
	cccopy = malloc(strlen(ccname) + 1);
	strcpy(cccopy, ccname);

	pam_putenv(pamh, prop);
	if (prop)
	  free(prop);
      }

    }

  }

  // note: ccname doesn't have to be freed; fullname does
  if (fullname) {
    ccname = fullname;
  } else if (cccopy) {
    ccname = cccopy;
  }

  serial = add_key("user", "krbrenewd:ccname", ccname, strlen(ccname), KEY_SPEC_SESSION_KEYRING);
  if (serial == -1)
    printf("Problem registering your Kerberos credentials 1 %s. They may expire during your session. %m\n", ccname);
  // we are presumably root at this point, but have to change permission to allow
  // it to be read by a different root session
  
  if (keyctl_setperm(serial, 0x3f3f0000))
    printf("Problem setting permissiosn for your Kerberos credentials 2. They may expire during your session. %m\n");

  if (cccopy)
    free(cccopy);
  if (fullname)
    krb5_free_string(context, fullname);
  if (context)
    krb5_free_context(context);

  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
} 

