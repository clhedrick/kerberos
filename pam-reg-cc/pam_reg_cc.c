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
  record it for renewal
  KRB5CCNAME will alredy be collection
}
for /tmp, just register the name}

if requested put a copy of the cache into /var/lib//var/lib/gssproxy/clients/

*/

char *
build_cache_name(char *arg, uid_t uid, const char *username)
{
    char *cache_name = NULL;
    int retval;
    size_t len = 0, delta;
    char *p, *q;

    // compute length of final product
    for (p = arg; *p != '\0'; p++) {
      if (p[0] == '%' && p[1] == 'U') {
	len += snprintf(NULL, 0, "%ld", (long) uid);
	p++;
      } else if (p[0] == '%' && p[1] == 'u') {
	len += snprintf(NULL, 0, "%s", username);
	p++;
      } else {
	len++;
      }
    }
    len++;

    // now do it for real
    cache_name = malloc(len);
    if (cache_name == NULL) {
      return NULL;
    }
    for (p = arg, q = cache_name; *p != '\0'; p++) {
      if (p[0] == '%' && p[1] == 'U') {
	delta = snprintf(q, len, "%ld", (long) uid);
	q += delta;
	len -= delta;
	p++;
      } else if (p[0] == '%' && p[1] == 'u') {
	delta = snprintf(q, len, "%s", username);
	q += delta;
	len -= delta;
	p++;
      } else {
	*q = *p;
	q++;
	len--;
      }
    }
    *q = '\0';
    return cache_name;
}

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
  char *default_realm = NULL;
  krb5_data realm_data;
  char *credcopy = NULL;
  char *finalcred = NULL;
  char *tempcred = NULL;
  krb5_ccache cachecopy = NULL;
  krb5_ccache firstcache = NULL;
  struct passwd * pwd = NULL;
  krb5_principal userprinc = NULL;

  pam_syslog(pamh, LOG_ERR, "ccname %s", ccname);

  if (!ccname) 
    return PAM_SUCCESS;  // nothing to do

  for (i = 0; i < argc; i++) {
    if (strcmp(argv[i], "usecollection") == 0)
      usecollection = 1;
  }

  // get basic user and kerberos info

  ret = krb5_init_context(&context);
  if (ret) goto err1;

  ret = krb5_get_default_realm(context, &default_realm);
  if (ret) goto err;

  if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) 
    return PAM_AUTHINFO_UNAVAIL;
      // switch uid and gid to get access to credentials
  pwd = getpwnam(username);
  if (!pwd) goto err;

  ret = krb5_build_principal(context, &userprinc, strlen(default_realm), default_realm, username, NULL);
  if (ret) goto err1;

  // for sss, we need to find the cache for the current principal. it's not necesarily the primary
  //   if another process did kswitch
  // for ssh, change KRB5CCNAME to the collection, or kinit with another principal will clobber this one

  if (strncmp(ccname, "KEYRING:", 8) == 0) {
    int numcolon = 0; 
    int count = 0;
    const char *cp;

    // all the funny business happens for keyring

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
      uid_t olduid;
      gid_t oldgid;

      olduid = getuid();
      oldgid = getgid();

      setresgid(pwd->pw_gid, pwd->pw_gid, -1);
      setresuid(pwd->pw_uid, pwd->pw_uid, -1);

      // find cache that matches principal
      ret = krb5_cc_cache_match(context, userprinc, &ccache);
      if (ret) goto err1;      

      ret = krb5_cc_get_full_name(context, ccache, &fullname);
      if (ret) goto err1;      
      
      // make it primary
      // ret = krb5_cc_switch(context, ccache); 
      // if (ret) goto err1;

    err1:
      if (ret)
	pam_syslog(pamh, LOG_ERR, "%s", error_message(ret));

      if (ccache)
	krb5_cc_close(context, ccache);

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
  // now register the cache for renewd

  serial = add_key("user", "krbrenewd:ccname", ccname, strlen(ccname), KEY_SPEC_SESSION_KEYRING);
  if (serial == -1)
    pam_syslog(pamh, LOG_ERR, "Problem registering your Kerberos credentials 1 %s. They may expire during your session. %m\n", ccname);
  // we are presumably root at this point, but have to change permission to allow
  // it to be read by a different root session
  
  if (keyctl_setperm(serial, 0x3f3f0000))
    pam_syslog(pamh, LOG_ERR, "Problem registering your Kerberos credentials 2 %s. They may expire during your session. %m\n", ccname);

  // now make a copy in FILE:/var/lib/gssproxy/clients/krb5cc_%U if asked.
  // That makes sure it's always available for NFS even if the user changes the primary cache

  realm_data.data = default_realm;
  realm_data.length = strlen(default_realm);
  
  krb5_appdefault_string(context, "register-cc", &realm_data, "credcopy", "", &credcopy);

  if (strlen(credcopy) > 0) {
    ret = krb5_cc_resolve(context, ccname, &firstcache);
    if (ret) goto err;
    finalcred = build_cache_name(credcopy, pwd->pw_uid, username);

    if ((strncmp(finalcred, "FILE:", 5) == 0 ||
    	 strncmp(finalcred, "/", 1) == 0) &&
    	asprintf(&tempcred, "%s.%ul", finalcred, (long)getpid()) > 0) {
      char *tempname = tempcred;
      char *finalname = finalcred;
      if (strncmp(finalcred, "FILE:", 5) == 0) {
	tempname = tempname + 5;
	finalname = finalname + 5;
      }
      ret = krb5_cc_resolve(context, tempcred, &cachecopy);
      if (ret) goto err;
      ret = krb5_cc_initialize(context, cachecopy, userprinc);
      if (ret) goto err;
      ret = krb5_cc_copy_creds(context, firstcache, cachecopy);
      if (ret) goto err;
      krb5_cc_close(context, cachecopy);
      cachecopy = NULL;
      krb5_cc_close(context, firstcache);
      firstcache = NULL;
      rename(tempname, finalname);
    } else {
      // not in temp. have to put copy in final location
      ret = krb5_cc_resolve(context, finalcred, &cachecopy);
      if (ret) goto err;
      ret = krb5_cc_initialize(context, cachecopy, userprinc);
      if (ret) goto err;
      ret = krb5_cc_copy_creds(context, firstcache, cachecopy);
      if (ret) goto err;
    }      
    
    // have copy. register it
    serial = add_key("user", "krbrenewd:ccname:2", finalcred, strlen(finalcred), KEY_SPEC_SESSION_KEYRING);
    if (serial == -1)
      pam_syslog(pamh, LOG_ERR, "Problem registering copy of your Kerberos credentials 1 %s. They may expire during your session %m", finalcred);

    // we are presumably root at this point, but have to change permission to allow
    // it to be read by a different root session
    if (keyctl_setperm(serial, 0x3f3f0000))
      pam_syslog(pamh, LOG_ERR, "Problem registering copy of your Kerberos credentials 2 %s. They may expire during your session %m", finalcred);

  }  

 err:
  if (ret)
    pam_syslog(pamh, LOG_ERR, "%s", error_message(ret));
  if (ret)
    printf(error_message(ret));
  if (userprinc)
    krb5_free_principal(context, userprinc);
  if (cachecopy)
    krb5_cc_close(context, cachecopy);
  if (tempcred)
    free(tempcred);
  if (finalcred)
    free(finalcred);
  if (firstcache)
    krb5_cc_close(context,firstcache);
  if (default_realm)
    krb5_free_default_realm(context, default_realm);
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

