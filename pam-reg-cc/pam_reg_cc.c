#define PAM_SM_SESSION
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
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

static inline int
data_eq(krb5_data d1, krb5_data d2)
{
  return (d1.length == d2.length && (d1.length == 0 ||
				     !memcmp(d1.data, d2.data, d1.length)));
}

static inline int
data_eq_string (krb5_data d, const char *s)
{
  return (d.length == strlen(s) && (d.length == 0 ||
				    !memcmp(d.data, s, d.length)));
}

krb5_boolean is_local_tgt (krb5_principal princ, krb5_data *realm);

/* Return true if princ is the local krbtgt principal for local_realm. */
krb5_boolean
is_local_tgt(krb5_principal princ, krb5_data *realm)
{
  return princ->length == 2 && data_eq(princ->realm, *realm) &&
    data_eq_string(princ->data[0], KRB5_TGS_NAME) &&
    data_eq(princ->data[1], *realm);
}

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
  krb5_cc_cursor cur = NULL;
  krb5_creds creds;
  struct passwd * pwd = NULL;
  krb5_principal userprinc = NULL;
  int found_current_tgt = FALSE;
  time_t now;
  krb5_deltat minlife;
  char *minlife_st;

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
  
  // see if it's got enough time left
  krb5_appdefault_string(context, "register-cc", &realm_data, "ticket_minlife", "0m", &minlife_st);
  ret = krb5_string_to_deltat(minlife_st, &minlife);
  if (ret)
    goto err;

  pam_syslog(pamh, LOG_ERR, "minlife %d", minlife);

  if (minlife) {

    ret = krb5_cc_resolve(context, ccname, &firstcache);
    if (ret) goto err;
    if ((ret = krb5_cc_start_seq_get(context, firstcache, &cur))) {
      goto err;
    }
    found_current_tgt = FALSE;   // found a TGT that is current
    
    now = time(0);
    
    while (!(ret = krb5_cc_next_cred(context, firstcache, &cur, &creds))) {
      // only renewable creds are worth looking at. and must be TGT
      if ((creds.ticket_flags & TKT_FLG_RENEWABLE) && is_local_tgt(creds.server, &userprinc->realm)) {
	// enough time left, it's current
	if ((creds.times.endtime - now) > minlife) {
	  found_current_tgt = TRUE;
	  krb5_free_cred_contents(context, &creds);
	  break;
	}
	krb5_free_cred_contents(context, &creds);
      }
    }
    krb5_cc_end_seq_get(context, firstcache, &cur);
    
    // if ticket isn't good enough issue warning.
    // most of the code is for reading warning from a file configured in krb5.conf
    // the text is probably a bit long to put in krb5.conf directly
    if (!found_current_tgt) {
      char *warnfilename = NULL;
      FILE *warnfile = NULL;
      char *warntext = NULL;
      long fsize;
      int warnfd;

      krb5_appdefault_string(context, "register-cc", &realm_data, "ticket_warn_file", "", &warnfilename);      
      // do we have a file with text? Otherwise there's a builtin default text
      if (warnfilename && strlen(warnfilename) > 0) {
	warnfile = fopen(warnfilename, "r");
	if (!warnfile)
	  goto texterr;
	// you'd expect to use fstat, but it's missing from libc somehow
	fseek(warnfile, 0, SEEK_END);
	fsize = ftell(warnfile);
	fseek(warnfile, 0, SEEK_SET);  //same as rewind(f);
	warntext = malloc(fsize + 1);
	if (!warntext)
	  goto texterr;
	if (fread(warntext, fsize, 1, warnfile) != 1)
	  goto texterr;
	warntext[fsize] = 0;
	goto textok;
	
      texterr:
	if (warntext) {
	  free(warntext);
	  warntext = NULL;
	}
      textok:
	if (warnfile) 
	  fclose(warnfile);
      }

      if (warntext) {
	pam_info(pamh, "%s", warntext);
	free(warntext);
      } else
	pam_info(pamh, "\n**********************************************************************\nYour Kerberos ticket doesn't have enough lifetime left. You may lose\naccess to your files during this session. We suggest using the\ncommand \"kinit\" to get a new ticket.\n**********************************************************************\n");
    }
  }

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

