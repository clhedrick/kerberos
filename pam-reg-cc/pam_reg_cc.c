#define PAM_SM_SESSION
#define PAM_SM_AUTH
#define _GNU_SOURCE 

#include <sys/types.h>
#include <sys/errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include "krb5.h"
#include "com_err.h"
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include "../common/ccacheutil.h"

/*
 * Copyright 2017 by Rutgers, the State University of New Jersey
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of Rutgers not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original Rutgers software.
 * Rutgers makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */


/*

Post process credential cache

We know of three cases:

sshd: uses the primary, even if it's wrong principal
  sets KRB5CCMAME to cache
Ubuntu sshd: always uses /tmp/...
  copy to KEYRING if that's the default, and change KRB5CCNAME
sssd: uses a cache with matching principal, doesn't change primary
  set KRB5CCNAME to collection
cache in /tmp: sets KRB5CCNAME to the file if not cron

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

#define RENEWDCCS "/run/renewdccs/"

void register_for_delete(pam_handle_t *pamh, const char *cache, uid_t uid) {
  char *newname;
  const char *cp;
  char *cp2;
  int fd;

  newname = malloc(strlen(cache) + strlen(RENEWDCCS) + 1);

  strcpy(newname, RENEWDCCS);
  cp2 = newname + strlen(RENEWDCCS);

  // none of our cache names use \, so map / to \

  cp = cache;

  while (*cp) {
    char ch = *cp;
    if (ch == '/')
      *cp2 = '\\';
    else
      *cp2 = ch;
    cp++;
    cp2++;
  }
  *cp2 = '\0';
  fd = open(newname, O_CREAT|O_WRONLY, 0600);
  if (fd < 0 && errno == ENOENT) {
    fd = mkdir(RENEWDCCS, 0700);
    if (fd < 0) {
      pam_syslog(pamh, LOG_ERR, "unable to create %s", RENEWDCCS);
      free(newname);
      return;
    }
    fd = open(newname, O_CREAT|O_WRONLY, 0600);
  }
  if (fd < 0) {
    pam_syslog(pamh, LOG_ERR, "unable to create %s", newname);
    free(newname);
    return;
  }
  dprintf(fd, "%lu\n", (unsigned long)uid);
  free(newname);
  close(fd);
}

// for names like /run/user/%U/krbcc_%U 
// make need to create directory, but only if it's user-specific

void
assure_dir(char *template, char *filename, struct passwd *pwd) {
  char *cp;
  char *lastslash = NULL;
  char *nexttolastslash = NULL;
  int ok = 0;
  int err;

  // first, see if there's a % in the last directory compontent
  // if so, that's a user-specific directory, and we're willing to
  // create it. Otherwise, nothing we can do.

  for (cp = template; *cp; cp++) {
    if (*cp == '/') {
      nexttolastslash = lastslash;
      lastslash = cp;
    }
  }
  // is there a % between next to last and last?
  if (lastslash && nexttolastslash) {
    cp = strchr(nexttolastslash, '%');
    if (cp < lastslash)
      ok = 1;
  }
  
  // if not, nothing to do
  if (!ok)
    return;

  // there is. need to check the directory
  
  // get directory, by cutting off at least /
  cp = strrchr(filename, '/');
  *cp = '\0';
  if (mkdir(filename, 0700)) {
    // nothing to do
    *cp = '/';
    return;
  }
  // created it, set owner
  chown(filename, pwd->pw_uid, pwd->pw_gid);
  *cp = '/';

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
  int i;
  const char *username;
  char *fullname = NULL;
  char *cccopy = NULL;
  int ret;
  krb5_context context = NULL;
  int usecollection = 0;
  int fakename = 0;
  char *default_realm = NULL;
  const char *default_name = NULL;
  krb5_data realm_data;
  char *finalcred = NULL;
  char *tempcred = NULL;
  krb5_ccache cachecopy = NULL;
  krb5_ccache firstcache = NULL;
  krb5_cc_cursor cur = NULL;
  krb5_creds creds;
  struct passwd * pwd = NULL;
  struct passwd pwd_struct;
  char pwd_buf[2048];
  krb5_principal userprinc = NULL;
  int found_current_tgt = FALSE;
  time_t now;
  krb5_deltat minlife;
  char *minlife_st;
  const void *getcred;
  int iscron = 0;
  char *key;
  uid_t olduid;
  gid_t oldgid;
  const char *servicename;

  pam_syslog(pamh, LOG_INFO, "registering ccname %s", ccname);

  for (i = 0; i < argc; i++) {
    if (strcmp(argv[i], "usecollection") == 0)
      usecollection = 1;
    if (strcmp(argv[i], "usedefaultname") == 0)
      fakename = 1;
  }

  if (!fakename && !ccname) 
    // KRB5CCNAME not specified and we haven't been asked to fake it
    return PAM_SUCCESS;  // nothing to do

  // generally credentials will be set up by sssd, pam_krb5, or sshd
  // in all of those cases we want the usual code. However pam_kgetcred
  // will put credentials in /tmp, and we want them to stay there even
  // if the default is keyring. So iscron really means is_kgetcred
  if (pam_get_data(pamh, "kgetcred_test", &getcred) == PAM_SUCCESS)
    iscron = 1;

  // get basic user and kerberos info

  ret = krb5_init_context(&context);
  if (ret) goto err1;

  if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) 
    return PAM_AUTHINFO_UNAVAIL;

  getpwnam_r(username, &pwd_struct, pwd_buf, sizeof(pwd_buf), &pwd);
  if (!pwd) goto err;

  olduid = getuid();
  oldgid = getgid();

  //
  // 1. If for some reason KRB5CCNAME isn't set, and config asks for it,
  // set KRB5CCNAME to the default ccache name. Renewd works better if
  // KRB5CCNAME is always set.
  //

  if (fakename && !ccname) {
    // KRB5CCNAME not specified. 
    // Find the default cache and get its name. Verify that there's a 
    // a principal for it, to avoid getting a handle with no actual cache
    // Need to change to the user, since the Kerberos libraries get %{uid}
    // from the current uid.

    char *prop = NULL;

    setresgid(pwd->pw_gid, pwd->pw_gid, -1);
    setresuid(pwd->pw_uid, pwd->pw_uid, -1);

    // since no KRB5, it means our default ccache
    ret = krb5_cc_default(context, &firstcache);
    if (ret == 0) 
      ret = krb5_cc_get_principal(context, firstcache, &userprinc);
    if (ret == 0)
      // we have an actual cache
      ret = krb5_cc_get_full_name(context, firstcache, &fullname);
    if (ret == 0)
      ccname = fullname;

    if (firstcache) {
      krb5_cc_close(context, firstcache);
      firstcache = NULL;
    }
    if (userprinc) {
      krb5_free_principal(context, userprinc);
      userprinc = NULL;
    }
    // fullname will be freed at the end

    // now put back our real uid
    setresuid(olduid, olduid, -1);
    setresgid(oldgid, oldgid, -1);

    if (!ccname) {
      // no name, nothing to do
      // this is considered normal. it's for root cron jobs, etc.
      krb5_free_context(context);
      pam_syslog(pamh, LOG_INFO, "no KRB5CCNAME nor default cache for uid %lud", olduid);
      return PAM_SUCCESS;  // nothing to do      
    }

    // have to put it in KRB5CCNAME
    if (asprintf(&prop, "%s=%s", "KRB5CCNAME", ccname) > 0) {
      pam_putenv(pamh, prop);
      if (prop)
	free(prop);
    }

    pam_syslog(pamh, LOG_INFO, "registering default ccname for this user %s", ccname);    

  }

  //
  // 2. If ccache is /tmp and default is KEYRING, move the cache into the KEYRING.
  // sshd in some versions ignores krb5.conf and puts the cache into /tmp. First, we
  // want a consistent user experience. Second, gssd seems to work better with the
  // keyring. ccache names for keyring always have to start KEYRING, so we don't need
  // fancy normalization code for the check.
  //

  setresgid(pwd->pw_gid, pwd->pw_gid, -1);
  setresuid(pwd->pw_uid, pwd->pw_uid, -1);
  default_name =  krb5_cc_default_name(context);  

  setresuid(olduid, olduid, -1);
  setresgid(oldgid, oldgid, -1);

  ret = krb5_get_default_realm(context, &default_realm);
  if (ret) goto err;
  ret = krb5_build_principal(context, &userprinc, strlen(default_realm), default_realm, username, NULL);
  if (ret) goto err1;

  // For NFS to work, rpc.gssd has to be able to find the credentials. It looks at /tmp and
  // the default in krb5.conf. We've got two issues: (1) sshd likes to put things in /tmp
  // (2) Ubuntu sssd likes to put things in keyring, even if that's not right. If krb5.conf
  // points to KCM and the actual ticket is in KEYRING, gssd will fail and the user won't be
  // able to get files. So if the default is not /tmp, and login put the credential somewhere
  // other than the default, move it.
  
  if (!iscron && default_name &&
      is_collection_type(default_name) &&
      strcmp(get_cc_type(ccname), get_cc_type(default_name)) != 0) {
    const char *cp;
    int numcolon = 0; 
    char *prop = NULL;


    setresgid(pwd->pw_gid, pwd->pw_gid, -1);
    setresuid(pwd->pw_uid, pwd->pw_uid, -1);

    ret = krb5_cc_resolve(context, ccname, &firstcache);
    if (ret) goto err2;

    // If possible we reuse an existing cache, if one has the right principal.
    // There is no API call that lets us look only for caches of a specific type. The best we
    // can do is this. We then have to verify that it's the right type. If it's not
    // we ignore it. That means in some cases we can create a new cache every time
    // we login. That's not so terrible. sshd and sssd already do that.
    ret = krb5_cc_cache_match(context, userprinc, &cachecopy);
    if (ret == 0 && strcmp(krb5_cc_get_type(context, cachecopy), get_cc_type(default_name)) != 0)
      ret = 1;

    // if none, create one
    if (ret) {
      char * newtype = get_cc_type(default_name);

      ret = krb5_cc_new_unique(context, newtype, NULL, &cachecopy);
      if (ret)   pam_syslog(pamh, LOG_INFO, "new_uniq failed %s\n", newtype);


      // it's not clear whether this is a good idea, but it's probably more
      //   likely to be right than wrong. If there is an existing cache and
      //   it's not primary, we leave things to avoid conflicting with something
      //   the user has done explicitly. But if there isn't one and we have to
      //   create it, it's probably best to make it primary
      // make it primary. ignore failure
      if (!ret)
	krb5_cc_switch(context, cachecopy); 

    }

    if (ret) goto err2;
    ret = krb5_cc_initialize(context, cachecopy, userprinc);
    if (ret) goto err2;
    ret = krb5_cc_copy_creds(context, firstcache, cachecopy);
    if (ret) goto err2;

    ret = krb5_cc_get_full_name(context, cachecopy, &tempcred);
    if (ret) goto err2;

    ccname = tempcred;  // tempcred will be freed at exit

    krb5_cc_close(context, cachecopy);
    cachecopy = NULL;
    krb5_cc_destroy(context, firstcache);
    firstcache = NULL;

    // now put back our real uid
    setresuid(olduid, olduid, -1);
    setresgid(oldgid, oldgid, -1);

    // reset environment to collection
    if (asprintf(&prop, "%s=%s", "KRB5CCNAME", ccname) > 0) {
	pam_putenv(pamh, prop);
	if (prop)
	  free(prop);
    }

    pam_syslog(pamh, LOG_INFO, "moving to %s", tempcred);

  }    

  //
  // 3. Normalize cache name. For /tmp, there's no issue as there are no
  // collections. For KEYRING, we do two things (1) if KRB5CCNAME was set
  // to the collection, find the actual ccache and put it in ccname. Leave
  // KRB5CCNAME to the collection, but we need the actual ccache for some
  // later codr. (2) if KRB5CCNAME is set to an actual ccache, reset it
  // to the collection. We want users to get a consistent experience, and to
  // be able to use kswitch.
  //


  // for sss, we need to find the cache for the current principal. it's not necesarily the primary
  //   if another process did kswitch
  // for ssh, change KRB5CCNAME to the collection, or kinit with another principal will clobber this one

  if (is_collection(ccname)) {
      krb5_ccache ccache = NULL;

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
  } else if (is_collection_type(ccname) && usecollection) {
      // have specific cache
      char *prop = NULL;
      char *collection = convert_to_collection(ccname, (uid_t)-1);

      // reset environment to collection
      if (asprintf(&prop, "KRB5CCNAME=%s", collection) > 0) {
	// ccname will no longer be valid after the putenv
	cccopy = malloc(strlen(ccname) + 1);
	strcpy(cccopy, ccname);

	pam_putenv(pamh, prop);
      }
      if (prop)
	free(prop);
      free(collection);
  }

  // note: ccname doesn't have to be freed; fullname does
  if (fullname) {
    ccname = fullname;
  } else if (cccopy) {
    ccname = cccopy;
  }

  //
  // 4. register the cache for renewal
  //

  register_for_delete(pamh, ccname, pwd->pw_uid);

  //
  // 5. except for cron, see if the ticket lifetime is too small, and warn user.
  // Doesn't make sense for cron because there's no user terminal for warning.
  // cron sets PAM_SILENT, which seems like the best test to use
  //

  if (!(flags & PAM_SILENT)) {

  realm_data.data = default_realm;
  realm_data.length = strlen(default_realm);
  
  // see if it's got enough time left
  krb5_appdefault_string(context, "register-cc", &realm_data, "ticket_minlife", "0m", &minlife_st);
  ret = krb5_string_to_deltat(minlife_st, &minlife);
  if (ret)
    goto err;

  if (minlife) {

    // KCM requires cc_resolve to be done as user
    setresgid(pwd->pw_gid, pwd->pw_gid, -1);
    setresuid(pwd->pw_uid, pwd->pw_uid, -1);
    ret = krb5_cc_resolve(context, ccname, &firstcache);
    setresuid(olduid, olduid, -1);
    setresgid(oldgid, oldgid, -1);

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
	if (((time_t)(uint32_t)creds.times.endtime - now) > minlife) {
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

  } // end if iscron

 err:
  if (ret)
    pam_syslog(pamh, LOG_ERR, "%s", error_message(ret));
  if (ret)
    printf("%s\n", error_message(ret));
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

 err2:
  setresuid(olduid, olduid, -1);
  setresgid(oldgid, oldgid, -1);
  goto err;

}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
} 

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  pam_sm_open_session(pamh, flags, argc, argv);
  return PAM_SUCCESS; // optional so always ok
}

