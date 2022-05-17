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

/*
 * Copyright 2022 by Rutgers, the State University of New Jersey
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

For sshd. Copy credential cache from /tmp/krb5cc* into KEYRING

*/


PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  const char *ccname = pam_getenv(pamh, "KRB5CCNAME");
  const char *username;
  int ret;
  krb5_context context = NULL;
  char *default_realm = NULL;
  const char *default_name = NULL;
  const char *default_type = NULL;
  const char *this_type = NULL;
  krb5_ccache cachecopy = NULL;
  krb5_ccache firstcache = NULL;
  struct passwd * pwd = NULL;
  struct passwd pwd_struct;
  char pwd_buf[2048];
  krb5_principal userprinc = NULL;
  uid_t olduid;
  gid_t oldgid;
  char *prop = NULL;
  int isnew = 0;

  // get basic user and kerberos info
  ret = krb5_init_context(&context);
  if (ret) goto err;

  if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) 
    return PAM_AUTHINFO_UNAVAIL;

  getpwnam_r(username, &pwd_struct, pwd_buf, sizeof(pwd_buf), &pwd);
  if (!pwd) goto err;

  olduid = getuid();
  oldgid = getgid();


  //
  // Ccache is /tmp and default is KEYRING or KCM. Move the cache into the KEYRING.
  // We have to be the user in order to create a new cache with the right name
  // and ownership, particularly for KCM:
  //

  setresgid(pwd->pw_gid, pwd->pw_gid, -1);
  setresuid(pwd->pw_uid, pwd->pw_uid, -1);

  // name of default crednetial. This will based on what is in krb5.conf
  // e.g. KEYRING:persistent:1003, not KEYRING:persistent:1003:xxxyyyzzz
  // We need this so we can find out the default type. Probably KEYRING or KCM.
  // This will also be the name we use for KRB5CCNAME after copying
  default_name =  krb5_cc_default_name(context);  

  // Find the default cache type, e.g. KEYRING or KCM.
  // No obvious way to do this without actually creating a cache temporarily
  ret = krb5_cc_resolve(context, default_name, &firstcache);
  if (ret) goto err2;
  default_type = krb5_cc_get_type(context, firstcache);
  // no longer need it, so close it
  krb5_cc_close(context, firstcache);
  firstcache = NULL;

  // set firstcache to cache in /tmp
  ret = krb5_cc_resolve(context, ccname, &firstcache);
  if (ret) goto err2;

  // if we already have the right kind of cache, nothing to do
  this_type = krb5_cc_get_type(context, firstcache);
  if (strcmp(this_type, default_type) == 0) {
    // they're the same, exit (err2 actually returns success)
    goto err2;
  }

  // need a principal for the new cache
  ret = krb5_get_default_realm(context, &default_realm);
  if (ret) goto err2;
  ret = krb5_build_principal(context, &userprinc, strlen(default_realm), default_realm, username, NULL);
  if (ret) goto err2;

  // Search all cache collections for this user, looking for one with the specified principal
  // The principal is simply user@CS.RUTGERS.EDU. So we're really just looking for their
  // current cache collection. We'd rather update its expiration than create a new one
  ret = krb5_cc_cache_match(context, userprinc, &cachecopy);

  // In theory this could find a KEYRING cache when the current default is KCM.
  // It's really unlikely for this to happen. But if it does, ignore the cache.
  if (ret == 0 && strcmp(krb5_cc_get_type(context, cachecopy), default_type) != 0)
    ret = 1;

  // if none, create one
  if (ret) {
    // We're about to overwrite cachecopy, so free the contents first if there are any.
    // This is to prevent a memory leak.
    if (cachecopy) {
      krb5_cc_close(context, cachecopy);      
      cachecopy = NULL;
    }
    
    // create a new cache with a unique name
    ret = krb5_cc_new_unique(context, default_type, NULL, &cachecopy);
    if (ret) {
      pam_syslog(pamh, LOG_INFO, "new_uniq failed %s\n", default_type);
      goto err2;
    }

    isnew = 1;

  }
  
  // Have to initialize it before we can put credentials in it.
  // If we are reusing an existing ccache this will reinitialize it.
  // That's what kinit -R does. 

  // There is a possible race condition. If rpc.gssd has to
  // recreate the NFS credentials and this process happens to
  // be between the initialize and the krb5_cc_copy_creds, then
  // this ccache is empty. However the original one in /tmp is
  // still there, so rpc.gssd will use it. (renewd has a similar
  // race condition, with no good workaround.)

  ret = krb5_cc_initialize(context, cachecopy, userprinc);
  if (ret) goto err2;

  // Copy credentials from the one in /tmp into the new one.
  // The only thing there should be the tgt.

  ret = krb5_cc_copy_creds(context, firstcache, cachecopy);
  if (ret) goto err2;

  if (isnew) {
    // the primary designation doesn't go away until reset,
    // even if the cache it points to doesn't exist. If we
    // found an existing cache, leave things alone. If we didn't,
    // have to make the new one primary, or primary could be
    // a non-existent cache.
    krb5_cc_switch(context, cachecopy);
  }

  // finished with the new cache
  krb5_cc_close(context, cachecopy);
  cachecopy = NULL;

  // destroy the cache in /tmp
  krb5_cc_destroy(context, firstcache);
  firstcache = NULL;

  // now put back our real uid
  setresuid(olduid, olduid, -1);
  setresgid(oldgid, oldgid, -1);

  // reset KRB5CCNAME to the copy. We use default_name so we get
  // KEYRING:persistent:1003, not KEYRING:persistent:1003:xxxyyyzz
  if (asprintf(&prop, "%s=%s", "KRB5CCNAME", default_name) > 0)
    pam_putenv(pamh, prop);

  pam_syslog(pamh, LOG_INFO, "moving to %s", default_name);

 err:
  if (ret)
    pam_syslog(pamh, LOG_ERR, "%s", error_message(ret));
  if (ret)
    printf("%s\n", error_message(ret));
  if (prop)
    free(prop);
  if (userprinc)
    krb5_free_principal(context, userprinc);
  if (cachecopy)
    krb5_cc_close(context, cachecopy);
  if (firstcache)
    krb5_cc_close(context,firstcache);
  if (default_realm)
    krb5_free_default_realm(context, default_realm);
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

