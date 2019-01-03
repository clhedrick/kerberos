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

This is designed for use with SSH.

We need ssh to get a ticket with the full hour lifetime. Otherwise the
other end could start out with a ticket with not enought lifetime to
survive until the next renew.

The only obvious way to do this is to renew the ticket. But renew has
possible race conditions. So the safest approach is not to touch the
current ticket, but put the renewed one someplace else and get ssh to
look there.

The cleanest solution is to put it in a memory cache. Initially I put
a script around ssh, and usrd krenew, but that leavrs lots of krenews
lying around, and also tickets in temp during the lifetime of the process.
This approach puts the tickets in memory, so we don't have that issue.

It interposes my own code around krb5_init_context. The magic is this line:

  real_krb5_init_context = dlsym(RTLD_NEXT, "krb5_init_context");

It finds the address of the original routine, so we can call it and then
do our own code.

The .so file built from this file is pointed to be LD_PRELOAD. that puts
it in front of the normal libraries.

*/


#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <krb5.h>
#include <com_err.h>
#include <stdlib.h>
#include <unistd.h>
#include <gssapi/gssapi.h>
#include <sys/types.h>
#include <pwd.h>
  
static OM_uint32 
(KRB5_CALLCONV *real_gss_acquire_cred)(
    OM_uint32 *,        /* minor_status */
    gss_name_t,         /* desired_name */
    OM_uint32,          /* time_req */
    gss_OID_set,        /* desired_mechs */
    gss_cred_usage_t,   /* cred_usage */
    gss_cred_id_t *,    /* output_cred_handle */
    gss_OID_set *,      /* actual_mechs */
    OM_uint32 *) = NULL;

/* wrapping function call */
OM_uint32 KRB5_CALLCONV
gss_acquire_cred(
    OM_uint32 *minor_status,        /* minor_status */
    gss_name_t desired_name,         /* desired_name */
    OM_uint32 time_req,          /* time_req */
    gss_OID_set desired_mech,        /* desired_mechs */
    gss_cred_usage_t cred_usage,   /* cred_usage */
    gss_cred_id_t *output_cred_handle,    /* output_cred_handle */
    gss_OID_set *actual_mechs,      /* actual_mechs */
    OM_uint32 *time_rec) {       /* time_rec */

  OM_uint32 retval;
  gss_name_t target_name = NULL;
  int target_alloc = 0;
  OM_uint32 minor, major;

  if (!real_gss_acquire_cred) 
    real_gss_acquire_cred = dlsym(RTLD_NEXT, "gss_acquire_cred");

  if (geteuid() != 0 && desired_name == GSS_C_NO_NAME) {
    gss_buffer_desc name;
    char pwbuf[1024]; // for strings in the pwd struct
    struct passwd passwd;  // for the pwd struct
    struct passwd *pwd;  // the actual return value, pointer to passwd or NULL

    // ignore return value, because checking pwd NULL will also work
    getpwuid_r(geteuid(), &passwd, pwbuf, sizeof(pwbuf), &pwd);

    if (pwd && pwd->pw_name) {
      name.value = (void *)pwd->pw_name;
      name.length = strlen(pwd->pw_name);
      major = gss_import_name(&minor, &name,
			       ((const gss_OID)GSS_C_NT_USER_NAME),
			       &target_name);
      if (major == GSS_S_COMPLETE && target_name) {
	desired_name = target_name;
	target_alloc = 1;
      } else {
#ifdef debug
	printf("import name failed\n");
#endif
      }
    }

  }

#ifdef debug
  printf("*********8 wrap called %x %d\n", desired_name, geteuid());
#endif

  retval = real_gss_acquire_cred(minor_status, desired_name, time_req, desired_mech, cred_usage, output_cred_handle, actual_mechs, time_rec);

#ifdef debug
  printf("gss_acquire_cred return %d\n", retval);
#endif

  if (target_alloc)
    major = gss_release_name(&minor, &target_name);

  return retval;

}
