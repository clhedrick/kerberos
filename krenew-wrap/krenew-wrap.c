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

/* Function pointers to hold the value of the glibc functions */
static krb5_error_code (*real_krb5_init_context)(krb5_context *context) = NULL;

// static int (*real_puts)(const char* str) = NULL;

static krb5_wrap_done = 0;

/* wrapping write function call */
krb5_error_code krb5_init_context(krb5_context *context)
{
  krb5_error_code retval;
  krb5_error_code code = 0;
  krb5_context ctx;
  krb5_principal user = NULL;
  krb5_creds creds;
  int creds_valid = 0;
  const char *cctype = NULL;
  krb5_ccache ccache = NULL;
  krb5_ccache newcache = NULL;

  real_krb5_init_context = dlsym(RTLD_NEXT, "krb5_init_context");
  retval = real_krb5_init_context(context);
  // only need to do this once, as it changes the default
  if (krb5_wrap_done || retval) {
    code = retval;
    goto done;
  }

  krb5_wrap_done = 1;

  ctx = *context;

  memset(&creds, 0, sizeof(creds));

  code = krb5_cc_default(ctx, &ccache);  if (code) goto done;

  cctype = krb5_cc_get_type(ctx, ccache);
  code = krb5_cc_get_principal(ctx, ccache, &user);   if (code) goto done;
  code = krb5_get_renewed_creds(ctx, &creds, user, ccache, NULL); if (code) goto done;
  creds_valid = 1;  
  code = krb5_cc_resolve(ctx, "MEMORY:renewtmp", &newcache); if (code) goto done;
  code = krb5_cc_initialize(ctx, newcache, user); if (code) goto done;
  code = krb5_cc_store_cred(ctx, newcache, &creds); if (code) goto done;

  putenv("KRB5CCNAME=MEMORY:renewtmp");
  code = krb5_cc_set_default_name(ctx, "MEMORY:renewtmp");

 done:
  if (code)
    printf("failed %s\n", error_message(code));
  if (ccache)
    krb5_cc_close(ctx, ccache);
  if (newcache)
    krb5_cc_close(ctx, newcache);
  if (user != NULL)
    krb5_free_principal(ctx, user);
  if (creds_valid)
    krb5_free_cred_contents(ctx, &creds);

  return retval;
}
