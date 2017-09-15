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

#define OTPPROMPT  "Enter OTP Token Value"

radwrapprompt (krb5_context context, void *data, const char *name,
	       const char *banner, int num_prompts, krb5_prompt *prompts) {

  char *pass = (char *)data;
  if (pass && num_prompts == 1 && strncmp(prompts[0].prompt, OTPPROMPT, strlen(OTPPROMPT)) == 0 & strlen(pass) < prompts[0].reply->length) {
    strcpy(prompts[0].reply->data, pass);
    prompts[0].reply->length = strlen(pass);
    printf("return prompt\n");
    return 0;
  }
  printf("prompt we can't handle\n");
  return -1;
}

/* Function pointers to hold the value of the glibc functions */
static krb5_error_code (*real_krb5_get_init_creds_password)(krb5_context context, krb5_creds * creds, krb5_principal client, const char * password, krb5_prompter_fct prompter, void * data, krb5_deltat start_time, const char * in_tkt_service, krb5_get_init_creds_opt * opt) = NULL;

// static int (*real_puts)(const char* str) = NULL;

static krb5_wrap_done = 0;

/* wrapping write function call */
krb5_error_code krb5_get_init_creds_password(krb5_context context, krb5_creds * creds, krb5_principal client, const char * password, krb5_prompter_fct prompter, void * data, krb5_deltat start_time, const char * in_tkt_service, krb5_get_init_creds_opt * opt)
{
  krb5_error_code retval;

  printf("*********8 wrap called\n");

  retval = krb5_get_init_creds_opt_set_fast_ccache_name(context, opt, "/tmp/krb_cc_radius");

  if (retval)
    return retval;

  if (!real_krb5_get_init_creds_password)
    real_krb5_get_init_creds_password = dlsym(RTLD_NEXT, "krb5_get_init_creds_password");

  printf("prompter %x data %x\n", prompter, data);

  retval = real_krb5_get_init_creds_password(context, creds, client, password, radwrapprompt, (void *)password, start_time, in_tkt_service, opt);

  printf("kerb reeturn %d\n", retval);

  return retval;

}
