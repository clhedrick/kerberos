/*
 * Heimdal shared module API.
 *
 * This is the glue required for a Heimdal password quality check via a
 * dynamically loaded module.  Heimdal's shared module API doesn't have
 * separate initialization and shutdown functions, so provide a self-contained
 * function that looks up the dictionary path from krb5.conf and does all the
 * work.  This means that it does memory allocations on every call, which
 * isn't ideal, but it's probably not that slow.
 *
 * Of course, the external Heimdal strength checking program can be used
 * instead.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2009, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <errno.h>
#ifdef HAVE_KADM5_KADM5_PWCHECK_H
# include <kadm5/kadm5-pwcheck.h>
#endif

#include <plugin/internal.h>
#include <util/macros.h>

/* Skip this entire file if not building with Heimdal. */
#ifdef HAVE_KRB5_REALM


/*
 * Write a Kerberos error string to a message buffer, with an optional
 * prefix.
 */
static void
convert_error(krb5_context ctx, krb5_error_code code, const char *prefix,
              char *message, size_t length)
{
    const char *error;

    error = krb5_get_error_message(ctx, code);
    if (prefix == NULL)
        snprintf(message, length, "%s", error);
    else
        snprintf(message, length, "%s: %s", prefix, error);
    krb5_free_error_message(ctx, error);
}


/*
 * This is the single check function that we provide.  It does the glue
 * required to initialize our checks, convert the Heimdal arguments to the
 * strings we expect, and return the result.
 */
static int
heimdal_pwcheck(krb5_context ctx, krb5_principal principal,
                krb5_data *password, const char *tuning UNUSED,
                char *message, size_t length)
{
    krb5_pwqual_moddata data = NULL;
    char *pastring = NULL;
    char *name = NULL;
    krb5_error_code code;

    /* Convert the password to a C string. */
    pastring = malloc(password->length + 1);
    if (pastring == NULL) {
        snprintf(message, length, "cannot allocate memory: %s",
                 strerror(errno));
        return 1;
    }
    memcpy(pastring, password->data, password->length);
    pastring[password->length] = '\0';

    /* Initialize strength checking. */
    code = strength_init(ctx, NULL, &data);
    if (code != 0) {
        convert_error(ctx, code, NULL, message, length);
        goto done;
    }

    /* Convert the principal to a string. */
    code = krb5_unparse_name(ctx, principal, &name);
    if (code != 0) {
        convert_error(ctx, code, "cannot unparse principal", message, length);
        goto done;
    }

    /* Do the password strength check. */
    code = strength_check(ctx, data, name, pastring);
    if (code != 0)
        convert_error(ctx, code, NULL, message, length);

done:
    free(pastring);
    if (name != NULL)
        krb5_free_unparsed_name(ctx, name);
    if (data != NULL)
        strength_close(ctx, data);
    return (code == 0) ? 0 : 1;
}

/* The public symbol that Heimdal looks for. */
static struct kadm5_pw_policy_check_func functions[] = {
    { "krb5-strength", heimdal_pwcheck },
    { NULL, NULL }
};
struct kadm5_pw_policy_verifier kadm5_password_verifier = {
    "krb5-strength",
    KADM5_PASSWD_VERSION_V1,
    "Russ Allbery",
    functions
};

#endif /* HAVE_KRB5_REALM */
