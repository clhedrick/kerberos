/*
 * Store errors in the Kerberos context.
 *
 * Provides helper functions for the rest of the plugin code to store an error
 * message in the Kerberos context.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2016 Russ Allbery <eagle@eyrie.org>
 * Copyright 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/kadmin.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <errno.h>

#include <plugin/internal.h>


/*
 * Internal helper function to set the Kerberos error message given a format,
 * an error code, and a variable argument structure.
 */
static void __attribute__((__format__(printf, 3, 0)))
set_error(krb5_context ctx, krb5_error_code code, const char *format,
          va_list args)
{
    char *message;

    if (vasprintf(&message, format, args) < 0) {
        strength_error_system(ctx, "cannot allocate memory");
        return;
    }
    krb5_set_error_message(ctx, code, "%s", message);
    free(message);
}


/*
 * The following functions handle various common error codes for failed
 * password quality checks.  They allow the code to be simpler and not embed
 * lots of long Kerberos error code defines.
 *
 * Each function has the same basic form: take a Kerberos context, a format,
 * and variable arguments and set the Kerberos error code and message,
 * returning the appropriate code.
 */
#define ERROR_FUNC(name, code)                                          \
    krb5_error_code                                                     \
    strength_error_ ## name(krb5_context ctx, const char *format, ...)  \
    {                                                                   \
        va_list args;                                                   \
        va_start(args, format);                                         \
        set_error(ctx, code, format, args);                             \
        va_end(args);                                                   \
        return code;                                                    \
    }
ERROR_FUNC(class,    KADM5_PASS_Q_CLASS)
ERROR_FUNC(config,   KADM5_MISSING_KRB5_CONF_PARAMS)
ERROR_FUNC(dict,     KADM5_PASS_Q_DICT)
ERROR_FUNC(generic,  KADM5_PASS_Q_GENERIC)
ERROR_FUNC(tooshort, KADM5_PASS_Q_TOOSHORT)


/*
 * Set the Kerberos error code to the current errno and the message to the
 * format and arguments passed to this function.
 */
krb5_error_code
strength_error_system(krb5_context ctx, const char *format, ...)
{
    va_list args;
    char *message;
    bool okay = true;
    int oerrno = errno;

    va_start(args, format);
    if (vasprintf(&message, format, args) < 0) {
        oerrno = errno;
        krb5_set_error_message(ctx, errno, "cannot allocate memory: %s",
                               strerror(errno));
        okay = false;
    }
    va_end(args);
    if (!okay)
        return oerrno;
    krb5_set_error_message(ctx, oerrno, "%s: %s", message, strerror(oerrno));
    free(message);
    return oerrno;
}
