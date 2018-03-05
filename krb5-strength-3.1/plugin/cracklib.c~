/*
 * Test a password for weaknesses using CrackLib.
 *
 * Contained here is the interface from the krb5-strength plugin to the
 * CrackLib library, including initialization and checking of a password
 * against a CrackLib dictionary.
 *
 * Developed by Derrick Brashear and Ken Hornstein of Sine Nomine Associates,
 *     on behalf of Stanford University
 * Extensive modifications by Russ Allbery <eagle@eyrie.org>
 * Copyright 2006, 2007, 2009, 2012, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <plugin/internal.h>

/* When using the embedded CrackLib, we need to provide our own prototype. */
#ifdef HAVE_CRACK_H
# include <crack.h>
#else
extern const char *FascistCheck(const char *password, const char *dict);
#endif


/*
 * Initialize the CrackLib dictionary.  Ensure that the dictionary file exists
 * and is readable and store the path in the module context.  Returns 0 on
 * success, non-zero on failure.
 *
 * The dictionary file should not include the trailing .pwd extension.
 * Currently, we don't cope with a NULL dictionary path.
 */
krb5_error_code
strength_init_cracklib(krb5_context ctx, krb5_pwqual_moddata data,
                       const char *dictionary)
{
    char *file;
    krb5_error_code code;

    /*
     * Get the dictionary from krb5.conf, and only use the dictionary provided
     * if krb5.conf configuration is not present.  The dictionary passed to
     * the initialization function is normally set by dict_path in the MIT
     * Kerberos configuration, and this allows that setting to be used for
     * other password strength modules while using a different dictionary for
     * krb5-strength.
     */
    strength_config_string(ctx, "password_dictionary", &data->dictionary);
    if (data->dictionary == NULL && dictionary != NULL) {
        data->dictionary = strdup(dictionary);
        if (data->dictionary == NULL)
            return strength_error_system(ctx, "cannot allocate memory");
    }

    /* All done if we don't have a dictionary. */
    if (data->dictionary == NULL)
        return 0;

    /* Sanity-check the dictionary path. */
    if (asprintf(&file, "%s.pwd", data->dictionary) < 0)
        return strength_error_system(ctx, "cannot allocate memory");
    if (access(file, R_OK) != 0) {
        code = strength_error_system(ctx, "cannot read dictionary %s", file);
        free(file);
        return code;
    }
    free(file);
    return 0;
}


/*
 * Check a password against CrackLib.  Returns 0 on success, non-zero on
 * failure or if the password is rejected.
 */
krb5_error_code
strength_check_cracklib(krb5_context ctx, krb5_pwqual_moddata data,
                        const char *password)
{
    const char *result;

    /* Nothing to do if we don't have a dictionary. */
    if (data->dictionary == NULL)
        return 0;

    /* Nothing to do if the password is longer than the maximum length. */
    if (data->cracklib_maxlen > 0)
        if (strlen(password) > (size_t) data->cracklib_maxlen)
            return 0;

    /* Check the password against CrackLib and return the results. */
    result = FascistCheck(password, data->dictionary);
    if (result != NULL)
        return strength_error_generic(ctx, "%s", result);
    else
        return 0;
}
