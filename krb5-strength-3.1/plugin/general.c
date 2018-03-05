/*
 * The general entry points for password strength checking.
 *
 * Provides the strength_init, strength_check, and strength_close entry points
 * for doing password strength checking.  These are the only interfaces that
 * are called by the implementation-specific code, and all other checks are
 * wrapped up in those interfaces.
 *
 * Developed by Derrick Brashear and Ken Hornstein of Sine Nomine Associates,
 *     on behalf of Stanford University
 * Extensive modifications by Russ Allbery <eagle@eyrie.org>
 * Copyright 2006, 2007, 2009, 2012, 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <ctype.h>

#include <plugin/internal.h>
#include <util/macros.h>


/*
 * Initialize the module.  Ensure that the dictionary file exists and is
 * readable and store the path in the module context.  Returns 0 on success,
 * non-zero on failure.  This function returns failure only if it could not
 * allocate memory or internal Kerberos calls that shouldn't fail do.
 *
 * The dictionary file should not include the trailing .pwd extension.
 * Currently, we don't cope with a NULL dictionary path.
 */
krb5_error_code
strength_init(krb5_context ctx, const char *dictionary,
              krb5_pwqual_moddata *moddata)
{
    krb5_pwqual_moddata data = NULL;
    krb5_error_code code;

    /* Allocate our internal data. */
    data = calloc(1, sizeof(*data));
    if (data == NULL)
        return strength_error_system(ctx, "cannot allocate memory");
    data->cdb_fd = -1;

    /* Get minimum length and character information from krb5.conf. */
    strength_config_number(ctx, "minimum_different", &data->minimum_different);
    strength_config_number(ctx, "minimum_length", &data->minimum_length);

    /* Get simple character class restrictions from krb5.conf. */
    strength_config_boolean(ctx, "require_ascii_printable", &data->ascii);
    strength_config_boolean(ctx, "require_non_letter", &data->nonletter);

    /* Get complex character class restrictions from krb5.conf. */
    code = strength_config_classes(ctx, "require_classes", &data->rules);
    if (code != 0)
        goto fail;

    /* Get CrackLib maximum length from krb5.conf. */
    strength_config_number(ctx, "cracklib_maxlen", &data->cracklib_maxlen);

    /*
     * Try to initialize CDB, CrackLib, and SQLite dictionaries.  These
     * functions handle their own configuration parsing and will do nothing if
     * the corresponding dictionary is not configured.
     */
    code = strength_init_cracklib(ctx, data, dictionary);
    if (code != 0)
        goto fail;
    code = strength_init_cdb(ctx, data);
    if (code != 0)
        goto fail;
    code = strength_init_sqlite(ctx, data);
    if (code != 0)
        goto fail;

    /* Initialized.  Set moddata and return. */
    *moddata = data;
    return 0;

fail:
    if (data != NULL)
        strength_close(ctx, data);
    *moddata = NULL;
    return code;
}


/*
 * Check if a password contains only printable ASCII characters.
 */
static bool
only_printable_ascii(const char *password)
{
    const char *p;

    for (p = password; *p != '\0'; p++)
        if (!isascii((unsigned char) *p) || !isprint((unsigned char) *p))
            return false;
    return true;
}


/*
 * Check if a password contains only letters and spaces.
 */
static bool
only_alpha_space(const char *password)
{
    const char *p;

    for (p = password; *p != '\0'; p++)
        if (!isalpha((unsigned char) *p) && *p != ' ')
            return false;
    return true;
}


/*
 * Check if a password has a sufficient number of unique characters.  Takes
 * the password and the required number of characters.
 */
static bool
has_minimum_different(const char *password, long minimum)
{
    size_t unique;
    const char *p;

    /* Special cases for passwords of length 0 and a minimum <= 1. */
    if (password == NULL || password[0] == '\0')
        return minimum <= 0;
    if (minimum <= 1)
        return true;

    /*
     * Count the number of unique characters by incrementing the count if each
     * subsequent character is not found in the previous password characters.
     * This algorithm is O(n^2), but passwords are short enough it shouldn't
     * matter.
     */
    unique = 1;
    for (p = password + 1; *p != '\0'; p++)
        if (memchr(password, *p, p - password) == NULL) {
            unique++;
            if (unique >= (size_t) minimum)
                return true;
        }
    return false;
}


/*
 * Check a given password.  Takes a Kerberos context, our module data, the
 * password, the principal the password is for, and a buffer and buffer length
 * into which to put any failure message.
 */
krb5_error_code
strength_check(krb5_context ctx UNUSED, krb5_pwqual_moddata data,
               const char *principal, const char *password)
{
    krb5_error_code code;

    /* Check minimum length first, since that's easy. */
    if ((long) strlen(password) < data->minimum_length)
        return strength_error_tooshort(ctx, ERROR_SHORT);

    // NIST recommendations. just length and database
    if (0) {

    /*
     * If desired, check whether the password contains non-ASCII or
     * non-printable ASCII characters.
     */
    if (data->ascii && !only_printable_ascii(password))
        return strength_error_generic(ctx, ERROR_ASCII);

    /*
     * If desired, ensure the password has a non-letter (and non-space)
     * character.  This requires that people using phrases at least include a
     * digit or punctuation to make phrase dictionary attacks or dictionary
     * attacks via combinations of words harder.
     */
    if (data->nonletter && only_alpha_space(password))
        return strength_error_class(ctx, ERROR_LETTER);

    /* If desired, check for enough unique characters. */
    if (data->minimum_different > 0)
        if (!has_minimum_different(password, data->minimum_different))
            return strength_error_class(ctx, ERROR_MINDIFF);

    /*
     * If desired, check that the password satisfies character class
     * restrictions.
     */
    code = strength_check_classes(ctx, data, password);
    if (code != 0)
        return code;

    /* Check if the password is based on the principal in some way. */
    code = strength_check_principal(ctx, data, principal, password);
    if (code != 0)
        return code;

    /* Check the password against CDB, CrackLib, and SQLite if configured. */
    code = strength_check_cracklib(ctx, data, password);
    if (code != 0)
        return code;
    code = strength_check_cdb(ctx, data, password);
    if (code != 0)
        return code;
    
    } // end of if (0)

    code = strength_check_sqlite(ctx, data, password);
    if (code != 0)
        return code;

    /* Success.  Password accepted. */
    return 0;
}


/*
 * Cleanly shut down the password strength plugin.  The only thing we have to
 * do is free the memory allocated for our internal data.
 */
void
strength_close(krb5_context ctx UNUSED, krb5_pwqual_moddata data)
{
    struct class_rule *last, *tmp;

    if (data == NULL)
        return;
    strength_close_cdb(ctx, data);
    strength_close_sqlite(ctx, data);
    last = data->rules;
    while (last != NULL) {
        tmp = last;
        last = last->next;
        free(tmp);
    }
    free(data->dictionary);
    free(data);
}
