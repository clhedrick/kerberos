/*
 * Password strength checks based on the principal.
 *
 * Performs various checks of the password against the principal for which the
 * password is being changed, trying to detect and reject passwords based on
 * components of the principal.
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
#include <portable/system.h>

#include <ctype.h>

#include <plugin/internal.h>
#include <util/macros.h>


/*
 * Given a string taken from the principal, check if the password matches that
 * string or is that string with leading or trailing digits added.  If so,
 * sets the Kerberos error and returns a non-zero error code.  Otherwise,
 * returns 0.
 */
static krb5_error_code
check_component(krb5_context ctx, const char *component, const char *password)
{
    char *copy;
    size_t i, j, complength, passlength;
    char c;

    /* Check if the password is a simple match for the component. */
    if (strcasecmp(component, password) == 0)
        return strength_error_generic(ctx, ERROR_USERNAME);

    /*
     * If the length of the password matches the length of the component,
     * check for a reversed match.
     */
    complength = strlen(component);
    passlength = strlen(password);
    if (complength == passlength) {
        copy = strdup(component);
        if (copy == NULL)
            return strength_error_system(ctx, "cannot allocate memory");
        for (i = 0, j = complength - 1; i < j; i++, j--) {
            c = copy[i];
            copy[i] = copy[j];
            copy[j] = c;
        }
        if (strcasecmp(copy, password) == 0) {
            memset(copy, 0, strlen(copy));
            free(copy);
            return strength_error_generic(ctx, ERROR_USERNAME);
        }
        free(copy);
    }

    /*
     * We've checked everything we care about unless the password is longer
     * than the component.
     */
    if (passlength <= complength)
        return 0;

    /*
     * Check whether the user just added leading or trailing digits to the
     * component of the principal to form the password.
     */
    for (i = 0; i <= passlength - complength; i++) {
        if (strncasecmp(password + i, component, complength) != 0)
            continue;

        /*
         * For this to be a match, all characters from 0 to i - 1 must be
         * digits, and all characters from strlen(component) + i to
         * strlen(password) - 1 must be digits.
         */
        for (j = 0; j < i; j++)
            if (!isdigit((unsigned char) password[j]))
                return 0;
        for (j = complength + i; j < passlength; j++)
            if (!isdigit((unsigned char) password[j]))
                return 0;

        /* The password was formed by adding digits to this component. */
        return strength_error_generic(ctx, ERROR_USERNAME);
    }

    /* No similarity to component detected. */
    return 0;
}


/*
 * Returns true if a given character is a separator character for forming
 * components, and false otherwise.
 */
static bool
is_separator(unsigned char c)
{
    if (c == '-' || c == '_')
        return false;
    if (isalnum(c))
        return false;
    return true;
}


/*
 * Check whether the password is based in some way on the principal.  We do
 * this by scanning the principal (in string form) and checking both each
 * component of that password (defined as the alphanumeric, hyphen, and
 * underscore bits between other characters) and the remaining principal from
 * that point forward (to catch, for example, the entire realm).  Returns 0 if
 * it is not and some non-zero error code if it appears to be.
 */
krb5_error_code
strength_check_principal(krb5_context ctx, krb5_pwqual_moddata data UNUSED,
                         const char *principal, const char *password)
{
    krb5_error_code code;
    char *copy, *start;
    size_t i, length;

    /* Sanity check. */
    if (principal == NULL)
        return 0;

    /* Start with checking the entire principal. */
    code = check_component(ctx, principal, password);
    if (code != 0)
        return code;

    /*
     * Make a copy of the principal and scan forward past any leading
     * separators.
     */
    length = strlen(principal);
    copy = strdup(principal);
    if (copy == NULL)
        return strength_error_system(ctx, "cannot allocate memory");
    i = 0;
    while (copy[i] != '\0' && is_separator(copy[i]))
        i++;

    /*
     * Now loop for each component.  At the start of each loop, check against
     * the component formed by the rest of the principal string.
     */
    do {
        if (i != 0) {
            code = check_component(ctx, copy + i, password);
            if (code != 0) {
                memset(copy, 0, strlen(copy));
                free(copy);
                return code;
            }
        }

        /* Set the component start and then scan for a separator. */
        start = copy + i;
        while (i < length && !is_separator(copy[i]))
            i++;

        /* At end of string or a separator.  Truncate the component. */
        copy[i] = '\0';

        /* Check the current component. */
        code = check_component(ctx, start, password);
        if (code != 0) {
            memset(copy, 0, strlen(copy));
            free(copy);
            return code;
        }

        /* Scan forward past any more separators. */
        while (i < length && is_separator(copy[i]))
            i++;
    } while (i < length);

    /* Password does not appear to be based on the principal. */
    memset(copy, 0, strlen(copy));
    free(copy);
    return 0;
}
