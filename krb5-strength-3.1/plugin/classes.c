/*
 * Password strength checks for character classes.
 *
 * Checks whether the password satisfies a set of character class rules.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2016 Russ Allbery <eagle@eyrie.org>
 * Copyright 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <ctype.h>

#include <plugin/internal.h>

/* Stores the characteristics of a particular password as boolean flags. */
struct password_classes {
    bool lower;
    bool upper;
    bool digit;
    bool symbol;
    unsigned long num_classes;
};


/*
 * Analyze a password and fill out a struct with flags indicating which
 * character classes are present in the password.
 */
static void
analyze_password(const char *password, struct password_classes *classes)
{
    const char *p;

    memset(classes, 0, sizeof(struct password_classes));
    for (p = password; *p != '\0'; p++) {
        if (islower((unsigned char) *p))
            classes->lower = true;
        else if (isupper((unsigned char) *p))
            classes->upper = true;
        else if (isdigit((unsigned char) *p))
            classes->digit = true;
        else
            classes->symbol = true;
    }
    if (classes->lower)  classes->num_classes++;
    if (classes->upper)  classes->num_classes++;
    if (classes->digit)  classes->num_classes++;
    if (classes->symbol) classes->num_classes++;
}


/*
 * Check whether a password satisfies a required character class rule, given
 * the length of the password and the classes.  Returns 0 if it does and a
 * Kerberos error code if it does not.
 */
static krb5_error_code
check_rule(krb5_context ctx, struct class_rule *rule, size_t length,
           struct password_classes *classes)
{
    if (length < rule->min || (rule->max > 0 && length > rule->max))
        return 0;
    if (classes->num_classes < rule->num_classes)
        return strength_error_class(ctx, ERROR_CLASS_MIN, rule->num_classes);
    if (rule->lower && !classes->lower)
        return strength_error_class(ctx, ERROR_CLASS_LOWER);
    if (rule->upper && !classes->upper)
        return strength_error_class(ctx, ERROR_CLASS_UPPER);
    if (rule->digit && !classes->digit)
        return strength_error_class(ctx, ERROR_CLASS_DIGIT);
    if (rule->symbol && !classes->symbol)
        return strength_error_class(ctx, ERROR_CLASS_SYMBOL);
    return 0;
}


/*
 * Check whether a password satisfies the configured character class
 * restrictions.
 */
krb5_error_code
strength_check_classes(krb5_context ctx, krb5_pwqual_moddata data,
                       const char *password)
{
    struct password_classes classes;
    size_t length;
    struct class_rule *rule;
    krb5_error_code code;

    if (data->rules == NULL)
        return 0;
    analyze_password(password, &classes);
    length = strlen(password);
    for (rule = data->rules; rule != NULL; rule = rule->next) {
        code = check_rule(ctx, rule, length, &classes);
        if (code != 0)
            return code;
    }
    return 0;
}
