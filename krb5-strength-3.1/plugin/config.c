/*
 * Retrieve configuration settings from krb5.conf.
 *
 * Provided here are functions to retrieve boolean, numeric, and string
 * settings from krb5.conf.  This wraps the somewhat awkward
 * krb5_appdefaults_* functions.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2016 Russ Allbery <eagle@eyrie.org>
 * Copyright 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <ctype.h>
#include <errno.h>

#include <plugin/internal.h>
#include <util/macros.h>

/* The representation of the realm differs between MIT and Kerberos. */
#ifdef HAVE_KRB5_REALM
typedef krb5_realm realm_type;
#else
typedef krb5_data *realm_type;
#endif

/* Maximum number of character classes. */
#define MAX_CLASSES 4


/*
 * Obtain the default realm and translate it into the format required by
 * krb5_appdefault_*.  This is obnoxious for MIT Kerberos, which returns the
 * default realm as a string but expects the realm as a krb5_data type when
 * calling krb5_appdefault_*.
 */
#ifdef HAVE_KRB5_REALM

static realm_type
default_realm(krb5_context ctx)
{
    krb5_error_code code;
    realm_type realm;

    code = krb5_get_default_realm(ctx, &realm);
    if (code != 0)
        realm = NULL;
    return realm;
}

#else /* !HAVE_KRB5_REALM */

static realm_type
default_realm(krb5_context ctx)
{
    char *realm = NULL;
    krb5_error_code code;
    krb5_data *realm_data;

    realm_data = calloc(1, sizeof(krb5_data));
    if (realm_data == NULL)
        return NULL;
    code = krb5_get_default_realm(ctx, &realm);
    if (code != 0) {
        free(realm);
        return NULL;
    }
    realm_data->magic = KV5M_DATA;
    realm_data->data = strdup(realm);
    if (realm_data->data == NULL) {
        free(realm_data);
        krb5_free_default_realm(ctx, realm);
        return NULL;
    }
    realm_data->length = strlen(realm);
    krb5_free_default_realm(ctx, realm);
    return realm_data;
}

#endif /* !HAVE_KRB5_REALM */


/*
 * Free the default realm data in whatever form it was generated for the calls
 * to krb5_appdefault_*.
 */
#ifdef HAVE_KRB5_REALM

static void
free_default_realm(krb5_context ctx UNUSED, realm_type realm)
{
    krb5_free_default_realm(ctx, realm);
}

#else /* !HAVE_KRB5_REALM */

static void
free_default_realm(krb5_context ctx UNUSED, realm_type realm)
{
    free(realm->data);
    free(realm);
}

#endif /* !HAVE_KRB5_REALM */


/*
 * Helper function to parse a number.  Takes the string to parse, the unsigned
 * int in which to store the number, and the pointer to set to the first
 * invalid character after the number.  Returns true if a number could be
 * successfully parsed and false otherwise.
 */
static bool
parse_number(const char *string, unsigned long *result, const char **end)
{
    unsigned long value;

    errno = 0;
    value = strtoul(string, (char **) end, 10);
    if (errno != 0 || *end == string)
        return false;
    *result = value;
    return true;
}


/*
 * Load a boolean option from Kerberos appdefaults.  Takes the Kerberos
 * context, the option, and the result location.
 */
void
strength_config_boolean(krb5_context ctx, const char *opt, bool *result)
{
    realm_type realm;
    int tmp;

    /*
     * The MIT version of krb5_appdefault_boolean takes an int * and the
     * Heimdal version takes a krb5_boolean *, so hope that Heimdal always
     * defines krb5_boolean to int or this will require more portability work.
     */
    realm = default_realm(ctx);
    krb5_appdefault_boolean(ctx, "krb5-strength", realm, opt, *result, &tmp);
    *result = tmp;
    free_default_realm(ctx, realm);
}


/*
 * Parse a single class specification.  Currently, this assumes that the class
 * specification is a comma-separated list of required classes, and those
 * classes are required for any length of password.  This will be enhanced
 * later.
 */
static krb5_error_code
parse_class(krb5_context ctx, const char *spec, struct class_rule **rule)
{
    struct vector *classes = NULL;
    size_t i;
    krb5_error_code code;
    const char *class, *end;
    bool okay;

    /* Create the basic rule structure. */
    *rule = calloc(1, sizeof(struct class_rule));
    if (*rule == NULL)
        return strength_error_system(ctx, "cannot allocate memory");

    /*
     * If the rule starts with a digit and contains a '-', it starts
     * with a range of affected password lengths.  Parse that range.
     */
    if (isdigit((unsigned char) *spec) && strchr(spec, '-') != NULL) {
        okay = parse_number(spec, &(*rule)->min, &end);
        if (okay)
            okay = (*end == '-');
        if (okay)
            okay = parse_number(end + 1, &(*rule)->max, &end);
        if (okay)
            okay = (*end == ':');
        if (okay)
            spec = end + 1;
        else {
            code = strength_error_config(ctx, "bad character class requirement"
                                         " in configuration: %s", spec);
            goto fail;
        }
    }

    /* Parse the required classes into a vector. */
    classes = strength_vector_split_multi(spec, ",", NULL);
    if (classes == NULL) {
        code = strength_error_system(ctx, "cannot allocate memory");
        goto fail;
    }

    /*
     * Walk the list of required classes and set our flags, diagnosing an
     * unknown character class.
     */
    for (i = 0; i < classes->count; i++) {
        class = classes->strings[i];
        if (strcmp(class, "upper") == 0)
            (*rule)->upper = true;
        else if (strcmp(class, "lower") == 0)
            (*rule)->lower = true;
        else if (strcmp(class, "digit") == 0)
            (*rule)->digit = true;
        else if (strcmp(class, "symbol") == 0)
            (*rule)->symbol = true;
	else if (isdigit((unsigned char) *class)) {
	    okay = parse_number(class, &(*rule)->num_classes, &end);
	    if (!okay || *end != '\0' || (*rule)->num_classes > MAX_CLASSES) {
                code = strength_error_config(ctx, "bad character class minimum"
                                             " in configuration: %s", class);
		goto fail;
	    }
	}
        else {
            code = strength_error_config(ctx, "unknown character class %s",
                                         class);
            goto fail;
        }
    }
    strength_vector_free(classes);
    return 0;

fail:
    strength_vector_free(classes);
    free(*rule);
    *rule = NULL;
    return code;
}


/*
 * Parse character class requirements from Kerberos appdefaults.  Takes the
 * Kerberos context, the option, and the place to store the linked list of
 * class requirements.
 */
krb5_error_code
strength_config_classes(krb5_context ctx, const char *opt,
                        struct class_rule **result)
{
    struct vector *config = NULL;
    struct class_rule *rules, *last, *tmp;
    krb5_error_code code;
    size_t i;

    /* Get the basic configuration as a list. */
    code = strength_config_list(ctx, opt, &config);
    if (code != 0)
        return code;
    if (config == NULL || config->count == 0) {
        *result = NULL;
        return 0;
    }

    /* Each word in the list will be a class rule. */
    code = parse_class(ctx, config->strings[0], &rules);
    if (code != 0 || rules == NULL)
        goto fail;
    last = rules;
    for (i = 1; i < config->count; i++) {
        code = parse_class(ctx, config->strings[i], &last->next);
        if (code != 0 || last->next == NULL)
            goto fail;
        last = last->next;
    }

    /* Success.  Free the vector and return the results. */
    strength_vector_free(config);
    *result = rules;
    return 0;

fail:
    last = rules;
    while (last != NULL) {
        tmp = last;
        last = last->next;
        free(tmp);
    }
    strength_vector_free(config);
    return code;
}


/*
 * Load a list option from Kerberos appdefaults.  Takes the Kerberos context,
 * the option, and the result location.  The option is read as a string and
 * the split on spaces and tabs into a list.
 *
 * This requires an annoying workaround because one cannot specify a default
 * value of NULL with MIT Kerberos, since MIT Kerberos unconditionally calls
 * strdup on the default value.  There's also no way to determine if memory
 * allocation failed while parsing or while setting the default value.
 */
krb5_error_code
strength_config_list(krb5_context ctx, const char *opt,
                     struct vector **result)
{
    realm_type realm;
    char *value = NULL;

    /* Obtain the string from [appdefaults]. */
    realm = default_realm(ctx);
    krb5_appdefault_string(ctx, "krb5-strength", realm, opt, "", &value);
    free_default_realm(ctx, realm);

    /* If we got something back, store it in result. */
    if (value != NULL) {
        if (value[0] != '\0') {
            *result = strength_vector_split_multi(value, " \t", *result);
            if (*result == NULL)
                return strength_error_system(ctx, "cannot allocate memory");
        }
        krb5_free_string(ctx, value);
    }
    return 0;
}


/*
 * Load a number option from Kerberos appdefaults.  Takes the Kerberos
 * context, the option, and the result location.  The native interface doesn't
 * support numbers, so we actually read a string and then convert.
 */
void
strength_config_number(krb5_context ctx, const char *opt, long *result)
{
    realm_type realm;
    char *tmp = NULL;
    char *end;
    long value;

    /* Obtain the setting in string form from [appdefaults]. */
    realm = default_realm(ctx);
    krb5_appdefault_string(ctx, "krb5-strength", realm, opt, "", &tmp);
    free_default_realm(ctx, realm);

    /*
     * If we found anything, convert it to a number.  Currently, we ignore
     * errors here.
     */
    if (tmp != NULL && tmp[0] != '\0') {
        errno = 0;
        value = strtol(tmp, &end, 10);
        if (errno == 0 && *end == '\0')
            *result = value;
    }
    if (tmp != NULL)
        krb5_free_string(ctx, tmp);
}


/*
 * Load a string option from Kerberos appdefaults.  Takes the Kerberos
 * context, the option, and the result location.
 *
 * This requires an annoying workaround because one cannot specify a default
 * value of NULL with MIT Kerberos, since MIT Kerberos unconditionally calls
 * strdup on the default value.  There's also no way to determine if memory
 * allocation failed while parsing or while setting the default value, so we
 * don't return an error code.
 */
void
strength_config_string(krb5_context ctx, const char *opt, char **result)
{
    realm_type realm;
    char *value = NULL;

    /* Obtain the string from [appdefaults]. */
    realm = default_realm(ctx);
    krb5_appdefault_string(ctx, "krb5-strength", realm, opt, "", &value);
    free_default_realm(ctx, realm);

    /* If we got something back, store it in result. */
    if (value != NULL) {
        if (value[0] != '\0') {
            free(*result);
            *result = strdup(value);
        }
        krb5_free_string(ctx, value);
    }
}
