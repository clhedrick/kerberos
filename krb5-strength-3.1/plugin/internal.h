/*
 * Prototypes for the kadmin password strength checking plugin.
 *
 * Developed by Derrick Brashear and Ken Hornstein of Sine Nomine Associates,
 *     on behalf of Stanford University
 * Extensive modifications by Russ Allbery <eagle@eyrie.org>
 * Copyright 2006, 2007, 2009, 2012, 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#ifndef PLUGIN_INTERNAL_H
#define PLUGIN_INTERNAL_H 1

#include <config.h>
#include <portable/krb5.h>
#include <portable/macros.h>

#ifdef HAVE_CDB_H
# include <cdb.h>
#endif
#ifdef HAVE_SQLITE3_H
# include <sqlite3.h>
#endif
#include <stddef.h>

#ifdef HAVE_KRB5_PWQUAL_PLUGIN_H
# include <krb5/pwqual_plugin.h>
#else
typedef struct krb5_pwqual_moddata_st *krb5_pwqual_moddata;
#endif

/* Error strings returned (and displayed to the user) for various failures. */
#define ERROR_ASCII        "Password contains non-ASCII or control characters"
#define ERROR_CLASS_LOWER  "Password must contain a lowercase letter"
#define ERROR_CLASS_UPPER  "Password must contain an uppercase letter"
#define ERROR_CLASS_DIGIT  "Password must contain a number"
#define ERROR_CLASS_SYMBOL \
    "Password must contain a space or punctuation character"
#define ERROR_CLASS_MIN \
    "Password must contain %lu types of characters (lowercase, uppercase," \
    " numbers, symbols)"
#define ERROR_DICT         "Password found in list of common passwords"
#define ERROR_LETTER       "Password is only letters and spaces"
#define ERROR_MINDIFF      "Password does not contain enough unique characters"
#define ERROR_SHORT        "Password is too short"
#define ERROR_USERNAME     "Password based on username or principal"

/*
 * A character class rule, which consists of a minimum length to which the
 * rule is applied, a maximum length to which the rule is applied, and a set
 * of flags for which character classes are required.  The symbol class
 * includes everything that isn't in one of the other classes, including
 * space.
 */
struct class_rule {
    unsigned long min;
    unsigned long max;
    bool lower;
    bool upper;
    bool digit;
    bool symbol;
    unsigned long num_classes;
    struct class_rule *next;
};

/* Used to store a list of strings, managed by the sync_vector_* functions. */
struct vector {
    size_t count;
    size_t allocated;
    char **strings;
};

/*
 * MIT Kerberos uses this type as an abstract data type for any data that a
 * password quality check needs to carry.  Reuse it since then we get type
 * checking for at least the MIT plugin.
 */
struct krb5_pwqual_moddata_st {
    long minimum_different;     /* Minimum number of different characters */
    long minimum_length;        /* Minimum password length */
    bool ascii;                 /* Whether to require printable ASCII */
    bool nonletter;             /* Whether to require a non-letter */
    struct class_rule *rules;   /* Linked list of character class rules */
    char *dictionary;           /* Base path to CrackLib dictionary */
    long cracklib_maxlen;       /* Longer passwords skip CrackLib checks */
    bool have_cdb;              /* Whether we have a CDB dictionary */
    int cdb_fd;                 /* File descriptor of CDB dictionary */
#ifdef HAVE_CDB_H
    struct cdb cdb;             /* Open CDB dictionary data */
#endif
#ifdef HAVE_SQLITE3_H
    sqlite3 *sqlite;            /* Open SQLite database handle */
    sqlite3_stmt *prefix_query; /* Query using the password prefix */
    sqlite3_stmt *suffix_query; /* Query using the reversed password suffix */
#endif
};

BEGIN_DECLS

/* Default to a hidden visibility for all internal functions. */
#pragma GCC visibility push(hidden)

/* Initialize the plugin and set up configuration. */
krb5_error_code strength_init(krb5_context, const char *dictionary,
                              krb5_pwqual_moddata *);

/*
 * Check a password.  Returns 0 if okay.  On error, sets the Kerberos error
 * message and returns a Kerberos status code.
 */
krb5_error_code strength_check(krb5_context, krb5_pwqual_moddata,
                               const char *principal, const char *password);

/* Free the internal plugin state. */
void strength_close(krb5_context, krb5_pwqual_moddata);

/*
 * CDB handling.  strength_init_cdb gets the dictionary configuration and sets
 * up the CDB database, strength_check_cdb checks it, and strength_close_cdb
 * handles freeing resources.
 *
 * If not built with CDB support, provide some stubs for check and close.
 * init is always a real function, which reports an error if CDB is
 * requested and not available.
 */
krb5_error_code strength_init_cdb(krb5_context, krb5_pwqual_moddata);
#ifdef HAVE_CDB
krb5_error_code strength_check_cdb(krb5_context, krb5_pwqual_moddata,
                                   const char *password);
void strength_close_cdb(krb5_context, krb5_pwqual_moddata);
#else
# define strength_check_cdb(c, d, p) 0
# define strength_close_cdb(c, d)    /* empty */
#endif

/*
 * CrackLib handling.  strength_init_cracklib gets the dictionary
 * configuration does some sanity checks on it, and strength_check_cracklib
 * checks the password against CrackLib.
 */
krb5_error_code strength_init_cracklib(krb5_context, krb5_pwqual_moddata,
                                       const char *dictionary);
krb5_error_code strength_check_cracklib(krb5_context, krb5_pwqual_moddata,
                                        const char *password);

/*
 * SQLite handling.  strength_init_sqlite gets the database configuration and
 * sets up the SQLite internal data, strength_check_sqlite checks a password,
 * and strength_close_sqlite handles freeing resources.
 *
 * If not built with SQLite support, provide some stubs for check and close.
 * init is always a real function, which reports an error if SQLite is
 * requested and not available.
 */
krb5_error_code strength_init_sqlite(krb5_context, krb5_pwqual_moddata);
#ifdef HAVE_SQLITE
krb5_error_code strength_check_sqlite(krb5_context, krb5_pwqual_moddata,
                                      const char *password);
void strength_close_sqlite(krb5_context, krb5_pwqual_moddata);
#else
# define strength_check_sqlite(c, d, p) 0
# define strength_close_sqlite(c, d)    /* empty */
#endif

/* Check whether the password statisfies character class requirements. */
krb5_error_code strength_check_classes(krb5_context, krb5_pwqual_moddata,
                                       const char *password);

/* Check whether the password is based on the principal in some way. */
krb5_error_code strength_check_principal(krb5_context, krb5_pwqual_moddata,
                                         const char *principal,
                                         const char *password);

/*
 * Manage vectors, which are counted lists of strings.  The functions that
 * return a boolean return false if memory allocation fails.
 */
struct vector *strength_vector_new(void)
    __attribute__((__malloc__));
bool strength_vector_add(struct vector *, const char *string)
    __attribute__((__nonnull__));
void strength_vector_free(struct vector *);

/*
 * vector_split_multi splits on a set of characters.  If the vector argument
 * is NULL, a new vector is allocated; otherwise, the provided one is reused.
 * Returns NULL on memory allocation failure, after which the provided vector
 * may have been modified to only have partial results.
 *
 * Empty strings will yield zero-length vectors.  Adjacent delimiters are
 * treated as a single delimiter by vector_split_multi.  Any leading or
 * trailing delimiters are ignored, so this function will never create
 * zero-length strings (similar to the behavior of strtok).
 */
struct vector *strength_vector_split_multi(const char *string,
                                           const char *seps, struct vector *)
    __attribute__((__nonnull__(1, 2)));

/*
 * Obtain configuration settings from krb5.conf.  These are wrappers around
 * the krb5_appdefault_* APIs that handle setting the section name, obtaining
 * the local default realm and using it to find settings, and doing any
 * necessary conversion.
 */
void strength_config_boolean(krb5_context, const char *, bool *)
    __attribute__((__nonnull__));
krb5_error_code strength_config_list(krb5_context, const char *,
                                     struct vector **)
    __attribute__((__nonnull__));
void strength_config_number(krb5_context, const char *, long *)
    __attribute__((__nonnull__));
void strength_config_string(krb5_context, const char *, char **)
    __attribute__((__nonnull__));

/* Parse the more complex configuration of required character classes. */
krb5_error_code strength_config_classes(krb5_context, const char *,
                                        struct class_rule **)
    __attribute__((__nonnull__));

/*
 * Store a particular password quality error in the Kerberos context.  The
 * _system variant uses errno for the error code and appends the strerror
 * results to the message.  All versions return the error code set.
 */
krb5_error_code strength_error_class(krb5_context, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));
krb5_error_code strength_error_config(krb5_context, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));
krb5_error_code strength_error_dict(krb5_context, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));
krb5_error_code strength_error_generic(krb5_context, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));
krb5_error_code strength_error_system(krb5_context, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));
krb5_error_code strength_error_tooshort(krb5_context, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));

/* Undo default visibility change. */
#pragma GCC visibility pop

END_DECLS

#endif /* !PLUGIN_INTERNAL_H */
