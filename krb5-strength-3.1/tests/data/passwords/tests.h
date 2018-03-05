/*
 * Type definition for password test data.
 *
 * This header provides the struct definition for password test data written
 * out by make-c-data.  It's included by the test data files.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#ifndef TESTS_DATA_PASSWORD_TESTS_H
#define TESTS_DATA_PASSWORD_TESTS_H 1

#include <config.h>
#include <portable/kadmin.h>
#include <portable/krb5.h>

struct password_test {
    const char *name;
    const char *principal;
    const char *password;
    krb5_error_code code;
    const char *error;
};

#endif /* !TESTS_DATA_PASSWORD_TESTS_H */
