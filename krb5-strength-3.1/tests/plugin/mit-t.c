/*
 * Test for the MIT Kerberos shared module API.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2010, 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/kadmin.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <dlfcn.h>
#include <errno.h>
#ifdef HAVE_KRB5_PWQUAL_PLUGIN_H
# include <krb5/pwqual_plugin.h>
#endif

#include <tests/tap/basic.h>
#include <tests/tap/kerberos.h>
#include <tests/tap/process.h>
#include <tests/tap/string.h>
#include <util/macros.h>

/*
 * The password test data, generated from the JSON source.  Defines arrays
 * named *_tests, where * is the file name without the ".c" suffix.
 */
#include <tests/data/passwords/cdb.c>
#include <tests/data/passwords/classes.c>
#include <tests/data/passwords/cracklib.c>
#include <tests/data/passwords/length.c>
#include <tests/data/passwords/letter.c>
#include <tests/data/passwords/principal.c>
#include <tests/data/passwords/sqlite.c>


#ifndef HAVE_KRB5_PWQUAL_PLUGIN_H
/*
 * If we're not building with MIT Kerberos, we can't run this test and much of
 * the test won't even compile.  Replace this test with a small program that
 * just calls skip_all.
 */
int
main(void)
{
    skip_all("not built against MIT libraries");
    return 0;
}

#else

/* The public symbol that we load and call to get the vtable. */
typedef krb5_error_code pwqual_strength_initvt(krb5_context, int, int,
                                               krb5_plugin_vtable);


/*
 * Loads the Heimdal password change plugin and tests that its metadata is
 * correct.  Returns a pointer to the kadm5_pw_policy_verifier struct or bails
 * on failure to load the plugin.  Stores the handle from dlopen in its second
 * argument for a later clean shutdown.
 */
static krb5_pwqual_vtable
load_plugin(krb5_context ctx, void **handle)
{
    char *path;
    krb5_error_code code;
    krb5_pwqual_vtable vtable = NULL;
    krb5_error_code (*init)(krb5_context, int, int, krb5_plugin_vtable);

    /* Load the module. */
    path = test_file_path("../plugin/.libs/strength.so");
    if (path == NULL)
        bail("cannot find plugin");
    *handle = dlopen(path, RTLD_NOW);
    if (*handle == NULL)
        bail("cannot dlopen %s: %s", path, dlerror());
    test_file_path_free(path);

    /* Find the entry point function. */
    init = dlsym(*handle, "pwqual_strength_initvt");
    if (init == NULL)
        bail("cannot get pwqual_strength_initvt symbol: %s", dlerror());

    /* Test for correct results when requesting the wrong API version. */
    code = init(ctx, 2, 0, (krb5_plugin_vtable) vtable);
    is_int(code, KRB5_PLUGIN_VER_NOTSUPP,
           "Correct status for bad major API version");

    /* Call that function properly to get the vtable. */
    vtable = bmalloc(sizeof(*vtable));
    code = init(ctx, 1, 1, (krb5_plugin_vtable) vtable);
    if (code != 0)
        bail_krb5(ctx, code, "cannot obtain module vtable");

    /* Check that all of the vtable entries are present. */
    if (vtable->open == NULL || vtable->check == NULL || vtable->close == NULL)
        bail("missing function in module vtable");

    /* Verify the metadata. */
    is_string("krb5-strength", vtable->name, "Module name");

    /* Return the vtable. */
    return vtable;
}


/*
 * Given a Kerberos context, the dispatch table, the module data, and a test
 * case, call out to the password strength checking module and check the
 * results.
 */
static void
is_password_test(krb5_context ctx, const krb5_pwqual_vtable vtable,
                 krb5_pwqual_moddata data, const struct password_test *test)
{
    krb5_principal princ;
    krb5_error_code code;
    const char *error;

    /* Translate the principal into a krb5_principal. */
    code = krb5_parse_name(ctx, test->principal, &princ);
    if (code != 0)
        bail_krb5(ctx, code, "cannot parse principal %s", test->principal);

    /* Call the verifier. */
    code = vtable->check(ctx, data, test->password, NULL, princ, NULL);

    /* Check the results against the test data. */
    is_int(test->code, code, "%s (status)", test->name);
    if (code == 0)
        is_string(test->error, NULL, "%s (error)", test->name);
    else {
        error = krb5_get_error_message(ctx, code);
        is_string(test->error, error, "%s (error)", test->name);
        krb5_free_error_message(ctx, error);
    }

    /* Free the parsed principal. */
    krb5_free_principal(ctx, princ);
}


int
main(void)
{
    char *path, *dictionary, *krb5_config, *krb5_config_empty, *tmpdir;
    char *setup_argv[12];
    const char*build;
    size_t i, count;
    krb5_context ctx;
    krb5_pwqual_vtable vtable;
    krb5_pwqual_moddata data;
    krb5_error_code code;
    void *handle;

    /*
     * Calculate how many tests we have.  There are two tests for the module
     * metadata, seven more tests for initializing the plugin, and two tests
     * per password test.
     *
     * We run all the CrackLib tests twice, once with an explicit dictionary
     * path and once from krb5.conf configuration.  We run the principal tests
     * with CrackLib, CDB, and SQLite configurations.
     */
    count = 2 * ARRAY_SIZE(cracklib_tests);
    count += 2 * ARRAY_SIZE(length_tests);
    count += ARRAY_SIZE(cdb_tests);
    count += ARRAY_SIZE(sqlite_tests);
    count += ARRAY_SIZE(classes_tests);
    count += ARRAY_SIZE(letter_tests);
    count += 3 * ARRAY_SIZE(principal_tests);
    plan(2 + 8 + count * 2);

    /* Start with the krb5.conf that contains no dictionary configuration. */
    path = test_file_path("data/krb5.conf");
    if (path == NULL)
        bail("cannot find data/krb5.conf in the test suite");
    basprintf(&krb5_config_empty, "KRB5_CONFIG=%s", path);
    putenv(krb5_config_empty);

    /* Obtain a Kerberos context with that krb5.conf file. */
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail_krb5(ctx, code, "cannot initialize Kerberos context");

    /* Load the plugin. */
    vtable = load_plugin(ctx, &handle);

    /* Initialize the plugin with a CrackLib dictionary. */
    build = getenv("BUILD");
    if (build == NULL)
        bail("BUILD not set in the environment");
    basprintf(&dictionary, "%s/data/dictionary", build);
    code = vtable->open(ctx, dictionary, &data);
    is_int(0, code, "Plugin initialization (explicit dictionary)");
    if (code != 0)
        bail("cannot continue after plugin initialization failure");

    /* Now, run all of the tests, with principal tests. */
    for (i = 0; i < ARRAY_SIZE(cracklib_tests); i++)
        is_password_test(ctx, vtable, data, &cracklib_tests[i]);
    for (i = 0; i < ARRAY_SIZE(principal_tests); i++)
        is_password_test(ctx, vtable, data, &principal_tests[i]);

    /* Close that initialization of the plugin and destroy that context. */
    vtable->close(ctx, data);
    krb5_free_context(ctx);
    ctx = NULL;

    /* Set up our krb5.conf with the dictionary configuration. */
    tmpdir = test_tmpdir();
    setup_argv[0] = test_file_path("data/make-krb5-conf");
    if (setup_argv[0] == NULL)
        bail("cannot find data/make-krb5-conf in the test suite");
    setup_argv[1] = path;
    setup_argv[2] = tmpdir;
    setup_argv[3] = (char *) "password_dictionary";
    setup_argv[4] = dictionary;
    setup_argv[5] = NULL;
    run_setup((const char **) setup_argv);

    /* Point KRB5_CONFIG at the newly-generated krb5.conf file. */
    basprintf(&krb5_config, "KRB5_CONFIG=%s/krb5.conf", tmpdir);
    putenv(krb5_config);
    free(krb5_config_empty);

    /* Obtain a new Kerberos context with that krb5.conf file. */
    krb5_free_context(ctx);
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail_krb5(ctx, code, "cannot initialize Kerberos context");

    /* Run all of the tests again.  No need to re-run principal tests. */
    code = vtable->open(ctx, NULL, &data);
    is_int(0, code, "Plugin initialization (krb5.conf dictionary)");
    if (code != 0)
        bail("cannot continue after plugin initialization failure");
    for (i = 0; i < ARRAY_SIZE(cracklib_tests); i++)
        is_password_test(ctx, vtable, data, &cracklib_tests[i]);
    vtable->close(ctx, data);

    /*
     * Add length restrictions and a maximum length for CrackLib.  This should
     * reject passwords as too short, but let through a password that's
     * actually in the CrackLib dictionary.
     */
    setup_argv[5] = (char *) "minimum_length";
    setup_argv[6] = (char *) "12";
    setup_argv[7] = (char *) "cracklib_maxlen";
    setup_argv[8] = (char *) "11";
    setup_argv[9] = NULL;
    run_setup((const char **) setup_argv);

    /* Obtain a new Kerberos context with that krb5.conf file. */
    krb5_free_context(ctx);
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail_krb5(ctx, code, "cannot initialize Kerberos context");

    /* Run all of the length tests. */
    code = vtable->open(ctx, NULL, &data);
    is_int(0, code, "Plugin initialization (length)");
    if (code != 0)
        bail("cannot continue after plugin initialization failure");
    for (i = 0; i < ARRAY_SIZE(length_tests); i++)
        is_password_test(ctx, vtable, data, &length_tests[i]);
    vtable->close(ctx, data);

    /* Add simple character class configuration to krb5.conf. */
    setup_argv[5] = (char *) "minimum_different";
    setup_argv[6] = (char *) "8";
    setup_argv[7] = (char *) "require_ascii_printable";
    setup_argv[8] = (char *) "true";
    setup_argv[9] = (char *) "require_non_letter";
    setup_argv[10] = (char *) "true";
    setup_argv[11] = NULL;
    run_setup((const char **) setup_argv);

    /* Obtain a new Kerberos context with that krb5.conf file. */
    krb5_free_context(ctx);
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail_krb5(ctx, code, "cannot initialize Kerberos context");

    /* Run all the simple character class tests. */
    code = vtable->open(ctx, NULL, &data);
    is_int(0, code, "Plugin initialization (simple character class)");
    if (code != 0)
        bail("cannot continue after plugin initialization failure");
    for (i = 0; i < ARRAY_SIZE(letter_tests); i++)
        is_password_test(ctx, vtable, data, &letter_tests[i]);
    vtable->close(ctx, data);

    /*
     * Add complex character class configuration to krb5.conf but drop
     * the dictionary configuration.
     */
    setup_argv[3] = (char *) "require_classes";
    setup_argv[4] = (char *) "8-19:lower,upper 8-15:digit 8-11:symbol 24-24:3";
    setup_argv[5] = NULL;
    run_setup((const char **) setup_argv);

    /* Obtain a new Kerberos context with that krb5.conf file. */
    krb5_free_context(ctx);
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail_krb5(ctx, code, "cannot initialize Kerberos context");

    /* Run all the complex character class tests. */
    code = vtable->open(ctx, NULL, &data);
    is_int(0, code, "Plugin initialization (complex character class)");
    if (code != 0)
        bail_krb5(ctx, code, "plugin initialization failure");
    for (i = 0; i < ARRAY_SIZE(classes_tests); i++)
        is_password_test(ctx, vtable, data, &classes_tests[i]);
    vtable->close(ctx, data);

    /* Re-run the length restriction checks with no dictionary at all. */
    setup_argv[3] = (char *) "minimum_length";
    setup_argv[4] = (char *) "12";
    setup_argv[5] = NULL;
    run_setup((const char **) setup_argv);

    /* Obtain a new Kerberos context with that krb5.conf file. */
    krb5_free_context(ctx);
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail_krb5(ctx, code, "cannot initialize Kerberos context");

    /* Run all of the length tests. */
    code = vtable->open(ctx, NULL, &data);
    is_int(0, code, "Plugin initialization (length)");
    if (code != 0)
        bail("cannot continue after plugin initialization failure");
    for (i = 0; i < ARRAY_SIZE(length_tests); i++)
        is_password_test(ctx, vtable, data, &length_tests[i]);
    vtable->close(ctx, data);

#ifdef HAVE_CDB

    /* If built with CDB, set up krb5.conf to use a CDB dictionary instead. */
    test_file_path_free(dictionary);
    dictionary = test_file_path("data/wordlist.cdb");
    if (dictionary == NULL)
        bail("cannot find data/wordlist.cdb in the test suite");
    setup_argv[3] = (char *) "password_dictionary_cdb";
    setup_argv[4] = dictionary;
    setup_argv[5] = NULL;
    run_setup((const char **) setup_argv);

    /* Obtain a new Kerberos context with that krb5.conf file. */
    krb5_free_context(ctx);
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail_krb5(ctx, code, "cannot initialize Kerberos context");

    /* Run the CDB and principal tests. */
    code = vtable->open(ctx, NULL, &data);
    is_int(0, code, "Plugin initialization (CDB dictionary)");
    if (code != 0)
        bail("cannot continue after plugin initialization failure");
    for (i = 0; i < ARRAY_SIZE(cdb_tests); i++)
        is_password_test(ctx, vtable, data, &cdb_tests[i]);
    for (i = 0; i < ARRAY_SIZE(principal_tests); i++)
        is_password_test(ctx, vtable, data, &principal_tests[i]);
    vtable->close(ctx, data);

#else /* !HAVE_CDB */

    /* Otherwise, mark the CDB tests as skipped. */
    count = ARRAY_SIZE(cdb_tests) + ARRAY_SIZE(principal_tests);
    skip_block(count * 2 + 1, "not built with CDB support");

#endif /* !HAVE_CDB */

#ifdef HAVE_SQLITE

    /*
     * If built with SQLite, set up krb5.conf to use a SQLite dictionary
     * instead.
     */
    test_file_path_free(dictionary);
    dictionary = test_file_path("data/wordlist.sqlite");
    if (dictionary == NULL)
        bail("cannot find data/wordlist.sqlite in the test suite");
    setup_argv[3] = (char *) "password_dictionary_sqlite";
    setup_argv[4] = dictionary;
    setup_argv[5] = NULL;
    run_setup((const char **) setup_argv);
    test_file_path_free(setup_argv[0]);
    test_file_path_free(path);

    /* Obtain a new Kerberos context with that krb5.conf file. */
    krb5_free_context(ctx);
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail_krb5(ctx, code, "cannot initialize Kerberos context");

    /* Run the SQLite and principal tests. */
    code = vtable->open(ctx, NULL, &data);
    is_int(0, code, "Plugin initialization (SQLite dictionary)");
    if (code != 0)
        bail("cannot continue after plugin initialization failure");
    for (i = 0; i < ARRAY_SIZE(sqlite_tests); i++)
        is_password_test(ctx, vtable, data, &sqlite_tests[i]);
    for (i = 0; i < ARRAY_SIZE(principal_tests); i++)
        is_password_test(ctx, vtable, data, &principal_tests[i]);
    vtable->close(ctx, data);

#else /* !HAVE_SQLITE */

    /* Otherwise, mark the SQLite tests as skipped. */
    count = ARRAY_SIZE(sqlite_tests) + ARRAY_SIZE(principal_tests);
    skip_block(count * 2 + 1, "not built with SQLite support");

#endif /* !HAVE_SQLITE */

    /* Manually clean up after the results of make-krb5-conf. */
    basprintf(&path, "%s/krb5.conf", tmpdir);
    unlink(path);
    free(path);
    test_tmpdir_free(tmpdir);

    /* Close down the module. */
    if (dlclose(handle) != 0)
        bail("cannot close plugin: %s", dlerror());

    /* Keep valgrind clean by freeing all memory. */
    test_file_path_free(dictionary);
    krb5_free_context(ctx);
    free(vtable);
    putenv((char *) "KRB5_CONFIG=");
    free(krb5_config);
    return 0;
}

#endif /* HAVE_KRB5_PWQUAL_PLUGIN_H */
