dnl Process this file with autoconf to produce a configure script.
dnl
dnl Written by Russ Allbery <eagle@eyrie.org>
dnl Copyright 2016 Russ Allbery <eagle@eyrie.org>
dnl Copyright 2006, 2007, 2009, 2010, 2012, 2013, 2014
dnl     The Board of Trustees of the Leland Stanford Junior University
dnl
dnl See LICENSE for licensing terms.

dnl Basic Autoconf configuration.
AC_PREREQ([2.64])
AC_INIT([krb5-strength], [3.1], [eagle@eyrie.org])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_LIBOBJ_DIR([portable])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 check-news dist-xz foreign silent-rules subdir-objects
    -Wall -Werror])
AM_MAINTAINER_MODE

dnl Detect unexpanded macros.
m4_pattern_forbid([^PKG_])
m4_pattern_forbid([^_?RRA_])

dnl Probe for basic build system tools.
AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
RRA_PROG_CC_WARNINGS_FLAGS
AC_SYS_LARGEFILE
AM_PROG_CC_C_O
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_PROG_INSTALL
AM_DISABLE_STATIC
LT_INIT

dnl External libraries.
RRA_LIB_CDB_OPTIONAL
RRA_LIB_CRACKLIB
AS_IF([test x"$rra_system_cracklib" = xyes],
    [RRA_LIB_CRACKLIB_SWITCH
     AC_CHECK_HEADERS([crack.h])
     RRA_LIB_CRACKLIB_RESTORE])
RRA_LIB_KRB5
RRA_LIB_KRB5_SWITCH
AC_CHECK_HEADERS([krb5/pwqual_plugin.h], [], [], [RRA_INCLUDES_KRB5])
AC_CHECK_TYPES([krb5_realm], [], [], [RRA_INCLUDES_KRB5])
AC_CHECK_FUNCS([krb5_free_default_realm \
    krb5_free_string \
    krb5_get_init_creds_opt_alloc \
    krb5_get_init_creds_opt_set_default_flags \
    krb5_principal_get_realm \
    krb5_xfree])
AC_CHECK_FUNCS([krb5_get_init_creds_opt_free],
    [RRA_FUNC_KRB5_GET_INIT_CREDS_OPT_FREE_ARGS])
AC_CHECK_DECLS([krb5_kt_free_entry], [], [], [RRA_INCLUDES_KRB5])
AC_LIBOBJ([krb5-extra])
AC_CHECK_HEADERS([kadm5/kadm5-pwcheck.h kadm5/kadm5_err.h], [], [],
    [RRA_INCLUDES_KRB5])
RRA_LIB_KRB5_RESTORE
RRA_LIB_SQLITE_OPTIONAL

dnl Probe for libdl, which is used for the test suite.
save_LIBS="$LIBS"
AC_SEARCH_LIBS([dlopen], [dl], [DL_LIBS="$LIBS"])
LIBS="$save_LIBS"
AC_SUBST([DL_LIBS])

dnl Checks for basic C functionality.
AC_HEADER_STDBOOL
AC_CHECK_HEADERS([sys/bittypes.h sys/select.h sys/time.h syslog.h])
AC_CHECK_DECLS([snprintf, vsnprintf])
RRA_C_C99_VAMACROS
RRA_C_GNU_VAMACROS
AC_TYPE_LONG_LONG_INT
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_CHECK_TYPES([ssize_t], [], [],
    [#include <sys/types.h>])
RRA_FUNC_SNPRINTF
AC_CHECK_FUNCS([setrlimit])
AC_REPLACE_FUNCS([asprintf mkstemp reallocarray strndup])

dnl Write out the results.
AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADER([config.h])
AC_OUTPUT
