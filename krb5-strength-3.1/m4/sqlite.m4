dnl Find the compiler and linker flags for SQLite.
dnl
dnl Finds the compiler and linker flags for linking with the SQLite library.
dnl Provides the --with-sqlite, --with-sqlite-lib, and --with-sqlite-include
dnl configure options to specify non-standard paths to the SQLite libraries or
dnl header files.  Currently, only SQLite 3 is considered sufficient.
dnl
dnl Provides the macros RRA_LIB_SQLITE and RRA_LIB_SQLITE_OPTIONAL and sets
dnl the substitution variables SQLITE_CPPFLAGS, SQLITE_LDFLAGS, and
dnl SQLITE_LIBS.  Also provides RRA_LIB_SQLITE_SWITCH to set CPPFLAGS,
dnl LDFLAGS, and LIBS to include the SQLite libraries, saving the current
dnl values first, and RRA_LIB_SQLITE_RESTORE to restore those settings to
dnl before the last RRA_LIB_SQLITE_SWITCH.  Defines HAVE_SQLITE and sets
dnl rra_use_SQLITE to true if libevent is found.  If it isn't found, the
dnl substitution variables will be empty.
dnl
dnl Depends on the lib-helper.m4 framework.
dnl
dnl The canonical version of this file is maintained in the rra-c-util
dnl package, available at <https://www.eyrie.org/~eagle/software/rra-c-util/>.
dnl
dnl Written by Russ Allbery <eagle@eyrie.org>
dnl Copyright 2014
dnl     The Board of Trustees of the Leland Stanford Junior University
dnl
dnl This file is free software; the authors give unlimited permission to copy
dnl and/or distribute it, with or without modifications, as long as this
dnl notice is preserved.

dnl Save the current CPPFLAGS, LDFLAGS, and LIBS settings and switch to
dnl versions that include the libevent flags.  Used as a wrapper, with
dnl RRA_LIB_SQLITE_RESTORE, around tests.
AC_DEFUN([RRA_LIB_SQLITE_SWITCH], [RRA_LIB_HELPER_SWITCH([SQLITE])])

dnl Restore CPPFLAGS, LDFLAGS, and LIBS to their previous values before
dnl RRA_LIB_SQLITE_SWITCH was called.
AC_DEFUN([RRA_LIB_SQLITE_RESTORE], [RRA_LIB_HELPER_RESTORE([SQLITE])])

dnl Checks if SQLite is present.  The single argument, if "true", says to fail
dnl if the SQLite library could not be found.  Prefer probing with pkg-config
dnl if available and the --with flags were not given.
AC_DEFUN([_RRA_LIB_SQLITE_INTERNAL],
[RRA_LIB_HELPER_PATHS([SQLITE])
 AS_IF([test x"$SQLITE_CPPFLAGS" = x && test x"$SQLITE_LDFLAGS" = x],
    [PKG_CHECK_EXISTS([sqlite3],
        [PKG_CHECK_MODULES([SQLITE], [sqlite3])
         SQLITE_CPPFLAGS="$SQLITE_CFLAGS"])])
 AS_IF([test x"$SQLITE_LIBS" = x],
    [RRA_LIB_SQLITE_SWITCH
     LIBS=
     AC_SEARCH_LIBS([sqlite3_open_v2], [sqlite3],
        [SQLITE_LIBS="$LIBS"],
        [AS_IF([test x"$1" = xtrue],
            [AC_MSG_ERROR([cannot find usable SQLite library])])])
     RRA_LIB_SQLITE_RESTORE])
 RRA_LIB_SQLITE_SWITCH
 AC_CHECK_HEADERS([sqlite3.h])
 RRA_LIB_SQLITE_RESTORE])

dnl The main macro for packages with mandatory SQLite 3 support.
AC_DEFUN([RRA_LIB_SQLITE],
[RRA_LIB_HELPER_VAR_INIT([SQLITE])
 RRA_LIB_HELPER_WITH([sqlite], [SQLite], [SQLITE])
 _RRA_LIB_SQLITE_INTERNAL([true])
 rra_use_SQLITE=true
 AC_DEFINE([HAVE_SQLITE], 1, [Define if SQLite is available.])])

dnl The main macro for packages with optional SQLite support.
AC_DEFUN([RRA_LIB_SQLITE_OPTIONAL],
[RRA_LIB_HELPER_VAR_INIT([SQLITE])
 RRA_LIB_HELPER_WITH_OPTIONAL([sqlite], [SQLite], [SQLITE])
 AS_IF([test x"$rra_use_SQLITE" != xfalse],
    [AS_IF([test x"$rra_use_SQLITE" = xtrue],
        [_RRA_LIB_SQLITE_INTERNAL([true])],
        [_RRA_LIB_SQLITE_INTERNAL([false])])])
 AS_IF([test x"$SQLITE_LIBS" != x],
    [rra_use_SQLITE=true
     AC_DEFINE([HAVE_SQLITE], 1, [Define if SQLite is available.])])])
