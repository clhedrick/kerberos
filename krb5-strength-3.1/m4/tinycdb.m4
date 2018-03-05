dnl Find the compiler and linker flags for libcdb.
dnl
dnl Finds the compiler and linker flags for linking with the libcdb library.
dnl Provides the --with-libcdb, --with-libcdb-lib, and --with-libcdb-include
dnl configure options to specify non-standard paths to libcdb libraries.
dnl
dnl Provides the macros RRA_LIB_CDB and RRA_LIB_CDB_OPTIONAL and sets the
dnl substitution variables CDB_CPPFLAGS, CDB_LDFLAGS, and CDB_LIBS.  Also
dnl provides RRA_LIB_CDB_SWITCH to set CPPFLAGS, LDFLAGS, and LIBS to include
dnl the TinyCDB libraries, saving the current values, and RRA_LIB_CDB_RESTORE
dnl to restore those settings to before the last RRA_LIB_CDB_SWITCH.  Defines
dnl HAVE_CDB and sets rra_use_CDB to true if the library is found.
dnl
dnl Depends on the lib-helper.m4 framework.
dnl
dnl The canonical version of this file is maintained in the rra-c-util
dnl package, available at <https://www.eyrie.org/~eagle/software/rra-c-util/>.
dnl
dnl Written by Russ Allbery <eagle@eyrie.org>
dnl Copyright 2013
dnl     The Board of Trustees of the Leland Stanford Junior University
dnl
dnl This file is free software; the authors give unlimited permission to copy
dnl and/or distribute it, with or without modifications, as long as this
dnl notice is preserved.

dnl Save the current CPPFLAGS, LDFLAGS, and LIBS settings and switch to
dnl versions that include the TinyCDB flags.  Used as a wrapper, with
dnl RRA_LIB_CDB_RESTORE, around tests.
AC_DEFUN([RRA_LIB_CDB_SWITCH], [RRA_LIB_HELPER_SWITCH([CDB])])

dnl Restore CPPFLAGS, LDFLAGS, and LIBS to their previous values (before
dnl RRA_LIB_CDB_SWITCH was called).
AC_DEFUN([RRA_LIB_CDB_RESTORE], [RRA_LIB_HELPER_RESTORE([CDB])])

dnl Checks if the libcdb library is present.  The single argument, if "true",
dnl says to fail if the libcdb library could not be found.
AC_DEFUN([_RRA_LIB_CDB_INTERNAL],
[RRA_LIB_HELPER_PATHS([CDB])
 RRA_LIB_CDB_SWITCH
 AC_CHECK_LIB([cdb], [cdb_init], [CDB_LIBS=-lcdb],
    [AS_IF([test x"$1" = xtrue],
        [AC_MSG_ERROR([cannot find usable TinyCDB library])])])
 AC_CHECK_HEADERS([cdb.h])
 RRA_LIB_CDB_RESTORE])

dnl The main macro for packages with mandatory TinyCDB support.
AC_DEFUN([RRA_LIB_CDB],
[RRA_LIB_HELPER_VAR_INIT([CDB])
 RRA_LIB_HELPER_WITH([tinycdb], [TinyCDB], [CDB])
 _RRA_LIB_CDB_INTERNAL([true])
 rra_use_CDB=true
 AC_DEFINE([HAVE_CDB], 1, [Define if libcdb is available.])])

dnl The main macro for packages with optional TinyCDB support.
AC_DEFUN([RRA_LIB_CDB_OPTIONAL],
[RRA_LIB_HELPER_VAR_INIT([CDB])
 RRA_LIB_HELPER_WITH_OPTIONAL([tinycdb], [TinyCDB], [CDB])
 AS_IF([test x"$rra_use_CDB" != xfalse],
    [AS_IF([test x"$rra_use_CDB" = xtrue],
        [_RRA_LIB_CDB_INTERNAL([true])],
        [_RRA_LIB_CDB_INTERNAL([false])])])
 AS_IF([test x"$CDB_LIBS" != x],
    [rra_use_CDB=true
     AC_DEFINE([HAVE_CDB], 1, [Define if libcdb is available.])])])
