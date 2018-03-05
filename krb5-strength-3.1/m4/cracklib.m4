dnl Find the compiler and linker flags for CrackLib.
dnl
dnl Allows the user to specify that the system CrackLib should be used instead
dnl of the embedded version by using --with-cracklib.  In that case, finds the
dnl compiler and linker flags for that version.  Also provides
dnl --with-cracklib-include and --with-cracklib-lib configure options to
dnl specify non-standard paths to the CrackLib headers and libraries.
dnl
dnl Provides the macro RRA_LIB_CRACKLIB.  If --with-cracklib is not specified,
dnl this macro will set the Automake conditional EMBEDDED_CRACKLIB.  If it is
dnl specified, sets the substitution variables CRACKLIB_CPPFLAGS,
dnl CRACKLIB_LDFLAGS, and CRACKLIB_LIBS.  Also provides
dnl RRA_LIB_CRACKLIB_SWITCH to set CPPFLAGS, LDFLAGS, and LIBS to include the
dnl remctl libraries, saving the current values first, and
dnl RRA_LIB_CRACKLIB_RESTORE to restore those settings to before the last
dnl RRA_LIB_CRACKLIB_SWITCH.
dnl
dnl Depends on RRA_SET_LDFLAGS.
dnl
dnl Written by Russ Allbery <eagle@eyrie.org>
dnl Copyright 2010
dnl     The Board of Trustees of the Leland Stanford Junior University
dnl
dnl This file is free software; the authors give unlimited permission to copy
dnl and/or distribute it, with or without modifications, as long as this
dnl notice is preserved.

dnl Save the current CPPFLAGS, LDFLAGS, and LIBS settings and switch to
dnl versions that include the Kerberos v5 flags.  Used as a wrapper, with
dnl RRA_LIB_CRACKLIB_RESTORE, around tests.
AC_DEFUN([RRA_LIB_CRACKLIB_SWITCH],
[rra_cracklib_save_CPPFLAGS="$CPPFLAGS"
 rra_cracklib_save_LDFLAGS="$LDFLAGS"
 rra_cracklib_save_LIBS="$LIBS"
 CPPFLAGS="$CRACKLIB_CPPFLAGS $CPPFLAGS"
 LDFLAGS="$CRACKLIB_LDFLAGS $LDFLAGS"
 LIBS="$CRACKLIB_LIBS $LIBS"])

dnl Restore CPPFLAGS, LDFLAGS, and LIBS to their previous values (before
dnl RRA_LIB_CRACKLIB_SWITCH was called).
AC_DEFUN([RRA_LIB_CRACKLIB_RESTORE],
[CPPFLAGS="$rra_cracklib_save_CPPFLAGS"
 LDFLAGS="$rra_cracklib_save_LDFLAGS"
 LIBS="$rra_cracklib_save_LIBS"])

dnl Set CRACKLIB_CPPFLAGS and CRACKLIB_LDFLAGS based on rra_cracklib_root,
dnl rra_cracklib_libdir, and rra_cracklib_includedir.
AC_DEFUN([_RRA_LIB_CRACKLIB_PATHS],
[AS_IF([test x"$rra_cracklib_libdir" != x],
    [CRACKLIB_LDFLAGS="-L$rra_cracklib_libdir"],
    [AS_IF([test x"$rra_cracklib_root" != x],
        [RRA_SET_LDFLAGS([CRACKLIB_LDFLAGS], [$rra_cracklib_root])])])
 AS_IF([test x"$rra_cracklib_includedir" != x],
    [CRACKLIB_CPPFLAGS="-I$rra_cracklib_includedir"],
    [AS_IF([test x"$rra_cracklib_root" != x],
        [AS_IF([test x"$rra_cracklib_root" != x/usr],
            [CRACKLIB_CPPFLAGS="-I${rra_cracklib_root}/include"])])])])

dnl Sanity-check the results of the CrackLib library search to be sure we can
dnl really link a CrackLib program.
AC_DEFUN([_RRA_LIB_CRACKLIB_CHECK],
[RRA_LIB_CRACKLIB_SWITCH
 AC_CHECK_FUNC([FascistCheck], ,
    [AC_MSG_FAILURE([unable to link with CrackLib library])])
 RRA_LIB_CRACKLIB_RESTORE])

dnl The main macro.
AC_DEFUN([RRA_LIB_CRACKLIB],
[rra_system_cracklib=
 rra_cracklib_root=
 rra_cracklib_libdir=
 rra_cracklib_includedir=
 CRACKLIB_CPPFLAGS=
 CRACKLIB_LDFLAGS=
 CRACKLIB_LIBS=
 AC_SUBST([CRACKLIB_CPPFLAGS])
 AC_SUBST([CRACKLIB_LDFLAGS])
 AC_SUBST([CRACKLIB_LIBS])

 AC_ARG_WITH([cracklib],
    [AS_HELP_STRING([--with-cracklib@<:@=DIR@:>@],
        [Use system CrackLib instead of embedded copy])],
    [AS_IF([test x"$withval" != xno], [rra_system_cracklib=yes])
     AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_cracklib_root="$withval"])])
 AC_ARG_WITH([cracklib-include],
    [AS_HELP_STRING([--with-cracklib-include=DIR],
        [Location of CrackLib headers])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_cracklib_includedir="$withval"])])
 AC_ARG_WITH([cracklib-lib],
    [AS_HELP_STRING([--with-cracklib-lib=DIR],
        [Location of cracklib libraries])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_cracklib_libdir="$withval"])])

 AM_CONDITIONAL([EMBEDDED_CRACKLIB], [test x"$rra_system_cracklib" != xyes])
 AS_IF([test x"$rra_system_cracklib" = xyes],
     [_RRA_LIB_CRACKLIB_PATHS
      CRACKLIB_LIBS="-lcrack"
      _RRA_LIB_CRACKLIB_CHECK])])
