# Automake makefile for krb5-strength.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2016 Russ Allbery <eagle@eyrie.org>
# Copyright 2007, 2009, 2010, 2012, 2013, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = .gitignore .travis.yml README.md LICENSE bootstrap		    \
	cracklib/HISTORY cracklib/LICENCE cracklib/README		    \
	cracklib/genrules.pl cracklib/mkdict docs/krb5-strength.5.in	    \
	docs/krb5-strength.pod docs/metadata tests/README tests/TESTS	    \
	tests/data/krb5.conf tests/data/make-krb5-conf tests/data/passwords \
	tests/data/perl.conf tests/data/perlcriticrc tests/data/perltidyrc  \
	tests/data/valgrind.supp tests/data/wordlist			    \
	tests/data/wordlist.cdb tests/data/wordlist.sqlite		    \
	tests/docs/pod-spelling-t tests/docs/pod-t tests/docs/urls-t	    \
	tests/perl/critic-t tests/perl/minimum-version-t		    \
	tests/perl/strict-t tests/tap/libtap.sh tests/tap/perl/Test/RRA.pm  \
	tests/tap/perl/Test/RRA/Config.pm				    \
	tests/tap/perl/Test/RRA/Automake.pm tests/tools/heimdal-history-t   \
	tests/tools/heimdal-strength-t tests/tools/wordlist-cdb-t	    \
	tests/tools/wordlist-sqlite-t tests/tools/wordlist-t		    \
	tests/util/xmalloc-t tools/heimdal-strength.pod

# Do this globally.  Everything needs to find the Kerberos headers and
# libraries, and if we're using the system CrackLib, TinyCDB, or SQLite, add
# its location unconditionally as well.
AM_CPPFLAGS = $(CRACKLIB_CPPFLAGS) $(KRB5_CPPFLAGS) $(CDB_CPPFLAGS) \
	$(SQLITE_CPPFLAGS)
AM_LDFLAGS = $(CRACKLIB_LDFLAGS) $(KRB5_LDFLAGS) $(CDB_LDFLAGS) \
	$(SQLITE_LDFLAGS)

# Build our portability library.
noinst_LTLIBRARIES = portable/libportable.la
portable_libportable_la_SOURCES = portable/dummy.c portable/kadmin.h	\
        portable/krb5.h portable/macros.h portable/stdbool.h		\
        portable/system.h
portable_libportable_la_LIBADD = $(LTLIBOBJS)

# Build our command-line utility library.
noinst_LIBRARIES = util/libutil.a
util_libutil_a_SOURCES = util/macros.h util/messages-krb5.c		    \
	util/messages-krb5.h util/messages.c util/messages.h util/xmalloc.c \
	util/xmalloc.h

# If we're building with the embedded cracklib, build cracklib as a helper
# library and build (but don't install) the packer program.
cracklib_libcracklib_la_SOURCES = cracklib/fascist.c cracklib/packlib.c \
	cracklib/rules.c cracklib/stringlib.c
cracklib_libcracklib_la_CPPFLAGS = -DIN_CRACKLIB
cracklib_packer_SOURCES = cracklib/packer.c cracklib/packer.h
cracklib_packer_LDADD = cracklib/libcracklib.la
if EMBEDDED_CRACKLIB
    noinst_LTLIBRARIES += cracklib/libcracklib.la
endif

# Put the plugin into $(libdir)/krb5/plugins/pwqual by default,
moduledir = $(libdir)/krb5/plugins/pwqual

# Rules for building the password strength plugin.
module_LTLIBRARIES = plugin/strength.la
plugin_strength_la_SOURCES = plugin/cdb.c plugin/classes.c plugin/config.c \
	plugin/cracklib.c plugin/error.c plugin/general.c plugin/heimdal.c \
	plugin/internal.h plugin/mit.c plugin/principal.c plugin/sqlite.c  \
	plugin/vector.c
plugin_strength_la_LDFLAGS = -module -avoid-version
if EMBEDDED_CRACKLIB
    plugin_strength_la_LIBADD = cracklib/libcracklib.la
else
    plugin_strength_la_LIBADD = $(CRACKLIB_LIBS)
endif
plugin_strength_la_LIBADD += portable/libportable.la $(KRB5_LIBS) \
	$(CDB_LIBS) $(SQLITE_LIBS)

# The Heimdal external check program.
bin_PROGRAMS = tools/heimdal-strength
tools_heimdal_strength_CFLAGS = $(AM_CFLAGS)
tools_heimdal_strength_SOURCES = plugin/cdb.c plugin/classes.c		  \
	plugin/config.c plugin/cracklib.c plugin/error.c plugin/general.c \
	plugin/internal.h plugin/principal.c plugin/sqlite.c		  \
	plugin/vector.c tools/heimdal-strength.c
if EMBEDDED_CRACKLIB
    tools_heimdal_strength_LDADD = cracklib/libcracklib.la
else
    tools_heimdal_strength_LDADD = $(CRACKLIB_LIBS)
endif
tools_heimdal_strength_LDADD += util/libutil.a portable/libportable.la \
	$(KRB5_LIBS) $(CDB_LIBS) $(SQLITE_LIBS)

# Other tools.
dist_bin_SCRIPTS = tools/heimdal-history tools/krb5-strength-wordlist

# Man pages for all tools.
dist_man_MANS = tools/heimdal-history.1 tools/heimdal-strength.1 \
	tools/krb5-strength-wordlist.1
man_MANS = docs/krb5-strength.5

# Substitute the installation paths into the manual page.
docs/krb5-strength.5: $(srcdir)/docs/krb5-strength.5.in
	[ -d docs ] || mkdir docs
	sed -e 's%\(\\f(CI\)*\@moduledir\(\\fI\)*\@%$(moduledir)%' \
	    < $(srcdir)/docs/krb5-strength.5.in > $@

# Handle the standard stuff that make maintainer-clean should probably remove
# but doesn't.  This breaks the GNU coding standard, but in this area the GNU
# coding standard is dumb.
CLEANFILES = docs/krb5-strength.5 tests/data/dictionary.hwm \
	tests/data/dictionary.pwd tests/data/dictionary.pwi
DISTCLEANFILES = tests/data/.placeholder
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 build-aux/compile		\
	build-aux/config.guess build-aux/config.sub build-aux/depcomp	\
	build-aux/install-sh build-aux/ltmain.sh build-aux/missing	\
	config.h.in config.h.in~ configure docs/krb5-strength.5.in	\
	m4/libtool.m4 m4/ltoptions.m4 m4/ltsugar.m4 m4/ltversion.m4	\
	m4/lt~obsolete.m4 tests/data/wordlist.cdb			\
	tests/data/wordlist.sqlite tools/heimdal-history.1		\
	tools/heimdal-strength.1 tools/krb5-strength-wordlist.1

# Also remove the generated *.c files from our JSON test data on
# maintainer-clean.
maintainer-clean-local:
	rm -f tests/data/passwords/*.c

warnings:
	$(MAKE) V=0 CFLAGS='$(WARNINGS_CFLAGS) $(AM_CFLAGS)' \
	    KRB5_CPPFLAGS='$(KRB5_CPPFLAGS_GCC)'
	$(MAKE) V=0 CFLAGS='$(WARNINGS_CFLAGS) $(AM_CFLAGS)' \
	    KRB5_CPPFLAGS='$(KRB5_CPPFLAGS_GCC)' $(check_PROGRAMS)

# The bits below are for the test suite, not for the main package.
check_PROGRAMS = tests/runtests tests/plugin/heimdal-t tests/plugin/mit-t \
	tests/portable/asprintf-t tests/portable/mkstemp-t		  \
	tests/portable/reallocarray-t tests/portable/snprintf-t		  \
	tests/portable/strndup-t tests/util/messages-krb5-t		  \
	tests/util/messages-t tests/util/xmalloc
if EMBEDDED_CRACKLIB
    check_PROGRAMS += cracklib/packer
endif
tests_runtests_CPPFLAGS = -DC_TAP_SOURCE='"$(abs_top_srcdir)/tests"' \
	-DC_TAP_BUILD='"$(abs_top_builddir)/tests"'
check_LIBRARIES = tests/tap/libtap.a
tests_tap_libtap_a_CPPFLAGS = -I$(abs_top_srcdir)/tests $(KRB5_CPPFLAGS)
tests_tap_libtap_a_SOURCES = tests/tap/basic.c tests/tap/basic.h	\
	tests/tap/kerberos.c tests/tap/kerberos.h tests/tap/macros.h	\
	tests/tap/process.c tests/tap/process.h tests/tap/string.c	\
	tests/tap/string.h

# The actual test programs.
tests_plugin_heimdal_t_CPPFLAGS = $(KRB5_CPPFLAGS)
tests_plugin_heimdal_t_LDADD = tests/tap/libtap.a portable/libportable.la \
	$(KRB5_LIBS) $(CDB_LIBS) $(DL_LIBS)
tests_plugin_mit_t_CPPFLAGS = $(KRB5_CPPFLAGS)
tests_plugin_mit_t_LDADD = tests/tap/libtap.a portable/libportable.la \
	$(KRB5_LIBS) $(CDB_LIBS) $(DL_LIBS)
tests_portable_asprintf_t_SOURCES = tests/portable/asprintf-t.c \
	tests/portable/asprintf.c
tests_portable_asprintf_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_mkstemp_t_SOURCES = tests/portable/mkstemp-t.c \
	tests/portable/mkstemp.c
tests_portable_mkstemp_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_reallocarray_t_SOURCES = tests/portable/reallocarray-t.c \
	tests/portable/reallocarray.c
tests_portable_reallocarray_t_LDADD = tests/tap/libtap.a \
	portable/libportable.la
tests_portable_snprintf_t_SOURCES = tests/portable/snprintf-t.c \
	tests/portable/snprintf.c
tests_portable_snprintf_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_strndup_t_SOURCES = tests/portable/strndup-t.c \
	tests/portable/strndup.c
tests_portable_strndup_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_util_messages_t_LDADD = tests/tap/libtap.a util/libutil.a \
	portable/libportable.la
tests_util_messages_krb5_t_LDADD = tests/tap/libtap.a util/libutil.a \
	portable/libportable.la $(KRB5_LIBS)
tests_util_xmalloc_LDADD = util/libutil.a portable/libportable.la

# The dictionary is used by the tests and needs to be built first.
if EMBEDDED_CRACKLIB
tests/data/dictionary.pwd: cracklib/packer $(srcdir)/cracklib/mkdict \
		$(srcdir)/tests/data/wordlist
	mkdir -p tests/data
	$(srcdir)/cracklib/mkdict $(srcdir)/tests/data/wordlist \
	    | cracklib/packer tests/data/dictionary
else
tests/data/dictionary.pwd: $(srcdir)/tests/data/wordlist
	mkdir -p tests/data
	cracklib-format $(srcdir)/tests/data/wordlist \
	    | cracklib-packer tests/data/dictionary
endif

check-local: $(check_PROGRAMS) tests/data/dictionary.pwd
	cd tests && ./runtests -l $(abs_top_srcdir)/tests/TESTS

# Used by maintainers to run the main test suite under valgrind.  Suppress
# the xmalloc and pod-spelling tests because the former won't work properly
# under valgrind (due to increased memory usage) and the latter is pointless
# to run under valgrind.  Don't try to trace several of the tests that are
# written in Perl or shell and test Perl programs.
check-valgrind: $(check_PROGRAMS) tests/data/dictionary.pwd
	rm -rf $(abs_top_builddir)/tmp-valgrind
	mkdir $(abs_top_builddir)/tmp-valgrind
	env RRA_MAINTAINER_TESTS= valgrind --leak-check=full		\
	    --show-reachable=yes --trace-children=yes			\
	    --log-file=$(abs_top_builddir)/tmp-valgrind/log.%p		\
	    --suppressions=$(abs_top_srcdir)/tests/data/valgrind.supp	\
	    --trace-children-skip="/bin/sh,*/cat,*/diff,*/expr,*/grep,*/mkdir,*/rm,*/rmdir,*/sed,*/sleep,*/true,*/wc,*/docs/*-t,*/perl/*-t,*/data/make-krb5-conf,*/tools/heimdal-history-t,*/tools/wordlist*-t" \
	    tests/runtests -l '$(abs_top_srcdir)/tests/TESTS'
