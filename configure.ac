dnl Derive the package version from the single source of truth in the public
dnl header, so configure.ac and src/smm-asset.h can never disagree.
m4_define([smm_ver_major],
  m4_esyscmd_s([sed -n 's/^#define SMM_VERSION_MAJOR \([0-9][0-9]*\).*/\1/p' src/smm-asset.h]))
m4_define([smm_ver_minor],
  m4_esyscmd_s([sed -n 's/^#define SMM_VERSION_MINOR \([0-9][0-9]*\).*/\1/p' src/smm-asset.h]))
m4_define([smm_ver_patch],
  m4_esyscmd_s([sed -n 's/^#define SMM_VERSION_PATCH \([0-9][0-9]*\).*/\1/p' src/smm-asset.h]))
AC_INIT([libsmm-asset], [smm_ver_major.smm_ver_minor.smm_ver_patch])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

AC_PROG_CC
AM_PROG_AR

LT_INIT([disable-static pic-only])

AC_ARG_ENABLE([werror],
  AS_HELP_STRING([--enable-werror], [treat warnings as errors]),
  [werror=$enableval], [werror=no])
AS_IF([test "x$werror" = "xyes"], [WERROR_CFLAGS="-Werror"])
AC_SUBST([WERROR_CFLAGS])

PKG_CHECK_MODULES([TIDY],[tidy])
PKG_CHECK_MODULES([CURL],[libcurl])
PKG_CHECK_MODULES([JANSSON],[jansson])
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4])

AC_ARG_ENABLE([integration-tests],
  [AS_HELP_STRING([--enable-integration-tests],
    [build and run integration tests (requires a live SMM server)])],
  [enable_integration_tests=$enableval],
  [enable_integration_tests=no])
AM_CONDITIONAL([INTEGRATION_TESTS], [test "x$enable_integration_tests" = "xyes"])

AC_CHECK_HEADERS([tidy.h],[],[
AC_CHECK_HEADERS([tidy/tidy.h])])

# explicit_bzero (glibc/BSD) scrubs secrets without the compiler optimising the
# store away. Where it is unavailable, smm_secure_clear falls back to a
# volatile write loop.
AC_CHECK_FUNCS([explicit_bzero])

AC_CONFIG_FILES([Makefile
	src/Makefile
	tests/Makefile
	src/smm-asset.pc])
AC_OUTPUT
