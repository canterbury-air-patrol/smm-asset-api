AC_INIT([libsmm-asset], [1.0.0])
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

AC_CONFIG_FILES([Makefile
	src/Makefile
	tests/Makefile
	src/smm-asset.pc])
AC_OUTPUT
