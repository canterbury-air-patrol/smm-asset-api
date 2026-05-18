TESTS = check_smm
check_PROGRAMS = check_smm
check_smm_SOURCES = check_smm.c $(top_builddir)/src/smm-asset.h
check_smm_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/src
check_smm_LDADD = $(top_builddir)/src/libsmmasset.la @CHECK_LIBS@

if INTEGRATION_TESTS
TESTS += integration_test
check_PROGRAMS += integration_test
integration_test_SOURCES = integration_test.c $(top_builddir)/src/smm-asset.h
integration_test_CFLAGS = -I$(top_srcdir)/src
integration_test_LDADD = $(top_builddir)/src/libsmmasset.la
endif

EXTRA_DIST = docker-compose.yml provision.sh
