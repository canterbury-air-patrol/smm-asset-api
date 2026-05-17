TESTS = check_smm
check_PROGRAMS = check_smm integration_test
check_smm_SOURCES = check_smm.c $(top_builddir)/src/smm-asset.h
check_smm_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/src
check_smm_LDADD = $(top_builddir)/src/libsmmasset.la @CHECK_LIBS@

integration_test_SOURCES = integration_test.c $(top_builddir)/src/smm-asset.h
integration_test_CFLAGS = -I$(top_srcdir)/src
integration_test_LDADD = $(top_builddir)/src/libsmmasset.la

EXTRA_DIST = docker-compose.yml provision.sh
