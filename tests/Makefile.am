TESTS = check_smm
check_PROGRAMS = check_smm
check_smm_SOURCES = check_smm.c $(top_builddir)/src/smm-asset.h
check_smm_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/src
check_smm_LDADD = $(top_builddir)/src/libsmmasset.la @CHECK_LIBS@
