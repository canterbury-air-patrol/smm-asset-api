AM_CFLAGS = $(WERROR_CFLAGS) -Wall -Wformat=2 -Wvla -Wextra -Wwrite-strings -Wmissing-prototypes -Wunreachable-code -pedantic -std=c11 -D_DEFAULT_SOURCE -D_GNU_SOURCE
AM_CFLAGS += $(TIDY_CFLAGS) $(CURL_CFLAGS) $(JANSSON_CFLAGS)

# Convenience library carrying the full symbol set. It is not installed; the
# test suite links against it so it can exercise internal helpers that are not
# part of the public API.
noinst_LTLIBRARIES = libsmmasset-internal.la
libsmmasset_internal_la_SOURCES = smm-asset.c smm-asset-curl.c smm-asset-internal.h
libsmmasset_internal_la_LIBADD = $(TIDY_LIBS) $(CURL_LIBS) $(JANSSON_LIBS)

# Installed shared library. Only the documented public API is exported
# (-export-symbols libsmmasset.sym), and the ABI is versioned with
# -version-info current:revision:age. Bump on every release:
#   - interfaces unchanged:           c:r:a   -> c:r+1:a
#   - interfaces added (compatible):  c:r:a   -> c+1:0:a+1
#   - interfaces changed/removed:     c:r:a   -> c+1:0:0
lib_LTLIBRARIES = libsmmasset.la
libsmmasset_la_SOURCES =
libsmmasset_la_LIBADD = libsmmasset-internal.la $(TIDY_LIBS) $(CURL_LIBS) $(JANSSON_LIBS)
libsmmasset_la_LDFLAGS = -no-undefined -version-info 0:0:0 -export-symbols $(srcdir)/libsmmasset.sym

EXTRA_DIST = libsmmasset.sym

include_HEADERS = smm-asset.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = smm-asset.pc
