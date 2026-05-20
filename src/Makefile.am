AM_CFLAGS = $(WERROR_CFLAGS) -Wall -Wformat=2 -Wvla -Wextra -Wwrite-strings -Wmissing-prototypes -Wunreachable-code -pedantic -std=c99 -D_DEFAULT_SOURCE -D_GNU_SOURCE
AM_CFLAGS += $(TIDY_CFLAGS) $(CURL_CFLAGS) $(JANSSON_CFLAGS)

lib_LTLIBRARIES = libsmmasset.la

libsmmasset_la_SOURCES = smm-asset.c smm-asset-curl.c smm-asset-internal.h
libsmmasset_la_LIBADD = $(TIDY_LIBS) $(CURL_LIBS) $(JANSSON_LIBS)

include_HEADERS = smm-asset.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = smm-asset.pc
