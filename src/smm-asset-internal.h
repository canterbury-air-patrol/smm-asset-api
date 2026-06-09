#pragma once

/**
 * smm-asset-internal.h, Internal structures and headers for libsmm-asset
 *
 * Copyright 2019 Canterbury Air Patrol Incorporated
 *
 * This file is part of libsmm-asset
 *
 * libsmm-asset is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "smm-asset.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>

#include <curl/curl.h>

enum http_return_codes
{
    HTTP_SUCCESS = 200,
    HTTP_MOVED_PERMANENTLY = 301,
    HTTP_FOUND = 302,
    HTTP_SEE_OTHER = 303,
};

#define SMM_CURL_CONNECT_TIMEOUT_SECS 30L
#define SMM_CURL_TRANSFER_TIMEOUT_SECS 60L

/* Upper bound on a buffered response body. The endpoints this library talks
 * to return small JSON/GeoJSON documents and a login HTML page, so this is a
 * generous ceiling that protects against a hostile or broken server driving
 * unbounded memory growth (and guards the buffer arithmetic against overflow).
 */
#define SMM_MAX_RESPONSE_BYTES ((size_t)8 * 1024 * 1024)

extern _Atomic bool smm_debug;
#define DEBUG(...)                                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        if (smm_debug)                                                                                                 \
        {                                                                                                              \
            printf ("%s:%i ", __func__, __LINE__);                                                                     \
            printf (__VA_ARGS__);                                                                                      \
        }                                                                                                              \
    } while (0)

struct smm_connection_s
{
    char *host;
    char *user;
    char *pass;
    smm_connection_status state;
    CURLSH *share;
    char *csrfmiddlewaretoken;
    pthread_mutex_t lock;
    bool verify_tls;
    int refcount;
    bool login_in_progress;
    pthread_cond_t login_cond;
    smm_error last_error;
};

struct smm_asset_s
{
    smm_connection conn;
    char *name;
    char *type;
    long long asset_id;
    long long asset_type_id;
    smm_asset_command last_command;
    double last_command_lat;
    double last_command_lon;
    pthread_mutex_t lock;
    smm_error last_error; /* guarded by lock */
};

struct smm_search_s
{
    smm_connection conn; /* owns a reference; acquired in smm_search_create */
    long long asset_id;  /* cached from the creating asset */
    char *url;
    uint64_t distance;
    uint64_t length;
    uint64_t sweep_width;
    smm_error last_error; /* not guarded; searches are single-threaded */
};

struct smm_curl_res_s
{
    bool success;
    long httpcode;
    char *full_uri;
    char *redirect_url;
    char *content_type;
};

struct buffer_s
{
    char *data;
    size_t bytes;
};

size_t to_buffer (char *ptr, size_t size, size_t nmemb, void *userdata);

bool smm_connection_share_init (smm_connection conn);
void smm_connection_share_destroy (smm_connection conn);

void smm_connection_ref (smm_connection conn);
void smm_connection_unref (smm_connection conn);
void smm_connection_set_error (smm_connection conn, smm_error_code code, const char *fmt, ...)
    __attribute__ ((format (printf, 3, 4)));
void smm_connection_clear_error (smm_connection conn);

void smm_curl_res_free (struct smm_curl_res_s *);
/* Raw single-shot fetch: no retry, no login redirect, no HTTPS upgrade.
 * Use this inside login itself to avoid re-entrant login attempts. */
struct smm_curl_res_s *smm_connection_curl_retrieve_url_r (smm_connection conn, const char *path, const char *post_data,
                                                           size_t (*write_func) (char *ptr, size_t size, size_t nmemb,
                                                                                 void *userdata),
                                                           void *write_data, bool json);
struct smm_curl_res_s *smm_connection_curl_retrieve_url (smm_connection conn, const char *path, const char *post_data,
                                                         size_t (*write_func) (char *ptr, size_t size, size_t nmemb,
                                                                               void *userdata),
                                                         void *write_data, bool json);
bool smm_asset_connection_login (smm_connection connection);
char *smm_parse_csrf_token (const char *data, size_t len);
bool smm_parse_assets (smm_connection connection, const char *data, size_t len, smm_assets *assets,
                       size_t *assets_count);
bool smm_parse_command (const char *data, size_t len, smm_asset_command *command, double *lat, double *lon);
bool smm_parse_waypoints (const char *data, size_t len, smm_waypoints *waypoints, size_t *waypoints_count);

smm_asset smm_asset_create (smm_connection connection, const char *name, const char *type, long long asset_id,
                            long long asset_type_id);
void smm_asset_free_asset (smm_asset assets);

char *smm_asset_build_position_url (long long asset_id, double lat, double lon, unsigned int alt, uint16_t heading,
                                    uint8_t fix);

void smm_asset_set_command_from_plaintext (smm_asset asset, const char *data, size_t len);

smm_search smm_parse_search_json (smm_asset asset, const char *data, size_t len);

/* Returns true for the HTTP status codes we treat as followable redirects
 * (301, 302, 303). */
bool smm_httpcode_is_redirect (long httpcode);

/* Returns true if https_redirect is an HTTPS upgrade of http_host to the
 * same host:port — used to guard against redirect-based downgrade attacks. */
bool smm_https_upgrade_is_same_host (const char *http_host, const char *https_redirect);

/* Returns true if url is a safe relative path: starts with '/', contains
 * no '..' segments, no query ('?'), no fragment ('#'), and no percent-
 * encoded characters ('%'). */
bool smm_url_path_is_safe (const char *url);

/* Returns true if content_type is the application/json media type, ignoring
 * ASCII case, leading whitespace, and any parameters (e.g. "; charset=utf-8").
 * A NULL content_type returns false. */
bool smm_content_type_is_json (const char *content_type);
