/**
 * smm-asset.c, API functions for communicating with Search Management Map
 * to act as an Asset.
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
#include "smm-asset-internal.h"

#include <inttypes.h>
#include <locale.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

_Atomic bool smm_debug = false;

/*
 * SMM expects coordinates in URLs formatted with '.' as the decimal separator.
 * printf-family conversions honour the thread's LC_NUMERIC, so a caller running
 * under a locale such as de_DE would otherwise emit "lat=-43,5" and corrupt the
 * request. We keep a private "C" locale and switch to it (per-thread, via
 * uselocale) only while formatting numbers.
 */
static locale_t smm_c_locale = (locale_t)0;
static pthread_once_t smm_c_locale_once = PTHREAD_ONCE_INIT;

static void
smm_c_locale_init (void)
{
    smm_c_locale = newlocale (LC_NUMERIC_MASK, "C", (locale_t)0);
}

static locale_t
smm_c_locale_get (void)
{
    pthread_once (&smm_c_locale_once, smm_c_locale_init);
    return smm_c_locale;
}

/* asprintf() that formats in the private "C" locale (see above), so coordinate
 * conversions use '.' as the decimal separator regardless of the caller's
 * LC_NUMERIC. Returns the asprintf() result; *strp is undefined on failure.
 *
 * If the private "C" locale is unavailable or cannot be installed, the
 * function fails (returns < 0) rather than formatting in the caller's locale:
 * emitting a corrupted coordinate such as "lat=-43,5" would be worse than
 * failing the request outright. */
static int smm_asprintf_c_locale (char **strp, const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));

static int
smm_asprintf_c_locale (char **strp, const char *fmt, ...)
{
    locale_t c_locale = smm_c_locale_get ();
    if (c_locale == (locale_t)0)
    {
        return -1;
    }

    /* POSIX: uselocale() returns the previous locale on success, or
     * (locale_t)0 on error. The previous locale is never (locale_t)0 — on a
     * thread that has not set a per-thread locale it is LC_GLOBAL_LOCALE
     * ((locale_t)-1), which is a *success* value we must restore below. So the
     * error test is == 0; do NOT change it to == -1 (that would treat the
     * common fresh-thread case as a failure and leave the thread in the C
     * locale). */
    locale_t old_locale = uselocale (c_locale);
    if (old_locale == (locale_t)0)
    {
        return -1;
    }

    va_list ap;
    va_start (ap, fmt);
    int n = vasprintf (strp, fmt, ap);
    va_end (ap);

    uselocale (old_locale);
    return n;
}

const char *
smm_asset_version_string (void)
{
    return SMM_VERSION_STRING;
}

uint32_t
smm_asset_version_number (void)
{
    return SMM_VERSION_NUMBER;
}

void
smm_asset_debugging_set (bool debug)
{
    smm_debug = debug;
}

smm_connection
smm_asset_connect (const char *host, const char *user, const char *pass)
{
    if (host == NULL || user == NULL || pass == NULL)
    {
        return NULL;
    }

    smm_connection conn = calloc (1, sizeof (struct smm_connection_s));
    if (conn == NULL)
    {
        return NULL;
    }

    conn->host = strdup (host);
    conn->user = strdup (user);
    conn->pass = strdup (pass);
    conn->verify_tls = true;
    conn->refcount = 1;
    conn->last_error.code = SMM_ERROR_NONE;
    conn->last_error.message[0] = '\0';

    if (!conn->host || !conn->user || !conn->pass)
    {
        free (conn->host);
        free (conn->user);
        free (conn->pass);
        free (conn);
        return NULL;
    }

    /* Normalise away trailing '/'s: request paths always start with '/', so a
     * host of "http://example.com/" would otherwise produce double-slash URLs
     * such as "http://example.com//assets/", which only work behind proxies
     * that merge slashes. Also makes a base path like
     * "https://example.com/smm/" concatenate correctly. */
    size_t host_len = strlen (conn->host);
    while (host_len > 0 && conn->host[host_len - 1] == '/')
    {
        conn->host[--host_len] = '\0';
    }

    pthread_mutex_init (&conn->lock, NULL);
    conn->login_in_progress = false;
    pthread_cond_init (&conn->login_cond, NULL);

    /* libcurl's global state must be initialised before any other libcurl call
     * (curl_share_init and curl_url below, and every request on this
     * connection). Do it here, the single chokepoint through which every
     * libcurl-using path is reached. */
    if (!smm_curl_global_init ())
    {
        conn->state = SMM_CONNECTION_FAILURE;
        return conn;
    }

    if (!smm_connection_share_init (conn))
    {
        smm_connection_unref (conn);
        return NULL;
    }

    /* Early host validation, on the normalised host actually used in URLs */
    CURLU *curlu = curl_url ();
    if (curlu)
    {
        if (curl_url_set (curlu, CURLUPART_URL, conn->host, 0) != CURLUE_OK)
        {
            conn->state = SMM_CONNECTION_HOST_INVALID;
        }
        else
        {
            /* Parse succeeded, but libcurl accepts schemes this library cannot
             * use as an SMM host (ftp, file, ...). Accept only http(s) with a
             * non-empty host; login still happens lazily on the first request.
             * libcurl lowercases the scheme, so a plain strcmp is sufficient. */
            char *scheme = NULL;
            char *chost = NULL;
            bool http_ok = curl_url_get (curlu, CURLUPART_SCHEME, &scheme, 0) == CURLUE_OK && scheme
                           && (strcmp (scheme, "http") == 0 || strcmp (scheme, "https") == 0)
                           && curl_url_get (curlu, CURLUPART_HOST, &chost, 0) == CURLUE_OK && chost && chost[0] != '\0';
            conn->state = http_ok ? SMM_CONNECTION_NEW : SMM_CONNECTION_HOST_INVALID;
            curl_free (scheme);
            curl_free (chost);
        }
        curl_url_cleanup (curlu);
    }
    else
    {
        conn->state = SMM_CONNECTION_FAILURE;
    }

    return conn;
}

smm_connection_status
smm_asset_connection_get_state (smm_connection connection)
{
    if (connection == NULL)
    {
        return SMM_CONNECTION_UNKNOWN;
    }
    pthread_mutex_lock (&connection->lock);
    smm_connection_status state = connection->state;
    pthread_mutex_unlock (&connection->lock);
    return state;
}

void
smm_asset_connection_tls_verify_set (smm_connection connection, bool verify)
{
    if (connection != NULL)
    {
        pthread_mutex_lock (&connection->lock);
        connection->verify_tls = verify;
        pthread_mutex_unlock (&connection->lock);
    }
}

void
smm_asset_connection_timeouts_set (smm_connection connection, long connect_secs, long transfer_secs)
{
    if (connection != NULL)
    {
        pthread_mutex_lock (&connection->lock);
        connection->connect_timeout_secs = connect_secs;
        connection->transfer_timeout_secs = transfer_secs;
        pthread_mutex_unlock (&connection->lock);
    }
}

static void
smm_asset_set_error (smm_asset asset, smm_error_code code, const char *fmt, ...)
{
    if (asset == NULL)
        return;
    pthread_mutex_lock (&asset->lock);
    asset->last_error.code = code;
    va_list ap;
    va_start (ap, fmt);
    vsnprintf (asset->last_error.message, sizeof (asset->last_error.message), fmt, ap);
    va_end (ap);
    pthread_mutex_unlock (&asset->lock);
}

static void
smm_asset_clear_error (smm_asset asset)
{
    if (asset == NULL)
        return;
    pthread_mutex_lock (&asset->lock);
    asset->last_error.code = SMM_ERROR_NONE;
    asset->last_error.message[0] = '\0';
    pthread_mutex_unlock (&asset->lock);
}

smm_error_code
smm_asset_get_last_error (smm_asset asset, char *message, size_t message_len)
{
    if (message != NULL && message_len > 0)
    {
        message[0] = '\0';
    }
    if (asset == NULL)
    {
        return SMM_ERROR_NONE;
    }
    pthread_mutex_lock (&asset->lock);
    smm_error_code code = asset->last_error.code;
    if (message != NULL && message_len > 0)
    {
        snprintf (message, message_len, "%s", asset->last_error.message);
    }
    pthread_mutex_unlock (&asset->lock);
    return code;
}

static void
smm_search_set_error (smm_search search, smm_error_code code, const char *fmt, ...)
{
    if (search == NULL)
        return;
    search->last_error.code = code;
    va_list ap;
    va_start (ap, fmt);
    vsnprintf (search->last_error.message, sizeof (search->last_error.message), fmt, ap);
    va_end (ap);
}

static void
smm_search_clear_error (smm_search search)
{
    if (search == NULL)
        return;
    search->last_error.code = SMM_ERROR_NONE;
    search->last_error.message[0] = '\0';
}

smm_error_code
smm_search_get_last_error (smm_search search, char *message, size_t message_len)
{
    if (message != NULL && message_len > 0)
    {
        message[0] = '\0';
    }
    if (search == NULL)
    {
        return SMM_ERROR_NONE;
    }
    if (message != NULL && message_len > 0)
    {
        snprintf (message, message_len, "%s", search->last_error.message);
    }
    return search->last_error.code;
}

void
smm_connection_set_error (smm_connection conn, smm_error_code code, const char *fmt, ...)
{
    if (conn == NULL)
    {
        return;
    }
    pthread_mutex_lock (&conn->lock);
    conn->last_error.code = code;
    va_list ap;
    va_start (ap, fmt);
    vsnprintf (conn->last_error.message, sizeof (conn->last_error.message), fmt, ap);
    va_end (ap);
    pthread_mutex_unlock (&conn->lock);
}

void
smm_connection_clear_error (smm_connection conn)
{
    if (conn == NULL)
    {
        return;
    }
    pthread_mutex_lock (&conn->lock);
    conn->last_error.code = SMM_ERROR_NONE;
    conn->last_error.message[0] = '\0';
    pthread_mutex_unlock (&conn->lock);
}

smm_error_code
smm_connection_get_last_error (smm_connection connection, char *message, size_t message_len)
{
    if (message != NULL && message_len > 0)
    {
        message[0] = '\0';
    }
    if (connection == NULL)
    {
        return SMM_ERROR_NONE;
    }
    pthread_mutex_lock (&connection->lock);
    smm_error_code code = connection->last_error.code;
    if (message != NULL && message_len > 0)
    {
        snprintf (message, message_len, "%s", connection->last_error.message);
    }
    pthread_mutex_unlock (&connection->lock);
    return code;
}

void
smm_connection_ref (smm_connection connection)
{
    if (connection == NULL)
    {
        return;
    }
    pthread_mutex_lock (&connection->lock);
    connection->refcount++;
    pthread_mutex_unlock (&connection->lock);
}

void
smm_connection_unref (smm_connection connection)
{
    if (connection == NULL)
    {
        return;
    }

    pthread_mutex_lock (&connection->lock);
    connection->refcount--;
    if (connection->refcount == 0)
    {
        pthread_mutex_unlock (&connection->lock);
        free (connection->host);
        free (connection->user);
        free (connection->pass);
        free (connection->csrfmiddlewaretoken);
        smm_connection_share_destroy (connection);
        pthread_cond_destroy (&connection->login_cond);
        pthread_mutex_destroy (&connection->lock);
        free (connection);
    }
    else
    {
        pthread_mutex_unlock (&connection->lock);
    }
}

void
smm_connection_close (smm_connection connection)
{
    smm_connection_unref (connection);
}

smm_asset
smm_asset_create (smm_connection conn, const char *name, const char *type, long long asset_id, long long asset_type_id)
{
    smm_asset asset = calloc (1, sizeof (struct smm_asset_s));
    if (asset == NULL)
    {
        return NULL;
    }

    /* Duplicate the strings and initialise the mutex before taking the
     * connection reference, so any failure here frees only the asset: there is
     * no reference or initialised mutex to unwind. The connection reference is
     * taken last, after every fallible step, so no failure path can leak it. */
    asset->name = name ? strdup (name) : NULL;
    asset->type = type ? strdup (type) : NULL;
    if ((name && !asset->name) || (type && !asset->type))
    {
        free (asset->name);
        free (asset->type);
        free (asset);
        return NULL;
    }

    if (pthread_mutex_init (&asset->lock, NULL) != 0)
    {
        free (asset->name);
        free (asset->type);
        free (asset);
        return NULL;
    }

    asset->asset_id = asset_id;
    asset->asset_type_id = asset_type_id;
    asset->conn = conn;
    smm_connection_ref (conn);

    return asset;
}

bool
smm_parse_assets (smm_connection connection, const char *data, size_t len, smm_assets *assets, size_t *assets_count)
{
    json_error_t json_error;
    bool res = false;

    /* Parse the assets */
    *assets_count = 0;
    *assets = NULL;

    json_t *json_root = json_loadb (data, len, 0, &json_error);
    if (json_root)
    {
        json_t *json_assets = json_object_get (json_root, "assets");
        if (json_is_array (json_assets))
        {
            size_t index = 0;
            json_t *value = NULL;

            json_array_foreach (json_assets, index, value)
            {
                const char *key = NULL;
                json_t *val = NULL;
                json_int_t asset_id = -1;
                json_int_t asset_type_id = -1;
                bool have_id = false;
                const char *name = NULL;
                const char *type = NULL;
                json_object_foreach (value, key, val)
                {
                    if (strcmp (key, "id") == 0)
                    {
                        /* Require a positive integer: the id is a server primary
                         * key substituted into request URLs, so 0 and negative
                         * values are rejected (have_id stays false, dropping the
                         * asset) rather than driving requests at nonsensical
                         * paths such as /data/assets/-1/. */
                        if (json_is_integer (val))
                        {
                            json_int_t id_value = json_integer_value (val);
                            if (id_value > 0)
                            {
                                asset_id = id_value;
                                have_id = true;
                            }
                        }
                    }
                    else if (strcmp (key, "type_id") == 0)
                    {
                        /* Validate as a positive integer, consistent with "id",
                         * so a non-integer or non-positive value is left as the
                         * -1 sentinel rather than silently coerced. type_id is
                         * optional, so an absent or malformed one does not drop
                         * the asset. */
                        if (json_is_integer (val))
                        {
                            json_int_t type_id_value = json_integer_value (val);
                            if (type_id_value > 0)
                            {
                                asset_type_id = type_id_value;
                            }
                        }
                    }
                    else if (strcmp (key, "name") == 0)
                    {
                        name = json_string_value (val);
                    }
                    else if (strcmp (key, "type_name") == 0)
                    {
                        type = json_string_value (val);
                    }
                }
                /* The id is required: it is substituted into request URLs
                 * (position reports, search lookups). Drop any asset that
                 * lacks a valid positive integer id rather than issuing
                 * requests against a sentinel id of -1. */
                if (!have_id)
                {
                    DEBUG ("asset entry has no valid integer id; skipping\n");
                    continue;
                }
                smm_asset new_asset = smm_asset_create (connection, name, type, asset_id, asset_type_id);
                if (new_asset)
                {
                    smm_asset *tmp = realloc (*assets, (*assets_count + 1) * sizeof (smm_asset));
                    if (tmp)
                    {
                        *assets = tmp;
                        (*assets)[*assets_count] = new_asset;
                        *assets_count += 1;
                    }
                    else
                    {
                        smm_asset_free_asset (new_asset);
                        smm_asset_free_assets (*assets, *assets_count);
                        *assets = NULL;
                        *assets_count = 0;
                        json_decref (json_root);
                        return false;
                    }
                }
            }
            res = true;
        }
        else
        {
            DEBUG ("Didn't find assets array in JSON\n");
        }
        json_decref (json_root);
    }
    else
    {
        DEBUG ("JSON Parse Error on line %i: %s\n", json_error.line, json_error.text);
    }

    return res;
}

bool
smm_asset_get_assets (smm_connection connection, smm_assets *assets, size_t *assets_count)
{
    struct buffer_s buf = { NULL, 0 };

    if (assets == NULL || assets_count == NULL)
    {
        smm_connection_set_error (connection, SMM_ERROR_INVALID_ARG, "assets and assets_count must be non-NULL");
        return false;
    }

    *assets = NULL;
    *assets_count = 0;
    smm_connection_clear_error (connection);

    struct smm_curl_res_s *res = smm_connection_curl_retrieve_url (connection, "/assets/", NULL, &buf, true);
    if (res == NULL)
    {
        smm_connection_set_error (connection, SMM_ERROR_NETWORK, "network failure fetching /assets/");
        return false;
    }
    if (!(res->success && res->httpcode == HTTP_SUCCESS))
    {
        smm_connection_set_error (connection, SMM_ERROR_SERVER, "unexpected HTTP %ld from /assets/", res->httpcode);
        smm_curl_res_free (res);
        free (buf.data);
        return false;
    }
    smm_curl_res_free (res);

    bool parse_res = smm_parse_assets (connection, buf.data, buf.bytes, assets, assets_count);
    if (!parse_res)
    {
        /* False positive: the analyzer sees smm_parse_assets's realloc-failure
         * cleanup unref an asset's connection and assumes that frees
         * 'connection', but the caller owns a reference for the duration of
         * this call, so it cannot be freed here. */
        /* NOLINTNEXTLINE(clang-analyzer-unix.Malloc) */
        smm_connection_set_error (connection, SMM_ERROR_PARSE, "failed to parse /assets/ response");
    }

    free (buf.data);
    return parse_res;
}

void
smm_asset_free_asset (smm_asset asset)
{
    if (asset)
    {
        smm_connection_unref (asset->conn);
        free (asset->name);
        free (asset->type);
        pthread_mutex_destroy (&asset->lock);
        free (asset);
    }
}

void
smm_asset_free_assets (smm_assets assets, size_t assets_count)
{
    for (size_t i = 0; i < assets_count; i++)
    {
        smm_asset_free_asset (assets[i]);
    }
    free (assets);
}

const char *
smm_asset_name (smm_asset asset)
{
    if (asset)
    {
        return asset->name;
    }
    return NULL;
}

const char *
smm_asset_type (smm_asset asset)
{
    if (asset)
    {
        return asset->type;
    }
    return NULL;
}

bool
smm_parse_command (const char *data, size_t len, smm_asset_command *command, double *lat, double *lon)
{
    json_error_t json_error;
    bool res = false;

    *command = SMM_COMMAND_UNKNOWN;

    json_t *json_root = json_loadb (data, len, 0, &json_error);
    if (json_root)
    {
        json_t *tmp = json_object_get (json_root, "action");
        if (json_is_string (tmp))
        {
            const char *cmd_str = json_string_value (tmp);
            if (cmd_str)
            {
                res = true;
                if (strcmp (cmd_str, "GOTO") == 0)
                {
                    /* A GOTO is only valid with both coordinates present,
                     * numeric, and in range. Accept any JSON number (real or
                     * integer); the server normally emits floats but the
                     * contract does not guarantee it. A malformed GOTO is
                     * rejected (res false, command left UNKNOWN) so a partial
                     * parse can never expose stale coordinates via
                     * smm_asset_last_goto_pos. */
                    json_t *json_lat = json_object_get (json_root, "latitude");
                    json_t *json_lon = json_object_get (json_root, "longitude");
                    if (json_is_number (json_lat) && json_is_number (json_lon))
                    {
                        double lat_value = json_number_value (json_lat);
                        double lon_value = json_number_value (json_lon);
                        if (lat_value >= -90.0 && lat_value <= 90.0 && lon_value >= -180.0 && lon_value <= 180.0)
                        {
                            *lat = lat_value;
                            *lon = lon_value;
                            *command = SMM_COMMAND_GOTO;
                        }
                        else
                        {
                            res = false;
                        }
                    }
                    else
                    {
                        res = false;
                    }
                }
                else if (strcmp (cmd_str, "RON") == 0)
                {
                    *command = SMM_COMMAND_CONTINUE;
                }
                else if (strcmp (cmd_str, "RTL") == 0)
                {
                    *command = SMM_COMMAND_RTL;
                }
                else if (strcmp (cmd_str, "CIR") == 0)
                {
                    *command = SMM_COMMAND_CIRCLE;
                }
                else if (strcmp (cmd_str, "AS") == 0)
                {
                    *command = SMM_COMMAND_ABANDON_SEARCH;
                }
                else if (strcmp (cmd_str, "MC") == 0)
                {
                    *command = SMM_COMMAND_MISSION_COMPLETE;
                }
                else
                {
                    *command = SMM_COMMAND_UNKNOWN;
                }
            }
        }

        json_decref (json_root);
    }
    else
    {
        DEBUG ("JSON Parse Error on line %i: %s\n", json_error.line, json_error.text);
    }

    return res;
}

bool
smm_asset_update_command (smm_asset asset, const struct buffer_s *buf)
{
    /* Parse into locals first, then commit under the lock. Coordinates are
     * only published for a valid GOTO, so a malformed GOTO (command left
     * UNKNOWN by smm_parse_command) cannot leave stale coordinates visible
     * through smm_asset_last_goto_pos. */
    smm_asset_command command = SMM_COMMAND_UNKNOWN;
    double lat = 0.0;
    double lon = 0.0;
    bool res = smm_parse_command (buf->data, buf->bytes, &command, &lat, &lon);

    pthread_mutex_lock (&asset->lock);
    asset->last_command = command;
    if (command == SMM_COMMAND_GOTO)
    {
        asset->last_command_lat = lat;
        asset->last_command_lon = lon;
    }
    pthread_mutex_unlock (&asset->lock);
    return res;
}

smm_asset_command
smm_asset_last_command (smm_asset asset)
{
    if (!asset)
    {
        return SMM_COMMAND_UNKNOWN;
    }
    smm_asset_command cmd;
    pthread_mutex_lock (&asset->lock);
    cmd = asset->last_command;
    pthread_mutex_unlock (&asset->lock);
    return cmd;
}

bool
smm_asset_last_goto_pos (smm_asset asset, double *lat, double *lon)
{
    if (!asset)
    {
        return false;
    }
    bool res = false;
    pthread_mutex_lock (&asset->lock);
    if (asset->last_command == SMM_COMMAND_GOTO)
    {
        if (lat != NULL && lon != NULL)
        {
            *lat = asset->last_command_lat;
            *lon = asset->last_command_lon;
            res = true;
        }
    }
    pthread_mutex_unlock (&asset->lock);
    return res;
}

#define CONTINUE_STR "Continue"
#define CONTINUE_LEN (sizeof (CONTINUE_STR) - 1)

void
smm_asset_set_command_from_plaintext (smm_asset asset, const char *data, size_t len)
{
    if (!asset)
    {
        return;
    }
    pthread_mutex_lock (&asset->lock);
    if (data && len >= CONTINUE_LEN && strncmp (data, CONTINUE_STR, CONTINUE_LEN) == 0)
    {
        asset->last_command = SMM_COMMAND_CONTINUE;
    }
    else
    {
        asset->last_command = SMM_COMMAND_NONE;
    }
    pthread_mutex_unlock (&asset->lock);
}

/* ASCII-only, case-insensitive comparison of the first n bytes. Used for
 * media-type matching so the result does not depend on the caller's locale
 * (e.g. the Turkish dotless-i rule that would break strncasecmp). */
static bool
smm_ascii_caseeq (const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        /* Stop at a terminator on either side. A shorter string mismatches
         * (and the comparison stays in-bounds) without relying on the
         * argument that b never contains an embedded NUL. */
        if (ca == '\0' || cb == '\0')
            return false;
        if (ca >= 'A' && ca <= 'Z')
            ca = (unsigned char)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (unsigned char)(cb + ('a' - 'A'));
        if (ca != cb)
            return false;
    }
    return true;
}

bool
smm_content_type_is_json (const char *content_type)
{
    static const char json[] = "application/json";
    const size_t json_len = sizeof (json) - 1;

    if (content_type == NULL)
        return false;

    /* Skip any leading whitespace before the media type. */
    while (*content_type == ' ' || *content_type == '\t')
        content_type++;

    if (!smm_ascii_caseeq (content_type, json, json_len))
        return false;

    /* The media type must end here: only whitespace or a ';' parameter
     * delimiter may follow (e.g. "application/json; charset=utf-8"). This
     * rejects look-alikes such as "application/json-patch+json". */
    const char *after = content_type + json_len;
    while (*after == ' ' || *after == '\t')
        after++;
    return *after == '\0' || *after == ';';
}

bool
smm_url_path_is_safe (const char *url)
{
    if (url == NULL || url[0] != '/')
        return false;
    if (strstr (url, "..") != NULL)
        return false;
    if (strchr (url, '?') != NULL)
        return false;
    if (strchr (url, '#') != NULL)
        return false;
    if (strchr (url, '%') != NULL)
        return false;
    return true;
}

char *
smm_asset_build_position_url (long long asset_id, double lat, double lon, int32_t alt, uint16_t heading, uint8_t fix)
{
    char *page = NULL;
    if (smm_asprintf_c_locale (&page,
                               "/data/assets/%lld/position/add/?lat=%lf&lon=%lf&alt=%" PRId32 "&heading=%u&fix=%u",
                               asset_id, lat, lon, alt, heading, fix)
        < 0)
    {
        return NULL;
    }
    return page;
}

bool
smm_asset_report_position (smm_asset asset, double latitude, double longitude, int32_t altitude, uint16_t heading,
                           uint8_t fix)
{
    if (!asset)
    {
        return false;
    }
    struct buffer_s buf = { NULL, 0 };

    char *page = smm_asset_build_position_url (asset->asset_id, latitude, longitude, altitude, heading, fix);
    if (page == NULL)
    {
        return false;
    }
    smm_asset_clear_error (asset);

    struct smm_curl_res_s *res = smm_connection_curl_retrieve_url (asset->conn, page, NULL, &buf, false);
    if (res == NULL)
    {
        smm_asset_set_error (asset, SMM_ERROR_NETWORK, "network failure reporting position");
        free (page);
        return false;
    }
    if (!(res->success && res->httpcode == HTTP_SUCCESS))
    {
        smm_asset_set_error (asset, SMM_ERROR_SERVER, "unexpected HTTP %ld from position report", res->httpcode);
        smm_curl_res_free (res);
        free (page);
        free (buf.data);
        return false;
    }

    free (page);

    /* if json data was returned, update the current action */
    if (smm_content_type_is_json (res->content_type))
    {
        smm_asset_update_command (asset, &buf);
    }
    else
    {
        smm_asset_set_command_from_plaintext (asset, buf.data, buf.bytes);
    }

    free (buf.data);

    smm_curl_res_free (res);

    return true;
}

static smm_search
smm_search_create (smm_asset asset, const char *url, uint64_t length, uint64_t distance, uint64_t sweep_width)
{
    smm_search search = calloc (1, sizeof (struct smm_search_s));
    if (search == NULL)
    {
        return NULL;
    }

    if (asset)
    {
        search->conn = asset->conn;
        search->asset_id = asset->asset_id;
        smm_connection_ref (asset->conn);
    }

    search->url = url ? strdup (url) : NULL;
    if (url && !search->url)
    {
        smm_connection_unref (search->conn);
        free (search);
        return NULL;
    }

    search->length = length;
    search->distance = distance;
    search->sweep_width = sweep_width;

    return search;
}

uint64_t
smm_search_distance (smm_search search)
{
    if (search)
    {
        return search->distance;
    }
    return 0;
}

uint64_t
smm_search_length (smm_search search)
{
    if (search)
    {
        return search->length;
    }
    return 0;
}

uint64_t
smm_search_sweep_width (smm_search search)
{
    if (search)
    {
        return search->sweep_width;
    }
    return 0;
}

void
smm_search_destroy (smm_search search)
{
    if (search)
    {
        smm_connection_unref (search->conn);
        free (search->url);
        free (search);
    }
}

static smm_waypoint
smm_waypoint_create (double lat, double lon)
{
    smm_waypoint wp = calloc (1, sizeof (struct smm_waypoint_s));
    if (wp == NULL)
    {
        return NULL;
    }
    wp->lat = lat;
    wp->lon = lon;
    return wp;
}

static void
smm_waypoint_free (smm_waypoint waypoint)
{
    free (waypoint);
}

bool
smm_parse_waypoints (const char *data, size_t len, smm_waypoints *waypoints, size_t *waypoints_count)
{
    json_error_t json_error;
    bool res = false;

    /* Parse the waypoints */
    *waypoints_count = 0;
    *waypoints = NULL;

    json_t *json_root = json_loadb (data, len, 0, &json_error);
    if (json_root)
    {
        json_t *json_features = json_object_get (json_root, "features");
        if (json_is_array (json_features))
        {
            if (json_array_size (json_features) == 1)
            {
                json_t *json_search = json_array_get (json_features, 0);
                if (json_is_object (json_search))
                {
                    json_t *json_geometry = json_object_get (json_search, "geometry");
                    if (json_is_object (json_geometry))
                    {
                        json_t *json_coords = json_object_get (json_geometry, "coordinates");
                        if (json_is_array (json_coords))
                        {
                            size_t index = 0;
                            json_t *value = NULL;
                            json_array_foreach (json_coords, index, value)
                            {
                                double lat = 0.0;
                                double lon = 0.0;
                                json_t *json_lat = json_array_get (value, 1);
                                json_t *json_lon = json_array_get (value, 0);
                                if (!json_is_number (json_lat) || !json_is_number (json_lon))
                                {
                                    continue;
                                }
                                lat = json_number_value (json_lat);
                                lon = json_number_value (json_lon);
                                smm_waypoint new_wp = smm_waypoint_create (lat, lon);
                                if (new_wp)
                                {
                                    smm_waypoint *tmp
                                        = realloc (*waypoints, (*waypoints_count + 1) * sizeof (smm_waypoint));
                                    if (tmp)
                                    {
                                        *waypoints = tmp;
                                        (*waypoints)[*waypoints_count] = new_wp;
                                        *waypoints_count += 1;
                                    }
                                    else
                                    {
                                        smm_waypoint_free (new_wp);
                                        smm_waypoints_free (*waypoints, *waypoints_count);
                                        *waypoints = NULL;
                                        *waypoints_count = 0;
                                        json_decref (json_root);
                                        return false;
                                    }
                                }
                            }
                            res = true;
                        }
                    }
                }
            }
            else
            {
                DEBUG ("GeoJSON features array size != 1 (%zi)\n", json_array_size (json_features));
            }
        }
        else
        {
            DEBUG ("Didn't find features array in GeoJSON\n");
        }
        json_decref (json_root);
    }
    else
    {
        DEBUG ("JSON Parse Error on line %i: %s\n", json_error.line, json_error.text);
    }

    return res;
}

bool
smm_search_get_waypoints (smm_search search, smm_waypoints *waypoints, size_t *waypoints_count)
{
    struct buffer_s buf = { NULL, 0 };

    if (!search)
    {
        return false;
    }
    if (waypoints == NULL || waypoints_count == NULL)
    {
        smm_search_set_error (search, SMM_ERROR_INVALID_ARG, "waypoints and waypoints_count must be non-NULL");
        return false;
    }

    *waypoints = NULL;
    *waypoints_count = 0;
    smm_search_clear_error (search);

    struct smm_curl_res_s *res = smm_connection_curl_retrieve_url (search->conn, search->url, NULL, &buf, true);

    if (res == NULL)
    {
        smm_search_set_error (search, SMM_ERROR_NETWORK, "network failure fetching waypoints");
        return false;
    }
    else if (!(res->success && res->httpcode == HTTP_SUCCESS))
    {
        smm_search_set_error (search, SMM_ERROR_SERVER, "unexpected HTTP %ld fetching waypoints", res->httpcode);
        smm_curl_res_free (res);
        free (buf.data);
        return false;
    }
    smm_curl_res_free (res);

    bool parse_res = smm_parse_waypoints (buf.data, buf.bytes, waypoints, waypoints_count);
    if (!parse_res)
    {
        smm_search_set_error (search, SMM_ERROR_PARSE, "failed to parse waypoints response");
    }

    free (buf.data);

    return parse_res;
}

static bool
smm_search_action (smm_search search, const char *action)
{
    if (!search)
    {
        return false;
    }
    char *action_page = NULL;
    struct buffer_s buf = { NULL, 0 };

    if (asprintf (&action_page, "%s%s/?asset_id=%lli", search->url, action, search->asset_id) < 0)
    {
        return false;
    }
    smm_search_clear_error (search);

    struct smm_curl_res_s *res = smm_connection_curl_retrieve_url (search->conn, action_page, NULL, &buf, false);
    if (res == NULL)
    {
        smm_search_set_error (search, SMM_ERROR_NETWORK, "network failure sending %s action", action);
        free (action_page);
        return false;
    }
    else if (!(res->success && res->httpcode == HTTP_SUCCESS))
    {
        smm_search_set_error (search, SMM_ERROR_SERVER, "unexpected HTTP %ld from %s action", res->httpcode, action);
        smm_curl_res_free (res);
        free (action_page);
        free (buf.data);
        return false;
    }

    smm_curl_res_free (res);
    free (action_page);
    action_page = NULL;

    free (buf.data);

    return true;
}

bool
smm_search_accept (smm_search search)
{
    return smm_search_action (search, "begin");
}

bool
smm_search_complete (smm_search search)
{
    return smm_search_action (search, "finished");
}

void
smm_waypoints_free (smm_waypoints waypoints, size_t waypoints_count)
{
    for (size_t i = 0; i < waypoints_count; i++)
    {
        smm_waypoint_free (waypoints[i]);
    }
    free (waypoints);
}

/* Read a non-negative quantity the server may encode as a JSON integer or a
 * JSON real. json_integer_value() returns 0 for a real value, so accept both;
 * negative, non-numeric, and out-of-range values clamp into [0, UINT64_MAX]. */
static uint64_t
smm_json_number_to_u64 (const json_t *value)
{
    if (!json_is_number (value))
    {
        return 0;
    }
    double d = json_number_value (value);
    if (d <= 0.0)
    {
        return 0;
    }
    if (d >= (double)UINT64_MAX)
    {
        return UINT64_MAX;
    }
    return (uint64_t)d;
}

smm_search
smm_parse_search_json (smm_asset asset, const char *data, size_t len)
{
    smm_search search = NULL;
    json_t *json_root = NULL;
    json_error_t json_error;

    json_root = json_loadb (data, len, 0, &json_error);
    if (json_root)
    {
        const char *url = NULL;
        uint64_t distance = 0;
        uint64_t length = 0;
        uint64_t sweep_width = 0;
        json_t *tmp = json_object_get (json_root, "object_url");
        if (tmp)
        {
            url = json_string_value (tmp);
        }
        /* Validate the server-supplied path: must be a safe relative path
         * with no '..' segments, query strings, fragments, or percent-
         * encoded characters that could redirect requests at an arbitrary
         * endpoint. */
        if (url && !smm_url_path_is_safe (url))
        {
            DEBUG ("object_url is not a safe relative path; ignoring\n");
            url = NULL;
        }
        distance = smm_json_number_to_u64 (json_object_get (json_root, "distance"));
        length = smm_json_number_to_u64 (json_object_get (json_root, "length"));
        sweep_width = smm_json_number_to_u64 (json_object_get (json_root, "sweep_width"));
        if (url)
        {
            search = smm_search_create (asset, url, length, distance, sweep_width);
        }
        json_decref (json_root);
    }
    else
    {
        DEBUG ("JSON Parse Error on line %i: %s\n", json_error.line, json_error.text);
    }
    return search;
}

smm_search
smm_asset_get_search (smm_asset asset, double latitude, double longitude)
{
    if (!asset)
    {
        return NULL;
    }
    smm_search search = NULL;
    struct buffer_s buf = { NULL, 0 };

    char *page = NULL;
    if (smm_asprintf_c_locale (&page, "/search/find/closest/?asset_id=%lli&latitude=%lf&longitude=%lf", asset->asset_id,
                               latitude, longitude)
        < 0)
    {
        return NULL;
    }
    smm_asset_clear_error (asset);

    struct smm_curl_res_s *res = smm_connection_curl_retrieve_url (asset->conn, page, NULL, &buf, false);
    if (res == NULL)
    {
        smm_asset_set_error (asset, SMM_ERROR_NETWORK, "network failure fetching closest search");
        free (page);
        return NULL;
    }
    if (!(res->success && res->httpcode == HTTP_SUCCESS))
    {
        smm_asset_set_error (asset, SMM_ERROR_SERVER, "unexpected HTTP %ld fetching closest search", res->httpcode);
        smm_curl_res_free (res);
        free (page);
        free (buf.data);
        return NULL;
    }
    free (page);

    if (smm_content_type_is_json (res->content_type))
    {
        search = smm_parse_search_json (asset, buf.data, buf.bytes);
    }
    smm_curl_res_free (res);
    free (buf.data);
    return search;
}
