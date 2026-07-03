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
#include "config.h"

#include "smm-asset-internal.h"
#include "smm-asset.h"

#include <errno.h>
#include <inttypes.h>
#include <locale.h>
#include <math.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

_Atomic bool smm_debug = false;

void
smm_secure_clear (char *s)
{
    if (s == NULL)
    {
        return;
    }
#ifdef HAVE_EXPLICIT_BZERO
    explicit_bzero (s, strlen (s));
#else
    /* Fallback: write through a volatile pointer so the compiler cannot elide
     * the scrub as a dead store to soon-to-be-freed memory. */
    volatile char *p = (volatile char *)s;
    for (size_t n = strlen (s); n > 0; n--)
    {
        *p++ = '\0';
    }
#endif
}

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

static bool
smm_url_part_absent (CURLU *curlu, CURLUPart part, CURLUcode absent_code, char **out)
{
    return curl_url_get (curlu, part, out, 0) == absent_code;
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
    pthread_mutex_init (&conn->io_lock, NULL);
    conn->login_in_progress = false;
    pthread_cond_init (&conn->login_cond, NULL);

    /* libcurl's global state must be initialised before any other libcurl call
     * (curl_share_init and curl_url below, and every request on this
     * connection). Do it here, the single chokepoint through which every
     * libcurl-using path is reached.
     *
     * Initialisation failures return the connection in SMM_CONNECTION_FAILURE
     * with a last_error recorded, never NULL (NULL is reserved for allocation
     * failure), so callers have one convention to check. Either failure leaves
     * conn->share NULL, which the request path refuses up front. */
    if (!smm_curl_global_init ())
    {
        conn->state = SMM_CONNECTION_FAILURE;
        smm_connection_set_error (conn, SMM_ERROR_NETWORK, "libcurl initialisation failed");
        return conn;
    }

    if (!smm_connection_share_init (conn))
    {
        conn->state = SMM_CONNECTION_FAILURE;
        smm_connection_set_error (conn, SMM_ERROR_NETWORK, "libcurl share initialisation failed");
        return conn;
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
            char *query = NULL;
            char *fragment = NULL;
            char *user_part = NULL;
            char *password_part = NULL;
            bool scheme_ok = curl_url_get (curlu, CURLUPART_SCHEME, &scheme, 0) == CURLUE_OK && scheme
                             && (strcmp (scheme, "http") == 0 || strcmp (scheme, "https") == 0);
            bool host_ok = curl_url_get (curlu, CURLUPART_HOST, &chost, 0) == CURLUE_OK && chost && chost[0] != '\0';
            bool no_query = smm_url_part_absent (curlu, CURLUPART_QUERY, CURLUE_NO_QUERY, &query);
            bool no_fragment = smm_url_part_absent (curlu, CURLUPART_FRAGMENT, CURLUE_NO_FRAGMENT, &fragment);
            /* Userinfo can contain a username without a password, or a
             * password field without a username; reject either form. */
            bool no_user = smm_url_part_absent (curlu, CURLUPART_USER, CURLUE_NO_USER, &user_part);
            bool no_password = smm_url_part_absent (curlu, CURLUPART_PASSWORD, CURLUE_NO_PASSWORD, &password_part);
            bool http_ok = scheme_ok && host_ok && no_query && no_fragment && no_user && no_password;
            conn->state = http_ok ? SMM_CONNECTION_NEW : SMM_CONNECTION_HOST_INVALID;
            curl_free (scheme);
            curl_free (chost);
            curl_free (query);
            curl_free (fragment);
            curl_free (user_part);
            curl_free (password_part);
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

static void smm_asset_set_error (smm_asset asset, smm_error_code code, const char *fmt, ...)
    __attribute__ ((format (printf, 3, 4)));

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

static void smm_search_set_error (smm_search search, smm_error_code code, const char *fmt, ...)
    __attribute__ ((format (printf, 3, 4)));

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
        /* Scrub the credentials and session token from memory before freeing,
         * so they do not linger in the heap after the connection is closed. */
        smm_secure_clear (connection->user);
        free (connection->user);
        smm_secure_clear (connection->pass);
        free (connection->pass);
        smm_secure_clear (connection->csrfmiddlewaretoken);
        free (connection->csrfmiddlewaretoken);
        smm_connection_share_destroy (connection);
        pthread_cond_destroy (&connection->login_cond);
        pthread_mutex_destroy (&connection->io_lock);
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
 * media-type and hostname matching so the result does not depend on the
 * caller's locale (e.g. the Turkish dotless-i rule that would break
 * strncasecmp). */
bool
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
smm_coords_valid (double lat, double lon)
{
    /* Reject NaN/infinity outright, then bound to valid WGS84 ranges so a bad
     * coordinate can never be formatted into a request URL as "nan"/"inf" or
     * sent as an operationally invalid position. */
    if (!isfinite (lat) || !isfinite (lon))
        return false;
    return lat >= -90.0 && lat <= 90.0 && lon >= -180.0 && lon <= 180.0;
}

bool
smm_position_inputs_valid (double lat, double lon, uint16_t heading, uint8_t fix)
{
    if (!smm_coords_valid (lat, lon))
        return false;
    if (heading > 359)
        return false;
    /* The public API documents fix as 0 (unknown), 2 (2D), or 3 (3D). */
    return fix == 0 || fix == 2 || fix == 3;
}

char *
smm_asset_build_position_body (double lat, double lon, int32_t alt, uint16_t heading, uint8_t fix)
{
    char *body = NULL;
    /* application/x-www-form-urlencoded body for the position POST. The
     * coordinates are formatted in the C locale so the decimal separator is
     * always '.'. */
    if (smm_asprintf_c_locale (&body, "lat=%lf&lon=%lf&alt=%" PRId32 "&heading=%u&fix=%u", lat, lon, alt, heading, fix)
        < 0)
    {
        return NULL;
    }
    return body;
}

bool
smm_asset_report_position (smm_asset asset, double latitude, double longitude, int32_t altitude, uint16_t heading,
                           uint8_t fix)
{
    if (!asset)
    {
        return false;
    }
    /* Clear the error before any fallible step, so no failure path can leave
     * a stale earlier error visible as this call's result. */
    smm_asset_clear_error (asset);
    if (!smm_position_inputs_valid (latitude, longitude, heading, fix))
    {
        smm_asset_set_error (asset, SMM_ERROR_INVALID_ARG,
                             "invalid position inputs (latitude, longitude, heading, or fix out of range)");
        return false;
    }
    struct buffer_s buf = { NULL, 0 };

    /* The endpoint is POST-only (it mutates state); the position fields go in
     * the request body and the CSRF token is added as a header by the curl
     * layer for session-authenticated connections. */
    char *body = smm_asset_build_position_body (latitude, longitude, altitude, heading, fix);
    if (body == NULL)
    {
        smm_asset_set_error (asset, SMM_ERROR_NETWORK, "failed to build position report request");
        return false;
    }
    char *page = NULL;
    if (asprintf (&page, "/data/assets/%lld/position/add/", asset->asset_id) < 0)
    {
        smm_asset_set_error (asset, SMM_ERROR_NETWORK, "failed to build position report request");
        free (body);
        return false;
    }

    struct smm_curl_res_s *res = smm_connection_curl_retrieve_url (asset->conn, page, body, &buf, false);
    free (page);
    free (body);
    if (res == NULL)
    {
        smm_asset_set_error (asset, SMM_ERROR_NETWORK, "network failure reporting position");
        free (buf.data);
        return false;
    }
    if (!(res->success && res->httpcode == HTTP_SUCCESS))
    {
        smm_asset_set_error (asset, SMM_ERROR_SERVER, "unexpected HTTP %ld from position report", res->httpcode);
        smm_curl_res_free (res);
        free (buf.data);
        return false;
    }

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
smm_search_create (smm_asset asset, long long search_id, uint64_t length, uint64_t distance, uint64_t sweep_width)
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

    search->search_id = search_id;
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

/* Parse one GeoJSON [lon, lat] coordinate tuple into a waypoint. Returns false
 * (creating no waypoint) for a non-array entry, a missing or non-numeric
 * coordinate, an out-of-range coordinate, or an allocation failure — each of
 * which fails the whole route parse rather than being silently skipped. */
static bool
smm_parse_waypoint_tuple (json_t *value, size_t index, smm_waypoint *out_wp)
{
    if (!json_is_array (value))
    {
        DEBUG ("malformed coordinate tuple at index %zu\n", index);
        return false;
    }
    json_t *json_lon = json_array_get (value, 0);
    json_t *json_lat = json_array_get (value, 1);
    if (!json_is_number (json_lon) || !json_is_number (json_lat))
    {
        DEBUG ("malformed coordinate tuple at index %zu\n", index);
        return false;
    }
    double lon = json_number_value (json_lon);
    double lat = json_number_value (json_lat);
    if (!smm_coords_valid (lat, lon))
    {
        DEBUG ("coordinate out of range at index %zu\n", index);
        return false;
    }
    smm_waypoint wp = smm_waypoint_create (lat, lon);
    if (wp == NULL)
    {
        return false;
    }
    *out_wp = wp;
    return true;
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
                        json_t *json_type = json_object_get (json_geometry, "type");
                        json_t *json_coords = json_object_get (json_geometry, "coordinates");
                        /* The search route is a GeoJSON LineString with at least
                         * two points; anything else is a malformed route rather
                         * than a (possibly empty or truncated) success. */
                        if (!json_is_string (json_type) || strcmp (json_string_value (json_type), "LineString") != 0)
                        {
                            DEBUG ("geometry type is not LineString\n");
                        }
                        else if (!json_is_array (json_coords) || json_array_size (json_coords) < 2)
                        {
                            DEBUG ("geometry does not have at least two coordinates\n");
                        }
                        else
                        {
                            bool ok = true;
                            size_t index = 0;
                            json_t *value = NULL;
                            json_array_foreach (json_coords, index, value)
                            {
                                smm_waypoint new_wp = NULL;
                                if (!smm_parse_waypoint_tuple (value, index, &new_wp))
                                {
                                    ok = false;
                                    break;
                                }
                                smm_waypoint *tmp
                                    = realloc (*waypoints, (*waypoints_count + 1) * sizeof (smm_waypoint));
                                if (tmp == NULL)
                                {
                                    smm_waypoint_free (new_wp);
                                    ok = false;
                                    break;
                                }
                                *waypoints = tmp;
                                (*waypoints)[*waypoints_count] = new_wp;
                                *waypoints_count += 1;
                            }
                            res = ok;
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

    if (!res)
    {
        /* Discard any partially-built list on failure so a malformed route is
         * never reported as a truncated or empty success. Safe on the initial
         * NULL/empty state. */
        smm_waypoints_free (*waypoints, *waypoints_count);
        *waypoints = NULL;
        *waypoints_count = 0;
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

    /* Build the request path from the parsed search id rather than reusing a
     * server-supplied string, so it can only ever be /search/<id>/. */
    char *page = NULL;
    if (asprintf (&page, "/search/%lld/", search->search_id) < 0)
    {
        smm_search_set_error (search, SMM_ERROR_NETWORK, "failed to build waypoints request");
        return false;
    }

    struct smm_curl_res_s *res = smm_connection_curl_retrieve_url (search->conn, page, NULL, &buf, true);
    free (page);

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
    char *body = NULL;
    struct buffer_s buf = { NULL, 0 };

    /* Clear the error before any fallible step, so no failure path can leave
     * a stale earlier error visible as this call's result. */
    smm_search_clear_error (search);

    /* Build the path from the parsed search id, not a server string, so it can
     * only ever be /search/<id>/<action>/. */
    if (asprintf (&action_page, "/search/%lld/%s/", search->search_id, action) < 0)
    {
        smm_search_set_error (search, SMM_ERROR_NETWORK, "failed to build %s action request", action);
        return false;
    }
    /* POST, not GET: search state changes (begin/finished) are @require_POST
     * on the server since the CSRF hardening that also moved position
     * reporting to POST. asset_id must travel in the POST body: on a POST the
     * server reads it from the form data only, so a query-string asset_id is
     * invisible and the action 404s. */
    if (asprintf (&body, "asset_id=%lli", search->asset_id) < 0)
    {
        smm_search_set_error (search, SMM_ERROR_NETWORK, "failed to build %s action request", action);
        free (action_page);
        return false;
    }

    struct smm_curl_res_s *res = smm_connection_curl_retrieve_url (search->conn, action_page, body, &buf, false);
    free (action_page);
    free (body);
    if (res == NULL)
    {
        smm_search_set_error (search, SMM_ERROR_NETWORK, "network failure sending %s action", action);
        return false;
    }
    if (!(res->success && res->httpcode == HTTP_SUCCESS))
    {
        smm_search_set_error (search, SMM_ERROR_SERVER, "unexpected HTTP %ld from %s action", res->httpcode, action);
        smm_curl_res_free (res);
        free (buf.data);
        return false;
    }

    smm_curl_res_free (res);
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

/* Validate and parse a server-supplied search object_url. Accepts only the
 * documented shape "/search/<positive-id>/" and writes the id to *id_out.
 * Returns false for any other path. Driving the actual request paths from this
 * parsed id (rather than reusing an arbitrary server string) keeps the search
 * API from being pointed at an unintended same-host endpoint such as
 * /accounts/logout/. */
static bool
smm_search_parse_object_url (const char *url, long long *id_out)
{
    static const char prefix[] = "/search/";
    const size_t prefix_len = sizeof (prefix) - 1;

    if (url == NULL || strncmp (url, prefix, prefix_len) != 0)
        return false;

    const char *p = url + prefix_len;
    /* Require the id to start with a digit: strtoll would otherwise skip
     * leading whitespace and accept a sign, loosening the strict
     * "/search/<digits>/" shape. */
    if (*p < '0' || *p > '9')
        return false;

    errno = 0;
    char *end = NULL;
    long long id = strtoll (p, &end, 10);
    if (errno == ERANGE || id <= 0)
        return false; /* overflow, or a non-positive id ("/search/0/") */

    /* Exactly one trailing '/' and nothing else may follow the id. */
    if (end[0] != '/' || end[1] != '\0')
        return false;

    *id_out = id;
    return true;
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
        long long search_id = 0;
        json_t *tmp = json_object_get (json_root, "object_url");
        if (tmp)
        {
            url = json_string_value (tmp);
        }
        /* Accept only the documented "/search/<positive-id>/" shape; the
         * parsed id (not the raw string) is the trust boundary for search
         * actions. */
        bool url_ok = smm_search_parse_object_url (url, &search_id);
        if (url_ok)
        {
            uint64_t distance = smm_json_number_to_u64 (json_object_get (json_root, "distance"));
            uint64_t length = smm_json_number_to_u64 (json_object_get (json_root, "length"));
            uint64_t sweep_width = smm_json_number_to_u64 (json_object_get (json_root, "sweep_width"));
            search = smm_search_create (asset, search_id, length, distance, sweep_width);
        }
        else
        {
            /* A successful closest-search response always carries a valid
             * /search/<id>/ object_url; a missing, non-string, or unexpected
             * one is a protocol violation by the server. */
            DEBUG ("object_url is missing or not a /search/<id>/ path\n");
            smm_asset_set_error (asset, SMM_ERROR_PROTOCOL, "search response has a missing or invalid object_url");
        }
        json_decref (json_root);
    }
    else
    {
        DEBUG ("JSON Parse Error on line %i: %s\n", json_error.line, json_error.text);
        smm_asset_set_error (asset, SMM_ERROR_PARSE, "failed to parse closest search JSON");
    }
    return search;
}

smm_search
smm_search_from_response (smm_asset asset, long httpcode, const char *content_type, const char *data, size_t len)
{
    if (httpcode == HTTP_NOT_FOUND)
    {
        /* The server's documented "no suitable searches exist" result. This is
         * a clean no-search outcome, not an error. */
        return NULL;
    }
    if (httpcode != HTTP_SUCCESS)
    {
        smm_asset_set_error (asset, SMM_ERROR_SERVER, "unexpected HTTP %ld fetching closest search", httpcode);
        return NULL;
    }
    if (!smm_content_type_is_json (content_type))
    {
        smm_asset_set_error (asset, SMM_ERROR_PROTOCOL, "non-JSON response to closest search");
        return NULL;
    }
    return smm_parse_search_json (asset, data, len);
}

smm_search
smm_asset_get_search (smm_asset asset, double latitude, double longitude)
{
    if (!asset)
    {
        return NULL;
    }
    /* Clear the error before any fallible step: a NULL return with the error
     * left SMM_ERROR_NONE is the documented "no suitable search" outcome, so
     * every failure path below must record an error, and none may leak a
     * stale one. */
    smm_asset_clear_error (asset);
    if (!smm_coords_valid (latitude, longitude))
    {
        smm_asset_set_error (asset, SMM_ERROR_INVALID_ARG, "invalid search coordinates (latitude or longitude)");
        return NULL;
    }
    struct buffer_s buf = { NULL, 0 };

    char *page = NULL;
    if (smm_asprintf_c_locale (&page, "/search/find/closest/?asset_id=%lli&latitude=%lf&longitude=%lf", asset->asset_id,
                               latitude, longitude)
        < 0)
    {
        smm_asset_set_error (asset, SMM_ERROR_NETWORK, "failed to build closest-search request");
        return NULL;
    }

    struct smm_curl_res_s *res = smm_connection_curl_retrieve_url (asset->conn, page, NULL, &buf, true);
    free (page);
    if (res == NULL)
    {
        smm_asset_set_error (asset, SMM_ERROR_NETWORK, "network failure fetching closest search");
        free (buf.data);
        return NULL;
    }

    smm_search search = smm_search_from_response (asset, res->httpcode, res->content_type, buf.data, buf.bytes);
    smm_curl_res_free (res);
    free (buf.data);
    return search;
}
