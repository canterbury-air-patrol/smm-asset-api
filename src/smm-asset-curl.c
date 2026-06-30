/**
 * smm-asset-curl.c, Use curl to communicate with the SMM server.
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

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_TIDY_H
#include <tidy.h>
#include <tidybuffio.h>
#elif HAVE_TIDY_TIDY_H
#include <tidy/tidy.h>
#include <tidy/tidybuffio.h>
#else
#error No tidy header(s)
#endif

static pthread_once_t smm_curl_global_once = PTHREAD_ONCE_INIT;
static CURLcode smm_curl_global_result = CURLE_OK;

static void
smm_curl_global_init_once (void)
{
    smm_curl_global_result = curl_global_init (CURL_GLOBAL_DEFAULT);
}

/* Initialise libcurl's global state exactly once before any other libcurl API
 * is used. Thread-safe via pthread_once; returns true on success. There is
 * deliberately no matching curl_global_cleanup(): as a shared library we cannot
 * know when the host application is finished with libcurl, and tearing the
 * global state down underneath it would be unsafe. */
bool
smm_curl_global_init (void)
{
    pthread_once (&smm_curl_global_once, smm_curl_global_init_once);
    return smm_curl_global_result == CURLE_OK;
}

static void
smm_curl_lock (CURL *handle, curl_lock_data data, curl_lock_access access, void *userptr)
{
    (void)handle;
    (void)data;
    (void)access;
    pthread_mutex_t *lock = (pthread_mutex_t *)userptr;
    pthread_mutex_lock (lock);
}

static void
smm_curl_unlock (CURL *handle, curl_lock_data data, void *userptr)
{
    (void)handle;
    (void)data;
    pthread_mutex_t *lock = (pthread_mutex_t *)userptr;
    pthread_mutex_unlock (lock);
}

static bool
smm_connection_share_configure (CURLSH *share, pthread_mutex_t *lock)
{
    if (curl_share_setopt (share, CURLSHOPT_LOCKFUNC, smm_curl_lock) != CURLSHE_OK)
        return false;
    if (curl_share_setopt (share, CURLSHOPT_UNLOCKFUNC, smm_curl_unlock) != CURLSHE_OK)
        return false;
    if (curl_share_setopt (share, CURLSHOPT_USERDATA, lock) != CURLSHE_OK)
        return false;
    if (curl_share_setopt (share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE) != CURLSHE_OK)
        return false;
    if (curl_share_setopt (share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS) != CURLSHE_OK)
        return false;
    if (curl_share_setopt (share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION) != CURLSHE_OK)
        return false;
    return true;
}

static bool
smm_build_login_post_data (const char *csrf, const char *user, const char *pass, char **out_post)
{
    bool ok = false;
    CURL *curl = curl_easy_init ();
    if (!curl)
        return false;

    char *esc_csrf = curl_easy_escape (curl, csrf, 0);
    char *esc_user = curl_easy_escape (curl, user, 0);
    char *esc_pass = curl_easy_escape (curl, pass, 0);

    if (esc_csrf && esc_user && esc_pass
        && asprintf (out_post, "csrfmiddlewaretoken=%s&username=%s&password=%s", esc_csrf, esc_user, esc_pass) >= 0)
    {
        ok = true;
    }

    curl_free (esc_csrf);
    curl_free (esc_user);
    curl_free (esc_pass);
    curl_easy_cleanup (curl);
    return ok;
}

bool
smm_connection_share_init (smm_connection conn)
{
    if (conn->share != NULL)
    {
        return true;
    }

    CURLSH *share = curl_share_init ();
    if (share == NULL)
    {
        return false;
    }

    if (!smm_connection_share_configure (share, &conn->lock))
    {
        curl_share_cleanup (share);
        return false;
    }

    conn->share = share;
    return true;
}

void
smm_connection_share_destroy (smm_connection conn)
{
    if (conn->share != NULL)
    {
        curl_share_cleanup (conn->share);
        conn->share = NULL;
    }
}

void
smm_curl_res_free (struct smm_curl_res_s *res)
{
    if (res)
    {
        free (res->full_uri);
        free (res->redirect_url);
        free (res->content_type);
        free (res);
    }
}

/* Compute size*nmemb for a libcurl write callback, guarding against size_t
 * overflow. Returns false (leaving *out untouched) when the product would
 * overflow, so the caller can abort the transfer by returning 0. libcurl
 * normally passes bounded chunks, but the arithmetic must be correct at the
 * boundary so a wrapped length cannot defeat later size checks. */
static bool
smm_curl_chunk_size (size_t size, size_t nmemb, size_t *out)
{
    if (size != 0 && nmemb > SIZE_MAX / size)
        return false;
    *out = size * nmemb;
    return true;
}

/* Signature is fixed by libcurl's curl_write_callback; params cannot be const. */
static size_t
/* cppcheck-suppress[constParameterCallback] */
eat_data (char *ptr __attribute__ ((unused)), size_t size, size_t nmemb, void *userdata __attribute__ ((unused)))
{
    size_t total;
    if (!smm_curl_chunk_size (size, nmemb, &total))
    {
        return 0;
    }
    return total;
}

/* Signature is fixed by libcurl's curl_write_callback; ptr cannot be const. */
size_t
/* cppcheck reports this as constParameterPointer or constParameterCallback
 * depending on its version (CI's cppcheck and a current local one disagree);
 * suppress both so the gate is reproducible across versions. */
/* cppcheck-suppress[constParameterPointer,constParameterCallback] */
to_buffer (char *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t new_bytes;
    if (!smm_curl_chunk_size (size, nmemb, &new_bytes))
    {
        return 0;
    }
    struct buffer_s *buf = (struct buffer_s *)userdata;
    /* Refuse to grow the buffer past the cap. Returning a short count makes
     * curl fail the transfer with CURLE_WRITE_ERROR. The comparison is written
     * to avoid overflow in buf->bytes + new_bytes (+1 for the NUL). */
    if (buf->bytes >= SMM_MAX_RESPONSE_BYTES || new_bytes > SMM_MAX_RESPONSE_BYTES - buf->bytes)
    {
        return 0;
    }
    char *tmp = realloc (buf->data, buf->bytes + new_bytes + 1);
    if (tmp == NULL)
    {
        return 0;
    }
    buf->data = tmp;
    memcpy (&buf->data[buf->bytes], ptr, new_bytes);
    buf->bytes += new_bytes;
    buf->data[buf->bytes] = '\0';

    return new_bytes;
}

bool
smm_connection_state_for_curl_error (CURLcode cres, smm_connection_status *state)
{
    switch (cres)
    {
        case CURLE_URL_MALFORMAT:
            *state = SMM_CONNECTION_HOST_INVALID;
            return true;
        case CURLE_COULDNT_RESOLVE_HOST:
        case CURLE_COULDNT_CONNECT:
            *state = SMM_CONNECTION_NO_HOST_CONNECTION;
            return true;
        case CURLE_HTTP_RETURNED_ERROR:
            /* The server was reached and answered; an HTTP-level error (a
             * 404/500 from one endpoint) says nothing about the connection
             * or the session, so leave the connection state alone. The
             * caller's per-object last_error carries the HTTP status. */
            return false;
        default:
            *state = SMM_CONNECTION_FAILURE;
            return true;
    }
}

void
smm_buffer_reset (struct buffer_s *buf)
{
    if (buf)
    {
        free (buf->data);
        buf->data = NULL;
        buf->bytes = 0;
    }
}

/* If a libcurl CURLINFO_COOKIELIST line names the wanted cookie, return a copy
 * of its value, else NULL. The line is Netscape format with seven tab-separated
 * fields: domain, flag, path, secure, expiry, name, value. */
static char *
smm_cookie_value_if_name (const char *line, const char *name)
{
    const char *fields[7];
    int n = 0;
    const char *p = line;

    fields[n++] = p;
    while (n < 7 && (p = strchr (p, '\t')) != NULL)
    {
        p++;
        fields[n++] = p;
    }
    if (n < 7)
    {
        return NULL;
    }

    /* The name occupies [fields[5], fields[6] - 1) (the byte before the value
     * is the separating tab); the value runs from fields[6] to end of line. */
    size_t name_len = (size_t)(fields[6] - 1 - fields[5]);
    if (strlen (name) != name_len || strncmp (fields[5], name, name_len) != 0)
    {
        return NULL;
    }
    return strdup (fields[6]);
}

/* Refresh the connection's stored CSRF token from the csrftoken cookie in the
 * handle's cookie jar. Django rotates the CSRF token on login, so the token
 * captured from the login page goes stale; tracking the cookie after every
 * request keeps a token that matches the cookie the server will check. */
static void
smm_connection_update_csrf_from_cookies (smm_connection conn, CURL *curl)
{
    struct curl_slist *cookies = NULL;
    if (curl_easy_getinfo (curl, CURLINFO_COOKIELIST, &cookies) != CURLE_OK)
    {
        return;
    }

    char *token = NULL;
    for (const struct curl_slist *c = cookies; c != NULL; c = c->next)
    {
        char *value = smm_cookie_value_if_name (c->data, "csrftoken");
        if (value)
        {
            free (token);
            token = value;
        }
    }
    curl_slist_free_all (cookies);

    if (token)
    {
        pthread_mutex_lock (&conn->lock);
        free (conn->csrfmiddlewaretoken);
        conn->csrfmiddlewaretoken = token;
        pthread_mutex_unlock (&conn->lock);
    }
}

struct smm_curl_res_s *
smm_connection_curl_retrieve_url_r (smm_connection conn, const char *path, const char *post_data,
                                    size_t (*write_func) (char *ptr, size_t size, size_t nmemb, void *userdata),
                                    void *write_data, bool json)
{
    struct smm_curl_res_s *res = NULL;
    CURL *curl = NULL;
    bool verify_tls = true;
    long connect_timeout = 0;
    long transfer_timeout = 0;
    CURLSH *share = NULL;
    struct curl_slist *headers = NULL;
    char *csrf_token = NULL;
    bool have_ref = false;

    /* Never log post_data: for the login request it carries the user's
     * password. Log only whether a body is present. */
    DEBUG ("(%p, %s, %s, %p)\n", (void *)conn, path, post_data ? "<redacted body>" : "(none)", write_data);

    if (conn == NULL || path == NULL)
    {
        DEBUG ("conn or path is NULL\n");
        return NULL;
    }

    res = (struct smm_curl_res_s *)calloc (1, sizeof (struct smm_curl_res_s));
    if (res == NULL)
    {
        return NULL;
    }

    pthread_mutex_lock (&conn->lock);
    verify_tls = conn->verify_tls;
    connect_timeout = conn->connect_timeout_secs;
    transfer_timeout = conn->transfer_timeout_secs;
    share = conn->share;
    /* Snapshot the current CSRF token so a POST can present it as a header. */
    if (post_data && conn->csrfmiddlewaretoken)
    {
        csrf_token = strdup (conn->csrfmiddlewaretoken);
    }
    conn->refcount++;
    have_ref = true;

    if (asprintf (&res->full_uri, "%s%s", conn->host, path) < 0)
    {
        /* POSIX leaves *strp undefined on asprintf failure; null it so the
         * unconditional free in smm_curl_res_free cannot touch an
         * indeterminate pointer (calloc zeroed it, but do not rely on the
         * call having left it untouched). */
        res->full_uri = NULL;
        pthread_mutex_unlock (&conn->lock);
        DEBUG ("failed to allocate full_uri");
        goto out;
    }
    pthread_mutex_unlock (&conn->lock);

    curl = curl_easy_init ();
    if (curl == NULL)
    {
        goto out;
    }

    curl_easy_setopt (curl, CURLOPT_SHARE, share);
    curl_easy_setopt (curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, verify_tls ? 1L : 0L);
    curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, verify_tls ? 2L : 0L);
    curl_easy_setopt (curl, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt (curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT,
                      connect_timeout > 0 ? connect_timeout : SMM_CURL_CONNECT_TIMEOUT_SECS);
    curl_easy_setopt (curl, CURLOPT_TIMEOUT, transfer_timeout > 0 ? transfer_timeout : SMM_CURL_TRANSFER_TIMEOUT_SECS);
    curl_easy_setopt (curl, CURLOPT_URL, res->full_uri);

    if (post_data)
    {
        curl_easy_setopt (curl, CURLOPT_REFERER, res->full_uri);
        curl_easy_setopt (curl, CURLOPT_POSTFIELDS, post_data);
        curl_easy_setopt (curl, CURLOPT_POST, 1L);
    }
    else
    {
        curl_easy_setopt (curl, CURLOPT_REFERER, NULL);
        curl_easy_setopt (curl, CURLOPT_POSTFIELDS, NULL);
        curl_easy_setopt (curl, CURLOPT_POST, 0L);
    }

    if (write_func)
    {
        curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, write_func);
        curl_easy_setopt (curl, CURLOPT_WRITEDATA, write_data);
    }
    else
    {
        curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, eat_data);
        curl_easy_setopt (curl, CURLOPT_WRITEDATA, NULL);
    }

    if (json)
    {
        headers = curl_slist_append (headers, "Accept: application/json");
    }
    /* Present the CSRF token as a header on POSTs. Using the header (rather than
     * a form field) means a request retried after a lazy login re-reads the
     * freshly rotated token, instead of resending a body fixed before login. */
    if (csrf_token)
    {
        char *csrf_header = NULL;
        if (asprintf (&csrf_header, "X-CSRFToken: %s", csrf_token) >= 0)
        {
            headers = curl_slist_append (headers, csrf_header);
            free (csrf_header);
        }
    }
    if (headers)
    {
        curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);
    }

    DEBUG ("fetching %s\n", res->full_uri);
    CURLcode cres = curl_easy_perform (curl);
    DEBUG ("curl returned %i\n", cres);
    res->success = (cres == CURLE_OK);

    /* Keep the stored CSRF token current with the cookie jar (the server may
     * set or rotate the csrftoken cookie on any response, notably login). */
    smm_connection_update_csrf_from_cookies (conn, curl);

    if (cres != CURLE_OK)
    {
        smm_connection_status new_state;
        if (smm_connection_state_for_curl_error (cres, &new_state))
        {
            pthread_mutex_lock (&conn->lock);
            conn->state = new_state;
            pthread_mutex_unlock (&conn->lock);
        }
    }

    curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &res->httpcode);
    DEBUG ("httpcode = %li\n", res->httpcode);
    switch (res->httpcode)
    {
        case HTTP_SUCCESS:
        {
            char *ct = NULL;
            if (curl_easy_getinfo (curl, CURLINFO_CONTENT_TYPE, &ct) == CURLE_OK && ct)
            {
                res->content_type = strdup (ct);
                if (!res->content_type)
                {
                    res->success = false;
                }
            }
        }
        break;
        case HTTP_MOVED_PERMANENTLY:
        case HTTP_FOUND:
        case HTTP_SEE_OTHER:
        {
            char *redirect_url = NULL;
            if (curl_easy_getinfo (curl, CURLINFO_REDIRECT_URL, &redirect_url) == CURLE_OK && redirect_url)
            {
                res->redirect_url = strdup (redirect_url);
                if (!res->redirect_url)
                {
                    res->success = false;
                }
            }
        }
        break;
        default:
            break;
    }

out:
    free (csrf_token);
    if (headers)
    {
        curl_slist_free_all (headers);
    }
    if (curl)
    {
        curl_easy_cleanup (curl);
    }
    if (have_ref)
    {
        smm_connection_unref (conn);
    }
    if (res && !res->success && res->httpcode == 0)
    {
        smm_curl_res_free (res);
        res = NULL;
    }

    DEBUG ("Done\n");

    return res;
}

/* Bound on how deeply extract_csrfmiddlewaretoken recurses into the parsed
 * login page. A login form is shallow; this only exists so a pathologically
 * nested (hostile) document cannot exhaust the stack. */
#define SMM_CSRF_MAX_DEPTH 256

static bool
extract_csrfmiddlewaretoken (TidyDoc tdoc, TidyNode tnod, char **token, int depth)
{
    bool res = false;
    if (depth >= SMM_CSRF_MAX_DEPTH)
    {
        DEBUG ("CSRF search exceeded max depth %i; stopping descent\n", SMM_CSRF_MAX_DEPTH);
        return false;
    }
    for (TidyNode child = tidyGetChild (tnod); child; child = tidyGetNext (child))
    {
        ctmbstr name = tidyNodeGetName (child);
        if (name)
        {
            if (strcmp (name, "input") == 0)
            {
                bool is_csrf = false;
                ctmbstr value = NULL;
                /* check the attributes */
                for (TidyAttr attr = tidyAttrFirst (child); attr; attr = tidyAttrNext (attr))
                {
                    ctmbstr attrName = tidyAttrName (attr);
                    if (strcmp (attrName, "name") == 0)
                    {
                        if (strcmp (tidyAttrValue (attr), "csrfmiddlewaretoken") == 0)
                        {
                            is_csrf = true;
                        }
                    }
                    else if (strcmp (attrName, "value") == 0)
                    {
                        value = tidyAttrValue (attr);
                    }
                }
                if (is_csrf && value)
                {
                    size_t len = strlen (value);
                    if (len > 0 && len < 256)
                    {
                        /* Validate token characters:
                         * [A-Za-z0-9_\-] */
                        bool valid = true;
                        for (size_t i = 0; i < len; i++)
                        {
                            if (!((value[i] >= 'a' && value[i] <= 'z') || (value[i] >= 'A' && value[i] <= 'Z')
                                  || (value[i] >= '0' && value[i] <= '9') || (value[i] == '_') || (value[i] == '-')))
                            {
                                valid = false;
                                break;
                            }
                        }
                        if (valid)
                        {
                            *token = strdup (value);
                            if (*token == NULL)
                            {
                                return false;
                            }
                            return true;
                        }
                        else
                        {
                            DEBUG ("CSRF "
                                   "token "
                                   "contains "
                                   "invalid "
                                   "characters"
                                   "\n");
                        }
                    }
                    else
                    {
                        DEBUG ("CSRF token has invalid "
                               "length: %zu\n",
                               len);
                    }
                }
            }
        }
        res = extract_csrfmiddlewaretoken (tdoc, child, token, depth + 1);
        if (res)
        {
            return res;
        }
    }
    return res;
}

char *
smm_parse_csrf_token (const char *data, size_t len)
{
    char *token = NULL;
    TidyBuffer docbuf = { 0 };
    TidyBuffer errbuf = { 0 };
    TidyDoc tdoc = tidyCreate ();

    if (tdoc == NULL)
    {
        return NULL;
    }

    tidyOptSetBool (tdoc, TidyForceOutput, yes);
    tidyOptSetInt (tdoc, TidyWrapLen, 4096);
    tidyBufInit (&docbuf);
    tidyBufInit (&errbuf);
    tidyBufAppend (&docbuf, (void *)data, len);

    /* Redirect tidy's diagnostics into a buffer we discard; otherwise it
     * writes parser warnings about the login page straight to the host
     * application's stderr on every login. Best-effort: if the redirect
     * cannot be installed we still parse rather than failing the login. */
    tidySetErrorBuffer (tdoc, &errbuf);

    if (tidyParseBuffer (tdoc, &docbuf) >= 0)
    {
        tidyCleanAndRepair (tdoc);
        extract_csrfmiddlewaretoken (tdoc, tidyGetRoot (tdoc), &token, 0);
    }

    tidyBufFree (&docbuf);
    tidyBufFree (&errbuf);
    tidyRelease (tdoc);

    return token;
}

bool
smm_connection_try_https_upgrade (smm_connection conn, const char *redirect_url)
{
    bool upgraded = false;
    if (conn == NULL || redirect_url == NULL)
    {
        return false;
    }
    static const char http_scheme[] = "http://";
    const size_t http_scheme_len = sizeof (http_scheme) - 1;

    pthread_mutex_lock (&conn->lock);
    /* smm_https_upgrade_is_same_host only matches hosts with an explicit
     * "http://" scheme, which is what makes skipping the scheme below safe.
     * Check the prefix here too, so the pointer arithmetic cannot silently
     * outlive that invariant if the validation ever changes. */
    if (strncmp (conn->host, http_scheme, http_scheme_len) == 0
        && smm_https_upgrade_is_same_host (conn->host, redirect_url))
    {
        char *new_host = NULL;
        if (asprintf (&new_host, "https://%s", conn->host + http_scheme_len) >= 0)
        {
            free (conn->host);
            conn->host = new_host;
            upgraded = true;
        }
        else
        {
            DEBUG ("Failed to create new host\n");
        }
    }
    pthread_mutex_unlock (&conn->lock);
    return upgraded;
}

bool
smm_asset_connection_login (smm_connection connection)
{
    bool res = false;
    struct buffer_s buf = { NULL, 0 };
    char *csrf_token = NULL;
    smm_connection_status new_state = SMM_CONNECTION_FAILURE;

    if (connection == NULL)
    {
        return false;
    }

    /* Serialise concurrent login attempts. If another thread is already
     * logging in, wait for it to finish. When it does, if the connection is
     * now CONNECTED, return success without making another login attempt. */
    pthread_mutex_lock (&connection->lock);
    while (connection->login_in_progress)
    {
        pthread_cond_wait (&connection->login_cond, &connection->lock);
    }
    if (connection->state == SMM_CONNECTION_CONNECTED)
    {
        pthread_mutex_unlock (&connection->lock);
        return true;
    }
    connection->login_in_progress = true;
    pthread_mutex_unlock (&connection->lock);

    /* Use the raw (non-retrying) fetch so that a redirect on the login page
     * itself does not recurse back into smm_asset_connection_login. The login
     * HTML is buffered through to_buffer, which enforces SMM_MAX_RESPONSE_BYTES;
     * the bytes are handed to Tidy only after the (capped) transfer completes. */
    struct smm_curl_res_s *res_get
        = smm_connection_curl_retrieve_url_r (connection, "/accounts/login/", NULL, to_buffer, &buf, false);

    /* The server may answer a plain-http login GET with a same-host redirect
     * to https (e.g. Django's SECURE_SSL_REDIRECT or a proxy rule). The lazy
     * request path performs this upgrade, so do the same here rather than
     * failing an eager login that the lazy path would have survived. One
     * attempt only; any other redirect is still a failure. */
    if (res_get && res_get->success && smm_httpcode_is_redirect (res_get->httpcode)
        && smm_connection_try_https_upgrade (connection, res_get->redirect_url))
    {
        DEBUG ("Upgrading login to https\n");
        smm_curl_res_free (res_get);
        /* Drop anything the redirect response wrote into the buffer. */
        smm_buffer_reset (&buf);
        res_get = smm_connection_curl_retrieve_url_r (connection, "/accounts/login/", NULL, to_buffer, &buf, false);
    }

    if (res_get && res_get->success && res_get->httpcode == HTTP_SUCCESS)
    {
        /* find the input token with the csrfmiddlewaretoken */
        csrf_token = smm_parse_csrf_token (buf.data, buf.bytes);

        if (csrf_token)
        {
            char *post_data = NULL;
            if (smm_build_login_post_data (csrf_token, connection->user, connection->pass, &post_data))
            {
                struct smm_curl_res_s *res_post
                    = smm_connection_curl_retrieve_url_r (connection, "/accounts/login/", post_data, NULL, NULL, false);
                if (res_post && res_post->success && res_post->httpcode == HTTP_FOUND)
                {
                    res = true;
                    new_state = SMM_CONNECTION_CONNECTED;
                }
                else
                {
                    new_state = SMM_CONNECTION_AUTHENTICATION_FAILURE;
                }
                smm_curl_res_free (res_post);
                free (post_data);
            }
            else
            {
                new_state = SMM_CONNECTION_FAILURE;
            }
        }
        else
        {
            DEBUG ("Failed to find CSRF token in login page\n");
            new_state = SMM_CONNECTION_PROTOCOL_ERROR;
        }
    }
    else if (!res_get)
    {
        DEBUG ("No res object returned\n");
        new_state = SMM_CONNECTION_NO_HOST_CONNECTION;
    }
    else
    {
        DEBUG ("success = %s, httpcode = %li\n", res_get->success ? "true" : "false", res_get->httpcode);
    }
    smm_curl_res_free (res_get);

    smm_buffer_reset (&buf);

    /* Publish state and last_error under the lock so readers always see a
     * consistent view. The raw request path already refreshes
     * csrfmiddlewaretoken from Set-Cookie after each response; keep that newer
     * cookie token when present, and use the parsed form token only as a
     * fallback for servers that do not set a csrftoken cookie. */
    pthread_mutex_lock (&connection->lock);
    if (csrf_token && connection->csrfmiddlewaretoken == NULL)
    {
        connection->csrfmiddlewaretoken = csrf_token;
        csrf_token = NULL;
    }
    connection->state = new_state;
    switch (new_state)
    {
        case SMM_CONNECTION_CONNECTED:
            connection->last_error.code = SMM_ERROR_NONE;
            connection->last_error.message[0] = '\0';
            break;
        case SMM_CONNECTION_AUTHENTICATION_FAILURE:
            connection->last_error.code = SMM_ERROR_AUTH;
            snprintf (connection->last_error.message, sizeof (connection->last_error.message), "authentication failed");
            break;
        case SMM_CONNECTION_PROTOCOL_ERROR:
            connection->last_error.code = SMM_ERROR_PROTOCOL;
            snprintf (connection->last_error.message, sizeof (connection->last_error.message),
                      "CSRF token not found in login page");
            break;
        case SMM_CONNECTION_NO_HOST_CONNECTION:
            connection->last_error.code = SMM_ERROR_NETWORK;
            snprintf (connection->last_error.message, sizeof (connection->last_error.message),
                      "network failure fetching login page");
            break;
        default:
            connection->last_error.code = SMM_ERROR_SERVER;
            snprintf (connection->last_error.message, sizeof (connection->last_error.message), "login failed");
            break;
    }
    connection->login_in_progress = false;
    pthread_cond_broadcast (&connection->login_cond);
    pthread_mutex_unlock (&connection->lock);

    free (csrf_token);
    return res;
}

bool
smm_httpcode_is_redirect (long httpcode)
{
    /* The redirects we follow: 301 (e.g. Django's SECURE_SSL_REDIRECT
     * HTTP->HTTPS upgrade), 302 (login redirect), and 303. */
    return httpcode == HTTP_MOVED_PERMANENTLY || httpcode == HTTP_FOUND || httpcode == HTTP_SEE_OTHER;
}

bool
smm_https_upgrade_is_same_host (const char *http_host, const char *https_redirect)
{
    if (http_host == NULL || https_redirect == NULL)
        return false;
    if (strncmp (http_host, "http://", 7) != 0)
        return false;
    if (strncmp (https_redirect, "https://", 8) != 0)
        return false;

    const char *orig_host = http_host + 7;
    const char *redir_host = https_redirect + 8;

    /* Host ends at '/', '?', '#', or end of string */
    size_t orig_len = strcspn (orig_host, "/?#");
    size_t redir_len = strcspn (redir_host, "/?#");

    return orig_len == redir_len && strncmp (orig_host, redir_host, orig_len) == 0;
}

struct smm_curl_res_s *
smm_connection_curl_retrieve_url (smm_connection conn, const char *path, const char *post_data, struct buffer_s *buf,
                                  bool json)
{
    bool retry = true;
    int retries = 0;
    bool csrf_retried = false;
    struct smm_curl_res_s *res
        = smm_connection_curl_retrieve_url_r (conn, path, post_data, buf ? to_buffer : NULL, buf, json);

    while (retry && retries < 3 && res != NULL)
    {
        retry = false;
        retries++;
        if (res->success && smm_httpcode_is_redirect (res->httpcode) && res->redirect_url)
        {
            DEBUG ("Got redirected to (%s) accessing %s\n", res->redirect_url, path);
            /* It's possible we need to upgrade to https */
            if (smm_connection_try_https_upgrade (conn, res->redirect_url))
            {
                DEBUG ("Upgrading to https\n");
                retry = true;
            }

            if (!retry && strstr (res->redirect_url, "accounts/login") != NULL)
            {
                DEBUG ("Login required\n");
                if (smm_asset_connection_login (conn))
                {
                    retry = true;
                }
            }

            if (!retry)
            {
                DEBUG ("Redirected to %s\n", res->redirect_url);
            }
        }
        else if (post_data != NULL && res->httpcode == HTTP_FORBIDDEN && !csrf_retried)
        {
            /* Django answers a CSRF failure with 403, not a login redirect.
             * The usual cause is a CSRF token that has gone stale (e.g. the
             * server rotated it since this session's token was captured), so
             * re-authenticate once to refresh it and retry the POST; the retry
             * re-reads the freshly rotated token. Bounded to a single attempt
             * (csrf_retried) so a genuine permission denial, which a re-login
             * cannot fix, does not loop. */
            csrf_retried = true;
            DEBUG ("403 on POST to %s; refreshing session and retrying once\n", path);
            if (smm_asset_connection_login (conn))
            {
                retry = true;
            }
        }
        if (retry && retries < 3)
        {
            smm_curl_res_free (res);
            /* Discard anything buffered from the redirect response itself
             * (proxies often attach an HTML body to a 301/302); otherwise it
             * would be prepended to the body of the retried request. */
            smm_buffer_reset (buf);
            res = smm_connection_curl_retrieve_url_r (conn, path, post_data, buf ? to_buffer : NULL, buf, json);
        }
    }

    /* A successful 200 from a real API endpoint means the session is good: the
     * server answered the request rather than redirecting us to the login
     * page. Reflect that in the connection state, which otherwise stays NEW
     * when the first request happens to succeed without a login round-trip
     * (e.g. cookies already valid on the shared handle). The login-page fetch
     * itself uses the raw _r path, so it never reaches here and cannot flip the
     * state to CONNECTED before authentication actually completes. */
    if (res != NULL && res->success && res->httpcode == HTTP_SUCCESS)
    {
        pthread_mutex_lock (&conn->lock);
        conn->state = SMM_CONNECTION_CONNECTED;
        pthread_mutex_unlock (&conn->lock);
    }

    return res;
}
