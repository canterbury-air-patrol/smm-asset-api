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
/* cppcheck-suppress[constParameterPointer] */
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

struct smm_curl_res_s *
smm_connection_curl_retrieve_url_r (smm_connection conn, const char *path, const char *post_data,
                                    size_t (*write_func) (char *ptr, size_t size, size_t nmemb, void *userdata),
                                    void *write_data, bool json)
{
    struct smm_curl_res_s *res = NULL;
    CURL *curl = NULL;
    bool verify_tls = true;
    CURLSH *share = NULL;
    struct curl_slist *headers = NULL;
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
    share = conn->share;
    conn->refcount++;
    have_ref = true;

    if (asprintf (&res->full_uri, "%s%s", conn->host, path) < 0)
    {
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
    curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, SMM_CURL_CONNECT_TIMEOUT_SECS);
    curl_easy_setopt (curl, CURLOPT_TIMEOUT, SMM_CURL_TRANSFER_TIMEOUT_SECS);
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
        curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);
    }

    DEBUG ("fetching %s\n", res->full_uri);
    CURLcode cres = curl_easy_perform (curl);
    DEBUG ("curl returned %i\n", cres);
    res->success = (cres == CURLE_OK);

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

static size_t
populate_tidy (char *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t total;
    if (!smm_curl_chunk_size (size, nmemb, &total))
    {
        return 0;
    }
    tidyBufAppend ((TidyBuffer *)userdata, ptr, total);
    return total;
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
    TidyBuffer docbuf = { 0 };
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

    tidyBufInit (&docbuf);

    /* Use the raw (non-retrying) fetch so that a redirect on the login page
     * itself does not recurse back into smm_asset_connection_login. */
    struct smm_curl_res_s *res_get
        = smm_connection_curl_retrieve_url_r (connection, "/accounts/login/", NULL, populate_tidy, &docbuf, false);

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
        /* Drop anything the redirect response wrote into the tidy buffer. */
        tidyBufFree (&docbuf);
        tidyBufInit (&docbuf);
        res_get
            = smm_connection_curl_retrieve_url_r (connection, "/accounts/login/", NULL, populate_tidy, &docbuf, false);
    }

    if (res_get && res_get->success && res_get->httpcode == HTTP_SUCCESS)
    {
        /* find the input token with the csrfmiddlewaretoken */
        csrf_token = smm_parse_csrf_token ((const char *)docbuf.bp, docbuf.size);

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

    tidyBufFree (&docbuf);

    /* Publish the CSRF token, state, and last_error under the lock so that
     * readers always see a consistent view of all three fields. */
    pthread_mutex_lock (&connection->lock);
    if (csrf_token)
    {
        free (connection->csrfmiddlewaretoken);
        connection->csrfmiddlewaretoken = csrf_token;
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

    return res;
}
