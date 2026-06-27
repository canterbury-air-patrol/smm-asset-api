#include "smm-asset-internal.h"
#include "smm-asset.h"
#include <arpa/inet.h>
#include <check.h>
#include <locale.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

START_TEST (test_csrf_extraction)
{
    const char *html
        = "<html><body><input type=\"hidden\" name=\"csrfmiddlewaretoken\" value=\"abcd1234\"></body></html>";
    char *token = smm_parse_csrf_token (html, strlen (html));
    ck_assert_ptr_nonnull (token);
    ck_assert_str_eq (token, "abcd1234");
    free (token);
}
END_TEST

START_TEST (test_csrf_extraction_missing)
{
    const char *html = "<html><body><input type=\"hidden\" name=\"somethingelse\" value=\"abcd1234\"></body></html>";
    char *token = smm_parse_csrf_token (html, strlen (html));
    ck_assert_ptr_null (token);
}
END_TEST

START_TEST (test_csrf_extraction_invalid_chars)
{
    const char *html
        = "<html><body><input type=\"hidden\" name=\"csrfmiddlewaretoken\" value=\"abcd!@#$\"></body></html>";
    char *token = smm_parse_csrf_token (html, strlen (html));
    ck_assert_ptr_null (token);
}
END_TEST

START_TEST (test_csrf_extraction_too_long)
{
    char html[1024];
    char value[300];
    memset (value, 'a', 299);
    value[299] = '\0';
    snprintf (html, sizeof (html),
              "<html><body><input type=\"hidden\" name=\"csrfmiddlewaretoken\" value=\"%s\"></body></html>", value);

    char *token = smm_parse_csrf_token (html, strlen (html));
    ck_assert_ptr_null (token);
}
END_TEST

START_TEST (test_csrf_extraction_deeply_nested)
{
    /* Bury the token far below the recursion cap inside deeply nested
     * elements. The walker must stop descending without overflowing the
     * stack; the token, being out of reach, is simply not returned. */
    const size_t depth = 600;
    const char open[] = "<div>";
    const char close[] = "</div>";
    const char input[] = "<input type=\"hidden\" name=\"csrfmiddlewaretoken\" value=\"deep\">";
    size_t cap = depth * (sizeof (open) - 1 + sizeof (close) - 1) + sizeof (input) + 64;
    char *html = malloc (cap);
    ck_assert_ptr_nonnull (html);

    size_t pos = 0;
    for (size_t i = 0; i < depth; i++)
        pos += (size_t)snprintf (html + pos, cap - pos, "%s", open);
    pos += (size_t)snprintf (html + pos, cap - pos, "%s", input);
    for (size_t i = 0; i < depth; i++)
        pos += (size_t)snprintf (html + pos, cap - pos, "%s", close);

    char *token = smm_parse_csrf_token (html, strlen (html));
    ck_assert_ptr_null (token);

    free (token);
    free (html);
}
END_TEST

START_TEST (test_assets_parsing)
{
    const char *json = "{\"assets\": [{\"id\": 1, \"type_id\": 2, \"name\": \"Asset 1\", \"type_name\": \"Type "
                       "1\"}, {\"id\": 3, \"type_id\": 4, \"name\": \"Asset 2\", \"type_name\": \"Type 2\"}]}";
    smm_assets assets;
    size_t count;
    bool res = smm_parse_assets (NULL, json, strlen (json), &assets, &count);

    ck_assert_uint_eq (res, true);
    ck_assert_uint_eq (count, 2);
    ck_assert_str_eq (smm_asset_name (assets[0]), "Asset 1");
    ck_assert_str_eq (smm_asset_type (assets[0]), "Type 1");
    ck_assert_str_eq (smm_asset_name (assets[1]), "Asset 2");
    ck_assert_str_eq (smm_asset_type (assets[1]), "Type 2");

    smm_asset_free_assets (assets, count);
}
END_TEST

START_TEST (test_assets_parsing_empty)
{
    const char *json = "{\"assets\": []}";
    smm_assets assets;
    size_t count;
    bool res = smm_parse_assets (NULL, json, strlen (json), &assets, &count);

    ck_assert_uint_eq (res, true);
    ck_assert_uint_eq (count, 0);
    ck_assert_ptr_null (assets);
}
END_TEST

START_TEST (test_assets_parsing_invalid)
{
    const char *json = "{\"not_assets\": []}";
    smm_assets assets;
    size_t count;
    bool res = smm_parse_assets (NULL, json, strlen (json), &assets, &count);

    ck_assert_uint_eq (res, false);
    ck_assert_uint_eq (count, 0);
}
END_TEST

START_TEST (test_assets_parsing_missing_type_id)
{
    const char *json = "{\"assets\": [{\"id\": 1, \"name\": \"Asset 1\", \"type_name\": \"Type 1\"}]}";
    smm_assets assets;
    size_t count;
    bool res = smm_parse_assets (NULL, json, strlen (json), &assets, &count);

    ck_assert_uint_eq (res, true);
    ck_assert_uint_eq (count, 1);
    ck_assert_str_eq (smm_asset_name (assets[0]), "Asset 1");
    smm_asset_free_assets (assets, count);
}
END_TEST

START_TEST (test_assets_parsing_missing_id)
{
    /* An asset with no id cannot be addressed in request URLs, so it is
     * dropped; the surrounding parse still succeeds. */
    const char *json = "{\"assets\": [{\"type_id\": 2, \"name\": \"Asset 1\", \"type_name\": \"Type 1\"}]}";
    smm_assets assets;
    size_t count;
    bool res = smm_parse_assets (NULL, json, strlen (json), &assets, &count);

    ck_assert_uint_eq (res, true);
    ck_assert_uint_eq (count, 0);
    ck_assert_ptr_null (assets);
}
END_TEST

START_TEST (test_assets_parsing_noninteger_id)
{
    /* A non-integer id is treated the same as a missing id. */
    const char *json = "{\"assets\": [{\"id\": \"oops\", \"type_id\": 2, \"name\": \"Asset 1\", \"type_name\": "
                       "\"Type 1\"}]}";
    smm_assets assets;
    size_t count;
    bool res = smm_parse_assets (NULL, json, strlen (json), &assets, &count);

    ck_assert_uint_eq (res, true);
    ck_assert_uint_eq (count, 0);
    ck_assert_ptr_null (assets);
}
END_TEST

START_TEST (test_assets_parsing_noninteger_type_id)
{
    /* type_id is optional; a non-integer value is tolerated (left at the
     * sentinel) and does not drop an otherwise valid asset. */
    const char *json = "{\"assets\": [{\"id\": 1, \"type_id\": \"oops\", \"name\": \"Asset 1\", \"type_name\": "
                       "\"Type 1\"}]}";
    smm_assets assets;
    size_t count;
    bool res = smm_parse_assets (NULL, json, strlen (json), &assets, &count);

    ck_assert_uint_eq (res, true);
    ck_assert_uint_eq (count, 1);
    ck_assert_str_eq (smm_asset_name (assets[0]), "Asset 1");
    smm_asset_free_assets (assets, count);
}
END_TEST

START_TEST (test_assets_parsing_drops_only_invalid)
{
    /* A valid asset is kept even when another entry in the array lacks an id. */
    const char *json = "{\"assets\": [{\"name\": \"No Id\"}, {\"id\": 7, \"type_id\": 2, \"name\": \"Good\", "
                       "\"type_name\": \"Type 1\"}]}";
    smm_assets assets;
    size_t count;
    bool res = smm_parse_assets (NULL, json, strlen (json), &assets, &count);

    ck_assert_uint_eq (res, true);
    ck_assert_uint_eq (count, 1);
    ck_assert_str_eq (smm_asset_name (assets[0]), "Good");
    smm_asset_free_assets (assets, count);
}
END_TEST

START_TEST (test_command_parsing_goto)
{
    const char *json = "{\"action\": \"GOTO\", \"latitude\": -43.5, \"longitude\": 172.6}";
    smm_asset_command cmd;
    double lat = 0, lon = 0;
    bool res = smm_parse_command (json, strlen (json), &cmd, &lat, &lon);

    ck_assert_uint_eq (res, true);
    ck_assert_int_eq (cmd, SMM_COMMAND_GOTO);
    ck_assert_ldouble_eq_tol (lat, -43.5, 0.0001);
    ck_assert_ldouble_eq_tol (lon, 172.6, 0.0001);
}
END_TEST

START_TEST (test_command_parsing_goto_integer_coords)
{
    const char *json = "{\"action\": \"GOTO\", \"latitude\": -43, \"longitude\": 172}";
    smm_asset_command cmd;
    double lat = 0, lon = 0;
    bool res = smm_parse_command (json, strlen (json), &cmd, &lat, &lon);

    ck_assert_uint_eq (res, true);
    ck_assert_int_eq (cmd, SMM_COMMAND_GOTO);
    ck_assert_ldouble_eq_tol (lat, -43.0, 0.0001);
    ck_assert_ldouble_eq_tol (lon, 172.0, 0.0001);
}
END_TEST

START_TEST (test_command_parsing_goto_mixed_lat_real_lon_int)
{
    const char *json = "{\"action\": \"GOTO\", \"latitude\": -43.75, \"longitude\": 172}";
    smm_asset_command cmd;
    double lat = 0, lon = 0;
    bool res = smm_parse_command (json, strlen (json), &cmd, &lat, &lon);

    ck_assert_uint_eq (res, true);
    ck_assert_int_eq (cmd, SMM_COMMAND_GOTO);
    ck_assert_ldouble_eq_tol (lat, -43.75, 0.0001);
    ck_assert_ldouble_eq_tol (lon, 172.0, 0.0001);
}
END_TEST

START_TEST (test_command_parsing_goto_mixed_lat_int_lon_real)
{
    const char *json = "{\"action\": \"GOTO\", \"latitude\": -43, \"longitude\": 172.5}";
    smm_asset_command cmd;
    double lat = 0, lon = 0;
    bool res = smm_parse_command (json, strlen (json), &cmd, &lat, &lon);

    ck_assert_uint_eq (res, true);
    ck_assert_int_eq (cmd, SMM_COMMAND_GOTO);
    ck_assert_ldouble_eq_tol (lat, -43.0, 0.0001);
    ck_assert_ldouble_eq_tol (lon, 172.5, 0.0001);
}
END_TEST

START_TEST (test_command_parsing_rtl)
{
    const char *json = "{\"action\": \"RTL\"}";
    smm_asset_command cmd;
    double lat = 0, lon = 0;
    bool res = smm_parse_command (json, strlen (json), &cmd, &lat, &lon);

    ck_assert_uint_eq (res, true);
    ck_assert_int_eq (cmd, SMM_COMMAND_RTL);
}
END_TEST

START_TEST (test_command_parsing_unknown)
{
    const char *json = "{\"action\": \"INVALID\"}";
    smm_asset_command cmd;
    double lat = 0, lon = 0;
    bool res = smm_parse_command (json, strlen (json), &cmd, &lat, &lon);

    ck_assert_uint_eq (res, true);
    ck_assert_int_eq (cmd, SMM_COMMAND_UNKNOWN);
}
END_TEST

START_TEST (test_waypoint_parsing)
{
    const char *json = "{\"features\": [{\"geometry\": {\"coordinates\": [[172.6, -43.5], [172.7, -43.6]]}}]}";
    smm_waypoints waypoints;
    size_t count;
    bool res = smm_parse_waypoints (json, strlen (json), &waypoints, &count);

    ck_assert_uint_eq (res, true);
    ck_assert_uint_eq (count, 2);
    ck_assert_ldouble_eq_tol (waypoints[0]->lat, -43.5, 0.0001);
    ck_assert_ldouble_eq_tol (waypoints[0]->lon, 172.6, 0.0001);
    ck_assert_ldouble_eq_tol (waypoints[1]->lat, -43.6, 0.0001);
    ck_assert_ldouble_eq_tol (waypoints[1]->lon, 172.7, 0.0001);

    smm_waypoints_free (waypoints, count);
}
END_TEST

START_TEST (test_search_sweep_width)
{
    struct smm_search_s search;
    memset (&search, 0, sizeof (search));
    search.sweep_width = 100;
    ck_assert_uint_eq (smm_search_sweep_width (&search), 100);
}
END_TEST

START_TEST (test_get_search_absolute_url_ignored)
{
    const char *json = "{\"object_url\": \"https://example.com/search/1/\", \"distance\": 10, \"length\": 100, "
                       "\"sweep_width\": 50}";
    smm_search search = smm_parse_search_json (NULL, json, strlen (json));
    ck_assert_ptr_null (search);
}
END_TEST

START_TEST (test_get_search_nonstring_object_url_returns_null)
{
    const char *json = "{\"object_url\": 123, \"distance\": 10, \"length\": 100, \"sweep_width\": 50}";
    smm_search search = smm_parse_search_json (NULL, json, strlen (json));
    ck_assert_ptr_null (search);
}
END_TEST

START_TEST (test_get_search_missing_object_url_returns_null)
{
    const char *json = "{\"distance\": 10, \"length\": 100, \"sweep_width\": 50}";
    smm_search search = smm_parse_search_json (NULL, json, strlen (json));
    ck_assert_ptr_null (search);
}
END_TEST

START_TEST (test_get_search_http_absolute_url_ignored)
{
    const char *json
        = "{\"object_url\": \"http://example.com/search/1/\", \"distance\": 10, \"length\": 100, \"sweep_width\": 50}";
    smm_search search = smm_parse_search_json (NULL, json, strlen (json));
    ck_assert_ptr_null (search);
}
END_TEST

START_TEST (test_get_search_relative_url_accepted)
{
    const char *json = "{\"object_url\": \"/search/1/\", \"distance\": 10, \"length\": 100, \"sweep_width\": 50}";
    smm_search search = smm_parse_search_json (NULL, json, strlen (json));
    ck_assert_ptr_nonnull (search);
    ck_assert_uint_eq (smm_search_distance (search), 10);
    ck_assert_uint_eq (smm_search_length (search), 100);
    ck_assert_uint_eq (smm_search_sweep_width (search), 50);
    smm_search_destroy (search);
}
END_TEST

START_TEST (test_get_search_real_numeric_fields)
{
    /* The server contract does not guarantee integers; a real-valued
     * distance/length/sweep_width must still be read (json_integer_value
     * would have returned 0). */
    const char *json = "{\"object_url\": \"/search/1/\", \"distance\": 10.7, \"length\": 100.9, \"sweep_width\": 50.5}";
    smm_search search = smm_parse_search_json (NULL, json, strlen (json));
    ck_assert_ptr_nonnull (search);
    ck_assert_uint_eq (smm_search_distance (search), 10);
    ck_assert_uint_eq (smm_search_length (search), 100);
    ck_assert_uint_eq (smm_search_sweep_width (search), 50);
    smm_search_destroy (search);
}
END_TEST

START_TEST (test_get_search_negative_numeric_clamps_zero)
{
    const char *json = "{\"object_url\": \"/search/1/\", \"distance\": -5, \"length\": 100, \"sweep_width\": 50}";
    smm_search search = smm_parse_search_json (NULL, json, strlen (json));
    ck_assert_ptr_nonnull (search);
    ck_assert_uint_eq (smm_search_distance (search), 0);
    smm_search_destroy (search);
}
END_TEST

START_TEST (test_search_accept_null_conn)
{
    struct smm_search_s search_s;
    memset (&search_s, 0, sizeof (search_s));
    search_s.conn = NULL;
    search_s.asset_id = 1;
    search_s.url = strdup ("/search/1/");
    bool r = smm_search_accept (&search_s);
    ck_assert_int_eq (r, false);
    free (search_s.url);
}
END_TEST

START_TEST (test_search_accept_null_search)
{
    bool r = smm_search_accept (NULL);
    ck_assert_int_eq (r, false);
}
END_TEST

START_TEST (test_search_complete_null_search)
{
    bool r = smm_search_complete (NULL);
    ck_assert_int_eq (r, false);
}
END_TEST

START_TEST (test_search_get_waypoints_null_search)
{
    smm_waypoints waypoints = NULL;
    size_t count = 0;
    bool r = smm_search_get_waypoints (NULL, &waypoints, &count);
    ck_assert_int_eq (r, false);
}
END_TEST

START_TEST (test_report_position_null_asset)
{
    bool r = smm_asset_report_position (NULL, -43.5, 172.6, 100, 270, 3);
    ck_assert_int_eq (r, false);
}
END_TEST

START_TEST (test_get_search_null_asset)
{
    smm_search s = smm_asset_get_search (NULL, -43.5, 172.6);
    ck_assert_ptr_null (s);
}
END_TEST

START_TEST (test_last_command_null_asset)
{
    smm_asset_command cmd = smm_asset_last_command (NULL);
    ck_assert_int_eq (cmd, SMM_COMMAND_UNKNOWN);
}
END_TEST

START_TEST (test_last_goto_pos_null_asset)
{
    double lat = 1.0, lon = 2.0;
    bool r = smm_asset_last_goto_pos (NULL, &lat, &lon);
    ck_assert_int_eq (r, false);
}
END_TEST

START_TEST (test_set_command_null_asset)
{
    /* must not crash */
    smm_asset_set_command_from_plaintext (NULL, "Continue", 8);
}
END_TEST

START_TEST (test_asset_outlives_connection)
{
    smm_connection conn = smm_asset_connect ("http://localhost/", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    smm_asset asset = smm_asset_create (conn, "A", "T", 1, 1);
    ck_assert_ptr_nonnull (asset);
    smm_connection_close (conn);
    /* asset holds its own reference; the connection must not be freed yet */
    ck_assert_str_eq (smm_asset_name (asset), "A");
    smm_asset_free_asset (asset);
    /* connection is freed here when asset's ref is dropped — no double-free */
}
END_TEST

START_TEST (test_report_position_null_conn)
{
    smm_asset asset = smm_asset_create (NULL, "A", "T", 1, 1);
    ck_assert_ptr_nonnull (asset);
    bool r = smm_asset_report_position (asset, -43.5, 172.6, 100, 270, 3);
    ck_assert_int_eq (r, false);
    smm_asset_free_asset (asset);
}
END_TEST

START_TEST (test_set_command_from_plaintext_continue)
{
    smm_asset asset = smm_asset_create (NULL, "A", "T", 1, 1);
    ck_assert_ptr_nonnull (asset);
    smm_asset_set_command_from_plaintext (asset, "Continue", 8);
    ck_assert_int_eq (smm_asset_last_command (asset), SMM_COMMAND_CONTINUE);
    smm_asset_free_asset (asset);
}
END_TEST

START_TEST (test_set_command_from_plaintext_other)
{
    smm_asset asset = smm_asset_create (NULL, "A", "T", 1, 1);
    ck_assert_ptr_nonnull (asset);
    smm_asset_set_command_from_plaintext (asset, "Other", 5);
    ck_assert_int_eq (smm_asset_last_command (asset), SMM_COMMAND_NONE);
    smm_asset_free_asset (asset);
}
END_TEST

START_TEST (test_set_command_from_plaintext_null)
{
    smm_asset asset = smm_asset_create (NULL, "A", "T", 1, 1);
    ck_assert_ptr_nonnull (asset);
    smm_asset_set_command_from_plaintext (asset, NULL, 0);
    ck_assert_int_eq (smm_asset_last_command (asset), SMM_COMMAND_NONE);
    smm_asset_free_asset (asset);
}
END_TEST

START_TEST (test_set_command_from_plaintext_zero_length)
{
    smm_asset asset = smm_asset_create (NULL, "A", "T", 1, 1);
    ck_assert_ptr_nonnull (asset);
    smm_asset_set_command_from_plaintext (asset, "", 0);
    ck_assert_int_eq (smm_asset_last_command (asset), SMM_COMMAND_NONE);
    smm_asset_free_asset (asset);
}
END_TEST

START_TEST (test_set_command_from_plaintext_with_trailing)
{
    smm_asset asset = smm_asset_create (NULL, "A", "T", 1, 1);
    ck_assert_ptr_nonnull (asset);
    smm_asset_set_command_from_plaintext (asset, "Continue\0garbage", 16);
    ck_assert_int_eq (smm_asset_last_command (asset), SMM_COMMAND_CONTINUE);
    smm_asset_free_asset (asset);
}
END_TEST

START_TEST (test_build_position_url_heading)
{
    char *url = smm_asset_build_position_url (42, -43.5, 172.6, 100, 270, 3);
    ck_assert_ptr_nonnull (url);
    ck_assert_ptr_nonnull (strstr (url, "heading="));
    ck_assert_ptr_null (strstr (url, "bearing="));
    free (url);
}
END_TEST

/* Coordinates must always use '.' as the decimal separator regardless of the
 * caller's LC_NUMERIC. We assert this under the current locale (always) and,
 * when a comma-decimal locale is installed, under that locale too. */
START_TEST (test_build_position_url_locale_independent)
{
    char *url = smm_asset_build_position_url (42, -43.5, 172.6, 100, 270, 3);
    ck_assert_ptr_nonnull (url);
    ck_assert_ptr_nonnull (strstr (url, "lat=-43.500000"));
    ck_assert_ptr_nonnull (strstr (url, "lon=172.600000"));
    free (url);

    /* Try a few locales that format decimals with a comma. If none are
     * installed (e.g. a minimal CI image) the loop is a no-op and the
     * assertions above still guard the common case. */
    const char *comma_locales[] = { "de_DE.UTF-8", "de_DE.utf8", "de_DE", "fr_FR.UTF-8", "nl_NL.UTF-8" };
    for (size_t i = 0; i < sizeof (comma_locales) / sizeof (comma_locales[0]); i++)
    {
        locale_t loc = newlocale (LC_NUMERIC_MASK, comma_locales[i], (locale_t)0);
        if (loc == (locale_t)0)
        {
            continue;
        }
        locale_t old = uselocale (loc);
        url = smm_asset_build_position_url (42, -43.5, 172.6, 100, 270, 3);
        uselocale (old);
        freelocale (loc);

        ck_assert_ptr_nonnull (url);
        ck_assert_ptr_nonnull (strstr (url, "lat=-43.500000"));
        ck_assert_ptr_null (strstr (url, ","));
        free (url);
        break;
    }
}
END_TEST

START_TEST (test_asset_get_last_error_null)
{
    char msg[16] = "sentinel";
    ck_assert_int_eq (smm_asset_get_last_error (NULL, msg, sizeof (msg)), SMM_ERROR_NONE);
    ck_assert_str_eq (msg, "");
}
END_TEST

START_TEST (test_asset_get_last_error_initial)
{
    smm_asset asset = smm_asset_create (NULL, "A", "T", 1, 1);
    ck_assert_ptr_nonnull (asset);
    char msg[64];
    ck_assert_int_eq (smm_asset_get_last_error (asset, msg, sizeof (msg)), SMM_ERROR_NONE);
    ck_assert_str_eq (msg, "");
    smm_asset_free_asset (asset);
}
END_TEST

START_TEST (test_search_get_last_error_null)
{
    char msg[16] = "sentinel";
    ck_assert_int_eq (smm_search_get_last_error (NULL, msg, sizeof (msg)), SMM_ERROR_NONE);
    ck_assert_str_eq (msg, "");
}
END_TEST

START_TEST (test_search_get_last_error_initial)
{
    const char *json = "{\"object_url\": \"/search/1/\", \"distance\": 10, \"length\": 100, \"sweep_width\": 50}";
    smm_search search = smm_parse_search_json (NULL, json, strlen (json));
    ck_assert_ptr_nonnull (search);
    char msg[64];
    ck_assert_int_eq (smm_search_get_last_error (search, msg, sizeof (msg)), SMM_ERROR_NONE);
    ck_assert_str_eq (msg, "");
    smm_search_destroy (search);
}
END_TEST

START_TEST (test_report_position_sets_asset_error_not_conn)
{
    /* With a NULL conn the network call fails; the error must land on the
     * asset, not the connection, so two assets sharing a connection cannot
     * clobber each other's error state. */
    smm_asset asset = smm_asset_create (NULL, "A", "T", 1, 1);
    ck_assert_ptr_nonnull (asset);
    smm_asset_report_position (asset, -43.5, 172.6, 100, 270, 3);
    char msg[256];
    ck_assert_int_ne (smm_asset_get_last_error (asset, msg, sizeof (msg)), SMM_ERROR_NONE);
    /* A real error must come with a human-readable description. */
    ck_assert_int_gt (strlen (msg), 0);
    smm_asset_free_asset (asset);
}
END_TEST

START_TEST (test_get_last_error_message_truncated_to_buffer)
{
    /* A message longer than the caller's buffer is truncated and still
     * NUL-terminated; the code is unaffected. */
    smm_asset asset = smm_asset_create (NULL, "A", "T", 1, 1);
    ck_assert_ptr_nonnull (asset);
    smm_asset_report_position (asset, -43.5, 172.6, 100, 270, 3);
    char tiny[4];
    ck_assert_int_ne (smm_asset_get_last_error (asset, tiny, sizeof (tiny)), SMM_ERROR_NONE);
    ck_assert_uint_eq (strlen (tiny), sizeof (tiny) - 1);
    /* NULL message / zero length only query the code. */
    ck_assert_int_ne (smm_asset_get_last_error (asset, NULL, 0), SMM_ERROR_NONE);
    ck_assert_int_ne (smm_asset_get_last_error (asset, tiny, 0), SMM_ERROR_NONE);
    smm_asset_free_asset (asset);
}
END_TEST

START_TEST (test_get_assets_null_outparams_record_invalid_arg)
{
    smm_connection conn = smm_asset_connect ("http://localhost/", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    smm_assets assets;
    size_t count;
    ck_assert_int_eq (smm_asset_get_assets (conn, NULL, &count), false);
    ck_assert_int_eq (smm_connection_get_last_error (conn, NULL, 0), SMM_ERROR_INVALID_ARG);
    ck_assert_int_eq (smm_asset_get_assets (conn, &assets, NULL), false);
    ck_assert_int_eq (smm_connection_get_last_error (conn, NULL, 0), SMM_ERROR_INVALID_ARG);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_get_waypoints_null_outparams_record_invalid_arg)
{
    const char *json = "{\"object_url\": \"/search/1/\", \"distance\": 10, \"length\": 100, \"sweep_width\": 50}";
    smm_search search = smm_parse_search_json (NULL, json, strlen (json));
    ck_assert_ptr_nonnull (search);
    smm_waypoints waypoints;
    size_t count;
    ck_assert_int_eq (smm_search_get_waypoints (search, NULL, &count), false);
    ck_assert_int_eq (smm_search_get_last_error (search, NULL, 0), SMM_ERROR_INVALID_ARG);
    ck_assert_int_eq (smm_search_get_waypoints (search, &waypoints, NULL), false);
    ck_assert_int_eq (smm_search_get_last_error (search, NULL, 0), SMM_ERROR_INVALID_ARG);
    smm_search_destroy (search);
}
END_TEST

START_TEST (test_search_action_sets_search_error_not_conn)
{
    /* With conn==NULL the network call fails; the error must land on the
     * search object. */
    struct smm_search_s search_s;
    memset (&search_s, 0, sizeof (search_s));
    search_s.conn = NULL;
    search_s.asset_id = 1;
    search_s.url = strdup ("/search/1/");
    smm_search_accept (&search_s);
    ck_assert_int_ne (smm_search_get_last_error (&search_s, NULL, 0), SMM_ERROR_NONE);
    free (search_s.url);
}
END_TEST

START_TEST (test_url_path_safe_valid)
{
    ck_assert_int_eq (smm_url_path_is_safe ("/search/1/"), true);
    ck_assert_int_eq (smm_url_path_is_safe ("/search/42/begin/"), true);
    ck_assert_int_eq (smm_url_path_is_safe ("/"), true);
}
END_TEST

START_TEST (test_url_path_safe_dotdot)
{
    ck_assert_int_eq (smm_url_path_is_safe ("/search/1/../../admin/"), false);
    ck_assert_int_eq (smm_url_path_is_safe ("/.."), false);
}
END_TEST

START_TEST (test_url_path_safe_query) { ck_assert_int_eq (smm_url_path_is_safe ("/search/1/?injected=evil"), false); }
END_TEST

START_TEST (test_url_path_safe_fragment) { ck_assert_int_eq (smm_url_path_is_safe ("/search/1/#frag"), false); }
END_TEST

START_TEST (test_url_path_safe_encoded) { ck_assert_int_eq (smm_url_path_is_safe ("/search/%2e%2e/admin/"), false); }
END_TEST

START_TEST (test_url_path_safe_absolute)
{
    ck_assert_int_eq (smm_url_path_is_safe ("http://example.com/search/1/"), false);
    ck_assert_int_eq (smm_url_path_is_safe ("https://example.com/search/1/"), false);
}
END_TEST

START_TEST (test_url_path_safe_null) { ck_assert_int_eq (smm_url_path_is_safe (NULL), false); }
END_TEST

START_TEST (test_to_buffer_accumulates)
{
    struct buffer_s buf = { NULL, 0 };
    char chunk1[] = "abc";
    char chunk2[] = "de";
    ck_assert_uint_eq (to_buffer (chunk1, 1, 3, &buf), 3);
    ck_assert_uint_eq (to_buffer (chunk2, 1, 2, &buf), 2);
    ck_assert_uint_eq (buf.bytes, 5);
    ck_assert_str_eq (buf.data, "abcde");
    free (buf.data);
}
END_TEST

START_TEST (test_to_buffer_rejects_oversized_chunk)
{
    /* A single chunk larger than the cap is refused without allocating. */
    struct buffer_s buf = { NULL, 0 };
    char chunk[] = "x";
    ck_assert_uint_eq (to_buffer (chunk, 1, SMM_MAX_RESPONSE_BYTES + 1, &buf), 0);
    ck_assert_ptr_null (buf.data);
}
END_TEST

START_TEST (test_to_buffer_rejects_when_full)
{
    /* Once bytes have reached the cap, further writes are refused. */
    struct buffer_s buf = { NULL, SMM_MAX_RESPONSE_BYTES };
    char chunk[] = "x";
    ck_assert_uint_eq (to_buffer (chunk, 1, 1, &buf), 0);
}
END_TEST

START_TEST (test_to_buffer_rejects_size_overflow)
{
    /* size * nmemb would overflow size_t; the callback must refuse the chunk
     * rather than wrap to a small length that defeats the cap check. */
    struct buffer_s buf = { NULL, 0 };
    char chunk[] = "x";
    ck_assert_uint_eq (to_buffer (chunk, SIZE_MAX, 2, &buf), 0);
    ck_assert_ptr_null (buf.data);
}
END_TEST

START_TEST (test_buffer_reset_discards_content)
{
    /* The retry loop resets the buffer between attempts so a redirect body
     * is not prepended to the body of the retried request. After a reset the
     * buffer must accumulate only the new content. */
    struct buffer_s buf = { NULL, 0 };
    char redirect_body[] = "<html>301 Moved Permanently</html>";
    char real_body[] = "{\"assets\": []}";
    ck_assert_uint_eq (to_buffer (redirect_body, 1, sizeof (redirect_body) - 1, &buf), sizeof (redirect_body) - 1);
    smm_buffer_reset (&buf);
    ck_assert_ptr_null (buf.data);
    ck_assert_uint_eq (buf.bytes, 0);
    ck_assert_uint_eq (to_buffer (real_body, 1, sizeof (real_body) - 1, &buf), sizeof (real_body) - 1);
    ck_assert_str_eq (buf.data, "{\"assets\": []}");
    free (buf.data);
}
END_TEST

START_TEST (test_buffer_reset_null_safe)
{
    struct buffer_s buf = { NULL, 0 };
    smm_buffer_reset (&buf); /* empty buffer */
    ck_assert_ptr_null (buf.data);
    smm_buffer_reset (NULL); /* must not crash */
}
END_TEST

START_TEST (test_content_type_is_json_plain) { ck_assert_int_eq (smm_content_type_is_json ("application/json"), true); }
END_TEST

START_TEST (test_content_type_is_json_with_charset)
{
    ck_assert_int_eq (smm_content_type_is_json ("application/json; charset=utf-8"), true);
    ck_assert_int_eq (smm_content_type_is_json ("application/json;charset=utf-8"), true);
    ck_assert_int_eq (smm_content_type_is_json ("application/json \t; charset=utf-8"), true);
}
END_TEST

START_TEST (test_content_type_is_json_case_insensitive)
{
    ck_assert_int_eq (smm_content_type_is_json ("Application/JSON"), true);
    ck_assert_int_eq (smm_content_type_is_json ("APPLICATION/JSON; CHARSET=UTF-8"), true);
}
END_TEST

START_TEST (test_content_type_is_json_leading_whitespace)
{
    ck_assert_int_eq (smm_content_type_is_json ("  application/json"), true);
}
END_TEST

START_TEST (test_content_type_is_json_rejects_lookalikes)
{
    ck_assert_int_eq (smm_content_type_is_json ("application/json-patch+json"), false);
    ck_assert_int_eq (smm_content_type_is_json ("application/jsonx"), false);
    ck_assert_int_eq (smm_content_type_is_json ("text/html"), false);
    ck_assert_int_eq (smm_content_type_is_json (""), false);
    ck_assert_int_eq (smm_content_type_is_json (NULL), false);
}
END_TEST

START_TEST (test_get_search_dotdot_url_rejected)
{
    const char *json = "{\"object_url\": \"/search/1/../../admin/\", \"distance\": 10, \"length\": 100, "
                       "\"sweep_width\": 50}";
    smm_search search = smm_parse_search_json (NULL, json, strlen (json));
    ck_assert_ptr_null (search);
}
END_TEST

START_TEST (test_get_search_query_url_rejected)
{
    const char *json
        = "{\"object_url\": \"/search/1/?injected=x\", \"distance\": 10, \"length\": 100, \"sweep_width\": 50}";
    smm_search search = smm_parse_search_json (NULL, json, strlen (json));
    ck_assert_ptr_null (search);
}
END_TEST

START_TEST (test_get_search_encoded_url_rejected)
{
    const char *json = "{\"object_url\": \"/search/%2e%2e/admin/\", \"distance\": 10, \"length\": 100, "
                       "\"sweep_width\": 50}";
    smm_search search = smm_parse_search_json (NULL, json, strlen (json));
    ck_assert_ptr_null (search);
}
END_TEST

START_TEST (test_curl_timeout_constants)
{
    /* Verify timeout macros are positive and connect <= transfer */
    ck_assert_int_gt (SMM_CURL_CONNECT_TIMEOUT_SECS, 0);
    ck_assert_int_gt (SMM_CURL_TRANSFER_TIMEOUT_SECS, 0);
    ck_assert_int_le (SMM_CURL_CONNECT_TIMEOUT_SECS, SMM_CURL_TRANSFER_TIMEOUT_SECS);
}
END_TEST

START_TEST (test_httpcode_is_redirect)
{
    ck_assert_int_eq (smm_httpcode_is_redirect (301), true);
    ck_assert_int_eq (smm_httpcode_is_redirect (302), true);
    ck_assert_int_eq (smm_httpcode_is_redirect (303), true);
}
END_TEST

START_TEST (test_httpcode_is_not_redirect)
{
    ck_assert_int_eq (smm_httpcode_is_redirect (200), false);
    ck_assert_int_eq (smm_httpcode_is_redirect (304), false);
    ck_assert_int_eq (smm_httpcode_is_redirect (307), false);
    ck_assert_int_eq (smm_httpcode_is_redirect (400), false);
    ck_assert_int_eq (smm_httpcode_is_redirect (0), false);
}
END_TEST

START_TEST (test_https_upgrade_same_host)
{
    ck_assert_int_eq (smm_https_upgrade_is_same_host ("http://example.com", "https://example.com/login/"), true);
}
END_TEST

START_TEST (test_https_upgrade_same_host_with_port)
{
    ck_assert_int_eq (smm_https_upgrade_is_same_host ("http://example.com:8080", "https://example.com:8080/login/"),
                      true);
}
END_TEST

START_TEST (test_https_upgrade_different_host)
{
    ck_assert_int_eq (smm_https_upgrade_is_same_host ("http://example.com", "https://evil.com/login/"), false);
}
END_TEST

START_TEST (test_https_upgrade_subdomain)
{
    ck_assert_int_eq (smm_https_upgrade_is_same_host ("http://example.com", "https://evil.example.com/login/"), false);
}
END_TEST

START_TEST (test_https_upgrade_different_port)
{
    ck_assert_int_eq (smm_https_upgrade_is_same_host ("http://example.com:80", "https://example.com:443/login/"),
                      false);
}
END_TEST

START_TEST (test_https_upgrade_null_args)
{
    ck_assert_int_eq (smm_https_upgrade_is_same_host (NULL, "https://example.com/"), false);
    ck_assert_int_eq (smm_https_upgrade_is_same_host ("http://example.com", NULL), false);
}
END_TEST

START_TEST (test_https_upgrade_non_http_http_host)
{
    ck_assert_int_eq (smm_https_upgrade_is_same_host ("ftp://example.com", "https://example.com/"), false);
    ck_assert_int_eq (smm_https_upgrade_is_same_host ("example.com", "https://example.com/"), false);
    ck_assert_int_eq (smm_https_upgrade_is_same_host ("", "https://example.com/"), false);
}
END_TEST

START_TEST (test_try_https_upgrade_switches_host)
{
    smm_connection conn = smm_asset_connect ("http://example.com", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    ck_assert_int_eq (smm_connection_try_https_upgrade (conn, "https://example.com/accounts/login/"), true);
    ck_assert_str_eq (conn->host, "https://example.com");
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_try_https_upgrade_rejects_other_host)
{
    smm_connection conn = smm_asset_connect ("http://example.com", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    ck_assert_int_eq (smm_connection_try_https_upgrade (conn, "https://evil.com/accounts/login/"), false);
    ck_assert_str_eq (conn->host, "http://example.com");
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_try_https_upgrade_null_args)
{
    smm_connection conn = smm_asset_connect ("http://example.com", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    ck_assert_int_eq (smm_connection_try_https_upgrade (conn, NULL), false);
    ck_assert_int_eq (smm_connection_try_https_upgrade (NULL, "https://example.com/"), false);
    ck_assert_str_eq (conn->host, "http://example.com");
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_https_upgrade_already_https)
{
    /* conn is already https — smm_https_upgrade_is_same_host must return false
     * since http_host does not start with "http://" */
    ck_assert_int_eq (smm_https_upgrade_is_same_host ("https://example.com", "https://example.com/login/"), false);
}
END_TEST

/* Minimal single-purpose HTTP server for the eager-login upgrade test: the
 * first connection is answered with a same-host https 301 (carrying an HTML
 * body, as proxies do); the second connection — the upgraded retry, which
 * arrives speaking TLS — is closed immediately so the login fails fast. */
struct redirect_server_s
{
    int listen_fd;
    uint16_t port;
};

static void *
redirect_server_thread (void *arg)
{
    struct redirect_server_s *srv = (struct redirect_server_s *)arg;

    int fd = accept (srv->listen_fd, NULL, NULL);
    if (fd >= 0)
    {
        char req[1024];
        /* Drain the request; its content does not affect the canned response.
         * glibc declares read/write warn_unused_result, and gcc ignores a
         * plain (void) cast for those, so "(void)!" is needed to keep
         * -Wunused-result (via -Wall, with --enable-werror) quiet. */
        (void)!read (fd, req, sizeof (req));
        const char body[] = "<html><body>301 Moved Permanently</body></html>";
        char resp[512];
        int n = snprintf (resp, sizeof (resp),
                          "HTTP/1.1 301 Moved Permanently\r\n"
                          "Location: https://127.0.0.1:%u/accounts/login/\r\n"
                          "Content-Type: text/html\r\n"
                          "Content-Length: %zu\r\n"
                          "Connection: close\r\n"
                          "\r\n"
                          "%s",
                          srv->port, sizeof (body) - 1, body);
        (void)!write (fd, resp, (size_t)n);
        close (fd);
    }

    /* The upgraded retry: close without answering the TLS handshake. If the
     * retry never happens (regression), this accept blocks and the test is
     * failed by the check timeout. */
    fd = accept (srv->listen_fd, NULL, NULL);
    if (fd >= 0)
    {
        close (fd);
    }
    return NULL;
}

START_TEST (test_eager_login_follows_https_upgrade)
{
    struct redirect_server_s srv;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof (addr);

    srv.listen_fd = socket (AF_INET, SOCK_STREAM, 0);
    ck_assert_int_ge (srv.listen_fd, 0);
    memset (&addr, 0, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    addr.sin_port = 0; /* ephemeral */
    ck_assert_int_eq (bind (srv.listen_fd, (struct sockaddr *)&addr, sizeof (addr)), 0);
    ck_assert_int_eq (listen (srv.listen_fd, 2), 0);
    ck_assert_int_eq (getsockname (srv.listen_fd, (struct sockaddr *)&addr, &addr_len), 0);
    srv.port = ntohs (addr.sin_port);

    pthread_t thread;
    ck_assert_int_eq (pthread_create (&thread, NULL, redirect_server_thread, &srv), 0);

    char host[64];
    snprintf (host, sizeof (host), "http://127.0.0.1:%u", srv.port);
    smm_connection conn = smm_asset_connect (host, "user", "pass");
    ck_assert_ptr_nonnull (conn);

    /* The login itself fails (the upgraded retry reaches a socket that does
     * not speak TLS), but the redirect must have switched the connection to
     * the https host — that retry happening at all is the regression this
     * test covers. */
    ck_assert_int_eq (smm_asset_connection_login (conn), false);
    char expected_host[64];
    snprintf (expected_host, sizeof (expected_host), "https://127.0.0.1:%u", srv.port);
    ck_assert_str_eq (conn->host, expected_host);

    pthread_join (thread, NULL);
    close (srv.listen_fd);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_curl_retrieve_url_r_returns_null_on_no_response)
{
    /* Exercises the httpcode==0 cleanup path in smm_connection_curl_retrieve_url_r.
     * Port 19999 is chosen to be connection-refused (fast) rather than a
     * timeout. The function must return NULL and free all internal state
     * (ASAN/Valgrind will catch any leak of content_type or redirect_url). */
    smm_connection conn = smm_asset_connect ("http://127.0.0.1:19999/", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    struct smm_curl_res_s *res = smm_connection_curl_retrieve_url_r (conn, "/test/", NULL, NULL, NULL, false);
    ck_assert_ptr_null (res);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_login_in_progress_reset_on_failure)
{
    /* login_in_progress must be false after a failed attempt so no caller
     * waiting on login_cond is ever stranded. Port 19999 is chosen to be
     * unreachable without blocking for long (connect-refused, not timeout). */
    smm_connection conn = smm_asset_connect ("http://127.0.0.1:19999/", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    bool res = smm_asset_connection_login (conn);
    ck_assert_int_eq (res, false);
    ck_assert_int_eq (conn->login_in_progress, false);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_state_for_curl_error_http_error_keeps_state)
{
    /* A 404/500 from one endpoint (CURLE_HTTP_RETURNED_ERROR under
     * FAILONERROR) must not flip a connected session into a failure state. */
    smm_connection_status state = SMM_CONNECTION_CONNECTED;
    ck_assert_int_eq (smm_connection_state_for_curl_error (CURLE_HTTP_RETURNED_ERROR, &state), false);
    ck_assert_int_eq (state, SMM_CONNECTION_CONNECTED);
}
END_TEST

START_TEST (test_state_for_curl_error_connection_failures)
{
    smm_connection_status state;
    ck_assert_int_eq (smm_connection_state_for_curl_error (CURLE_URL_MALFORMAT, &state), true);
    ck_assert_int_eq (state, SMM_CONNECTION_HOST_INVALID);
    ck_assert_int_eq (smm_connection_state_for_curl_error (CURLE_COULDNT_RESOLVE_HOST, &state), true);
    ck_assert_int_eq (state, SMM_CONNECTION_NO_HOST_CONNECTION);
    ck_assert_int_eq (smm_connection_state_for_curl_error (CURLE_COULDNT_CONNECT, &state), true);
    ck_assert_int_eq (state, SMM_CONNECTION_NO_HOST_CONNECTION);
    ck_assert_int_eq (smm_connection_state_for_curl_error (CURLE_OPERATION_TIMEDOUT, &state), true);
    ck_assert_int_eq (state, SMM_CONNECTION_FAILURE);
}
END_TEST

START_TEST (test_invalid_host)
{
    smm_connection conn = smm_asset_connect ("not a url", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    ck_assert_int_eq (smm_asset_connection_get_state (conn), SMM_CONNECTION_HOST_INVALID);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_connect_null_host)
{
    smm_connection conn = smm_asset_connect (NULL, "user", "pass");
    ck_assert_ptr_null (conn);
}
END_TEST

START_TEST (test_connect_null_user)
{
    smm_connection conn = smm_asset_connect ("http://localhost/", NULL, "pass");
    ck_assert_ptr_null (conn);
}
END_TEST

START_TEST (test_connect_null_pass)
{
    smm_connection conn = smm_asset_connect ("http://localhost/", "user", NULL);
    ck_assert_ptr_null (conn);
}
END_TEST

START_TEST (test_command_parsing_circle)
{
    const char *json = "{\"action\": \"CIR\"}";
    smm_asset_command cmd;
    double lat = 0, lon = 0;
    bool res = smm_parse_command (json, strlen (json), &cmd, &lat, &lon);
    ck_assert_uint_eq (res, true);
    ck_assert_int_eq (cmd, SMM_COMMAND_CIRCLE);
}
END_TEST

START_TEST (test_command_parsing_abandon_search)
{
    const char *json = "{\"action\": \"AS\"}";
    smm_asset_command cmd;
    double lat = 0, lon = 0;
    bool res = smm_parse_command (json, strlen (json), &cmd, &lat, &lon);
    ck_assert_uint_eq (res, true);
    ck_assert_int_eq (cmd, SMM_COMMAND_ABANDON_SEARCH);
}
END_TEST

START_TEST (test_command_parsing_mission_complete)
{
    const char *json = "{\"action\": \"MC\"}";
    smm_asset_command cmd;
    double lat = 0, lon = 0;
    bool res = smm_parse_command (json, strlen (json), &cmd, &lat, &lon);
    ck_assert_uint_eq (res, true);
    ck_assert_int_eq (cmd, SMM_COMMAND_MISSION_COMPLETE);
}
END_TEST

START_TEST (test_command_parsing_continue)
{
    const char *json = "{\"action\": \"RON\"}";
    smm_asset_command cmd;
    double lat = 0, lon = 0;
    bool res = smm_parse_command (json, strlen (json), &cmd, &lat, &lon);
    ck_assert_uint_eq (res, true);
    ck_assert_int_eq (cmd, SMM_COMMAND_CONTINUE);
}
END_TEST

START_TEST (test_command_parsing_no_action_field)
{
    const char *json = "{\"notaction\": \"RTL\"}";
    smm_asset_command cmd = SMM_COMMAND_NONE;
    double lat = 0, lon = 0;
    bool res = smm_parse_command (json, strlen (json), &cmd, &lat, &lon);
    ck_assert_uint_eq (res, false);
}
END_TEST

START_TEST (test_waypoints_parsing_empty_features)
{
    const char *json = "{\"features\": []}";
    smm_waypoints waypoints = NULL;
    size_t count = 0;
    bool res = smm_parse_waypoints (json, strlen (json), &waypoints, &count);
    ck_assert_uint_eq (res, false);
    ck_assert_uint_eq (count, 0);
}
END_TEST

START_TEST (test_waypoints_parsing_multiple_features)
{
    const char *json
        = "{\"features\": [{\"geometry\": {\"coordinates\": [[172.6, -43.5]]}}, {\"geometry\": {\"coordinates\": "
          "[[172.7, -43.6]]}}]}";
    smm_waypoints waypoints = NULL;
    size_t count = 0;
    bool res = smm_parse_waypoints (json, strlen (json), &waypoints, &count);
    ck_assert_uint_eq (res, false);
    ck_assert_uint_eq (count, 0);
}
END_TEST

START_TEST (test_waypoint_parsing_integer_coords)
{
    /* GeoJSON coordinates may be integers; json_real_value returns 0 for
     * integer JSON nodes, so we must use json_number_value instead. */
    const char *json = "{\"features\": [{\"geometry\": {\"coordinates\": [[173, -44], [172, -43]]}}]}";
    smm_waypoints waypoints;
    size_t count;
    bool res = smm_parse_waypoints (json, strlen (json), &waypoints, &count);

    ck_assert_uint_eq (res, true);
    ck_assert_uint_eq (count, 2);
    ck_assert_ldouble_eq_tol (waypoints[0]->lat, -44.0, 0.0001);
    ck_assert_ldouble_eq_tol (waypoints[0]->lon, 173.0, 0.0001);
    ck_assert_ldouble_eq_tol (waypoints[1]->lat, -43.0, 0.0001);
    ck_assert_ldouble_eq_tol (waypoints[1]->lon, 172.0, 0.0001);

    smm_waypoints_free (waypoints, count);
}
END_TEST

START_TEST (test_waypoints_parsing_missing_geometry)
{
    const char *json = "{\"features\": [{\"properties\": {}}]}";
    smm_waypoints waypoints = NULL;
    size_t count = 0;
    bool res = smm_parse_waypoints (json, strlen (json), &waypoints, &count);
    ck_assert_uint_eq (res, false);
    ck_assert_uint_eq (count, 0);
}
END_TEST

START_TEST (test_waypoints_parsing_missing_coordinates)
{
    const char *json = "{\"features\": [{\"geometry\": {\"type\": \"LineString\"}}]}";
    smm_waypoints waypoints = NULL;
    size_t count = 0;
    bool res = smm_parse_waypoints (json, strlen (json), &waypoints, &count);
    ck_assert_uint_eq (res, false);
    ck_assert_uint_eq (count, 0);
}
END_TEST

START_TEST (test_waypoints_parsing_no_features_key)
{
    const char *json = "{\"type\": \"FeatureCollection\"}";
    smm_waypoints waypoints = NULL;
    size_t count = 0;
    bool res = smm_parse_waypoints (json, strlen (json), &waypoints, &count);
    ck_assert_uint_eq (res, false);
    ck_assert_uint_eq (count, 0);
}
END_TEST

START_TEST (test_asset_last_goto_pos_not_goto)
{
    smm_asset asset = smm_asset_create (NULL, "A", "T", 1, 1);
    ck_assert_ptr_nonnull (asset);
    smm_asset_set_command_from_plaintext (asset, "Other", 5);
    double lat = 99.0, lon = 99.0;
    bool res = smm_asset_last_goto_pos (asset, &lat, &lon);
    ck_assert_int_eq (res, false);
    ck_assert_ldouble_eq_tol (lat, 99.0, 0.0001);
    ck_assert_ldouble_eq_tol (lon, 99.0, 0.0001);
    smm_asset_free_asset (asset);
}
END_TEST

START_TEST (test_asset_last_goto_pos_goto)
{
    const char *json = "{\"action\": \"GOTO\", \"latitude\": -43.5, \"longitude\": 172.6}";
    smm_asset asset = smm_asset_create (NULL, "A", "T", 1, 1);
    ck_assert_ptr_nonnull (asset);
    pthread_mutex_lock (&asset->lock);
    smm_parse_command (json, strlen (json), &asset->last_command, &asset->last_command_lat, &asset->last_command_lon);
    pthread_mutex_unlock (&asset->lock);
    double lat = 0.0, lon = 0.0;
    bool res = smm_asset_last_goto_pos (asset, &lat, &lon);
    ck_assert_int_eq (res, true);
    ck_assert_ldouble_eq_tol (lat, -43.5, 0.0001);
    ck_assert_ldouble_eq_tol (lon, 172.6, 0.0001);
    smm_asset_free_asset (asset);
}
END_TEST

START_TEST (test_search_distance_and_length)
{
    struct smm_search_s search;
    memset (&search, 0, sizeof (search));
    search.distance = 500;
    search.length = 1200;
    ck_assert_uint_eq (smm_search_distance (&search), 500);
    ck_assert_uint_eq (smm_search_length (&search), 1200);
}
END_TEST

START_TEST (test_build_position_url_values)
{
    char *url = smm_asset_build_position_url (7, -43.5, 172.6, 35, 270, 3);
    ck_assert_ptr_nonnull (url);
    ck_assert_ptr_nonnull (strstr (url, "assets/7/"));
    ck_assert_ptr_nonnull (strstr (url, "alt=35"));
    ck_assert_ptr_nonnull (strstr (url, "heading=270"));
    ck_assert_ptr_nonnull (strstr (url, "fix=3"));
    free (url);
}
END_TEST

START_TEST (test_build_position_url_negative_altitude)
{
    /* Altitude may be below mean sea level; it must be sent as a signed value,
     * not wrapped through an unsigned conversion. */
    char *url = smm_asset_build_position_url (7, -43.5, 172.6, -12, 270, 3);
    ck_assert_ptr_nonnull (url);
    ck_assert_ptr_nonnull (strstr (url, "alt=-12"));
    free (url);
}
END_TEST

START_TEST (test_build_position_url_altitude_int32_range)
{
    /* The altitude parameter is int32_t; the full range must format intact. */
    char *url = smm_asset_build_position_url (7, -43.5, 172.6, INT32_MIN, 270, 3);
    ck_assert_ptr_nonnull (url);
    ck_assert_ptr_nonnull (strstr (url, "alt=-2147483648"));
    free (url);

    url = smm_asset_build_position_url (7, -43.5, 172.6, INT32_MAX, 270, 3);
    ck_assert_ptr_nonnull (url);
    ck_assert_ptr_nonnull (strstr (url, "alt=2147483647"));
    free (url);
}
END_TEST

START_TEST (test_build_position_url_heading_boundary)
{
    char *url0 = smm_asset_build_position_url (1, 0.0, 0.0, 0, 0, 0);
    ck_assert_ptr_nonnull (url0);
    ck_assert_ptr_nonnull (strstr (url0, "heading=0"));
    free (url0);

    char *url359 = smm_asset_build_position_url (1, 0.0, 0.0, 0, 359, 0);
    ck_assert_ptr_nonnull (url359);
    ck_assert_ptr_nonnull (strstr (url359, "heading=359"));
    free (url359);
}
END_TEST

START_TEST (test_debugging_set)
{
    smm_asset_debugging_set (true);
    smm_asset_debugging_set (false);
}
END_TEST

START_TEST (test_version_runtime_matches_headers)
{
    /* The runtime queries must agree with the macros the tests were compiled
     * against (the tests always run against the just-built library). */
    ck_assert_str_eq (smm_asset_version_string (), SMM_VERSION_STRING);
    ck_assert_uint_eq (smm_asset_version_number (), SMM_VERSION_NUMBER);
    ck_assert_uint_eq (smm_asset_version_number () >> 16, SMM_VERSION_MAJOR);
    ck_assert_uint_eq ((smm_asset_version_number () >> 8) & 0xff, SMM_VERSION_MINOR);
    ck_assert_uint_eq (smm_asset_version_number () & 0xff, SMM_VERSION_PATCH);
}
END_TEST

START_TEST (test_connection_login_fields_initialised)
{
    smm_connection conn = smm_asset_connect ("not a url", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    /* login_in_progress must be false after smm_asset_connect; if not, a
     * subsequent caller would deadlock waiting on the condition variable. */
    ck_assert_int_eq (conn->login_in_progress, false);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_get_last_error_null_connection)
{
    char msg[16] = "sentinel";
    ck_assert_int_eq (smm_connection_get_last_error (NULL, msg, sizeof (msg)), SMM_ERROR_NONE);
    ck_assert_str_eq (msg, "");
}
END_TEST

START_TEST (test_get_last_error_initial)
{
    smm_connection conn = smm_asset_connect ("http://localhost/", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    char msg[64];
    ck_assert_int_eq (smm_connection_get_last_error (conn, msg, sizeof (msg)), SMM_ERROR_NONE);
    ck_assert_str_eq (msg, "");
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_get_state_null_connection)
{
    ck_assert_int_eq (smm_asset_connection_get_state (NULL), SMM_CONNECTION_UNKNOWN);
}
END_TEST

START_TEST (test_connection_login_null) { ck_assert_int_eq (smm_asset_connection_login (NULL), false); }
END_TEST

START_TEST (test_get_state_initial)
{
    smm_connection conn = smm_asset_connect ("http://localhost/", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    ck_assert_int_eq (smm_asset_connection_get_state (conn), SMM_CONNECTION_NEW);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_get_state_invalid_host)
{
    smm_connection conn = smm_asset_connect ("not a url", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    ck_assert_int_eq (smm_asset_connection_get_state (conn), SMM_CONNECTION_HOST_INVALID);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_connect_strips_trailing_slash)
{
    /* Request paths always start with '/', so a trailing '/' on the host
     * would otherwise yield "http://example.com//assets/". */
    smm_connection conn = smm_asset_connect ("http://example.com/", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    ck_assert_str_eq (conn->host, "http://example.com");
    ck_assert_int_eq (smm_asset_connection_get_state (conn), SMM_CONNECTION_NEW);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_connect_strips_multiple_trailing_slashes)
{
    smm_connection conn = smm_asset_connect ("http://example.com///", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    ck_assert_str_eq (conn->host, "http://example.com");
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_connect_no_trailing_slash_unchanged)
{
    smm_connection conn = smm_asset_connect ("http://example.com:8080", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    ck_assert_str_eq (conn->host, "http://example.com:8080");
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_connect_base_path_trailing_slash)
{
    /* A base path (server behind a reverse-proxy subpath) keeps the path but
     * loses the trailing '/' so request paths concatenate cleanly. */
    smm_connection conn = smm_asset_connect ("https://example.com/smm/", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    ck_assert_str_eq (conn->host, "https://example.com/smm");
    ck_assert_int_eq (smm_asset_connection_get_state (conn), SMM_CONNECTION_NEW);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_https_upgrade_preserves_base_path)
{
    /* The https upgrade rebuilds the host from the part after "http://", so a
     * base path must survive the scheme switch. */
    smm_connection conn = smm_asset_connect ("http://example.com/smm/", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    ck_assert_int_eq (smm_connection_try_https_upgrade (conn, "https://example.com/accounts/login/"), true);
    ck_assert_str_eq (conn->host, "https://example.com/smm");
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_connect_only_slashes_is_invalid)
{
    /* Degenerate input that normalises to the empty string must be reported
     * as an invalid host, not silently accepted. */
    smm_connection conn = smm_asset_connect ("///", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    /* Normalisation ran before validation: every slash was stripped, and it
     * is that empty host the validation then rejected. */
    ck_assert_str_eq (conn->host, "");
    ck_assert_int_eq (smm_asset_connection_get_state (conn), SMM_CONNECTION_HOST_INVALID);
    smm_connection_close (conn);
}
END_TEST

Suite *
smm_suite (void)
{
    Suite *s;
    TCase *tc_csrf;
    TCase *tc_conn;

    s = suite_create ("SMM");

    tc_conn = tcase_create ("Connection");
    tcase_add_test (tc_conn, test_curl_timeout_constants);
    tcase_add_test (tc_conn, test_httpcode_is_redirect);
    tcase_add_test (tc_conn, test_httpcode_is_not_redirect);
    tcase_add_test (tc_conn, test_curl_retrieve_url_r_returns_null_on_no_response);
    tcase_add_test (tc_conn, test_login_in_progress_reset_on_failure);
    tcase_add_test (tc_conn, test_https_upgrade_same_host);
    tcase_add_test (tc_conn, test_https_upgrade_same_host_with_port);
    tcase_add_test (tc_conn, test_https_upgrade_different_host);
    tcase_add_test (tc_conn, test_https_upgrade_subdomain);
    tcase_add_test (tc_conn, test_https_upgrade_different_port);
    tcase_add_test (tc_conn, test_https_upgrade_null_args);
    tcase_add_test (tc_conn, test_https_upgrade_non_http_http_host);
    tcase_add_test (tc_conn, test_https_upgrade_already_https);
    tcase_add_test (tc_conn, test_try_https_upgrade_switches_host);
    tcase_add_test (tc_conn, test_try_https_upgrade_rejects_other_host);
    tcase_add_test (tc_conn, test_try_https_upgrade_null_args);
    tcase_add_test (tc_conn, test_eager_login_follows_https_upgrade);
    tcase_add_test (tc_conn, test_state_for_curl_error_http_error_keeps_state);
    tcase_add_test (tc_conn, test_state_for_curl_error_connection_failures);
    tcase_add_test (tc_conn, test_invalid_host);
    tcase_add_test (tc_conn, test_connect_null_host);
    tcase_add_test (tc_conn, test_connect_null_user);
    tcase_add_test (tc_conn, test_connect_null_pass);
    tcase_add_test (tc_conn, test_connection_login_fields_initialised);
    tcase_add_test (tc_conn, test_get_last_error_null_connection);
    tcase_add_test (tc_conn, test_get_last_error_initial);
    tcase_add_test (tc_conn, test_asset_get_last_error_null);
    tcase_add_test (tc_conn, test_asset_get_last_error_initial);
    tcase_add_test (tc_conn, test_search_get_last_error_null);
    tcase_add_test (tc_conn, test_search_get_last_error_initial);
    tcase_add_test (tc_conn, test_report_position_sets_asset_error_not_conn);
    tcase_add_test (tc_conn, test_get_last_error_message_truncated_to_buffer);
    tcase_add_test (tc_conn, test_search_action_sets_search_error_not_conn);
    tcase_add_test (tc_conn, test_get_assets_null_outparams_record_invalid_arg);
    tcase_add_test (tc_conn, test_get_waypoints_null_outparams_record_invalid_arg);
    tcase_add_test (tc_conn, test_get_state_null_connection);
    tcase_add_test (tc_conn, test_connection_login_null);
    tcase_add_test (tc_conn, test_get_state_initial);
    tcase_add_test (tc_conn, test_get_state_invalid_host);
    tcase_add_test (tc_conn, test_connect_strips_trailing_slash);
    tcase_add_test (tc_conn, test_connect_strips_multiple_trailing_slashes);
    tcase_add_test (tc_conn, test_connect_no_trailing_slash_unchanged);
    tcase_add_test (tc_conn, test_connect_base_path_trailing_slash);
    tcase_add_test (tc_conn, test_https_upgrade_preserves_base_path);
    tcase_add_test (tc_conn, test_connect_only_slashes_is_invalid);
    tcase_add_test (tc_conn, test_debugging_set);
    tcase_add_test (tc_conn, test_version_runtime_matches_headers);
    suite_add_tcase (s, tc_conn);

    TCase *tc_position = tcase_create ("Position");
    tcase_add_test (tc_position, test_build_position_url_heading);
    tcase_add_test (tc_position, test_build_position_url_locale_independent);
    tcase_add_test (tc_position, test_set_command_from_plaintext_continue);
    tcase_add_test (tc_position, test_set_command_from_plaintext_other);
    tcase_add_test (tc_position, test_set_command_from_plaintext_null);
    tcase_add_test (tc_position, test_set_command_from_plaintext_zero_length);
    tcase_add_test (tc_position, test_set_command_from_plaintext_with_trailing);
    tcase_add_test (tc_position, test_set_command_null_asset);
    tcase_add_test (tc_position, test_report_position_null_conn);
    tcase_add_test (tc_position, test_report_position_null_asset);
    tcase_add_test (tc_position, test_last_command_null_asset);
    tcase_add_test (tc_position, test_last_goto_pos_null_asset);
    tcase_add_test (tc_position, test_get_search_null_asset);
    suite_add_tcase (s, tc_position);

    tc_csrf = tcase_create ("CSRF");
    tcase_add_test (tc_csrf, test_csrf_extraction);
    tcase_add_test (tc_csrf, test_csrf_extraction_missing);
    tcase_add_test (tc_csrf, test_csrf_extraction_invalid_chars);
    tcase_add_test (tc_csrf, test_csrf_extraction_too_long);
    tcase_add_test (tc_csrf, test_csrf_extraction_deeply_nested);
    suite_add_tcase (s, tc_csrf);

    TCase *tc_assets = tcase_create ("Assets");
    tcase_add_test (tc_assets, test_assets_parsing);
    tcase_add_test (tc_assets, test_assets_parsing_empty);
    tcase_add_test (tc_assets, test_assets_parsing_invalid);
    tcase_add_test (tc_assets, test_assets_parsing_missing_id);
    tcase_add_test (tc_assets, test_assets_parsing_noninteger_id);
    tcase_add_test (tc_assets, test_assets_parsing_noninteger_type_id);
    tcase_add_test (tc_assets, test_assets_parsing_drops_only_invalid);
    tcase_add_test (tc_assets, test_assets_parsing_missing_type_id);
    suite_add_tcase (s, tc_assets);

    TCase *tc_commands = tcase_create ("Commands");
    tcase_add_test (tc_commands, test_command_parsing_goto);
    tcase_add_test (tc_commands, test_command_parsing_goto_integer_coords);
    tcase_add_test (tc_commands, test_command_parsing_goto_mixed_lat_real_lon_int);
    tcase_add_test (tc_commands, test_command_parsing_goto_mixed_lat_int_lon_real);
    tcase_add_test (tc_commands, test_command_parsing_rtl);
    tcase_add_test (tc_commands, test_command_parsing_circle);
    tcase_add_test (tc_commands, test_command_parsing_abandon_search);
    tcase_add_test (tc_commands, test_command_parsing_mission_complete);
    tcase_add_test (tc_commands, test_command_parsing_continue);
    tcase_add_test (tc_commands, test_command_parsing_unknown);
    tcase_add_test (tc_commands, test_command_parsing_no_action_field);
    suite_add_tcase (s, tc_commands);

    TCase *tc_waypoints = tcase_create ("Waypoints");
    tcase_add_test (tc_waypoints, test_waypoint_parsing);
    tcase_add_test (tc_waypoints, test_waypoints_parsing_empty_features);
    tcase_add_test (tc_waypoints, test_waypoints_parsing_multiple_features);
    tcase_add_test (tc_waypoints, test_waypoint_parsing_integer_coords);
    tcase_add_test (tc_waypoints, test_waypoints_parsing_missing_geometry);
    tcase_add_test (tc_waypoints, test_waypoints_parsing_missing_coordinates);
    tcase_add_test (tc_waypoints, test_waypoints_parsing_no_features_key);
    suite_add_tcase (s, tc_waypoints);

    TCase *tc_search = tcase_create ("Search");
    tcase_add_test (tc_search, test_search_accept_null_conn);
    tcase_add_test (tc_search, test_search_accept_null_search);
    tcase_add_test (tc_search, test_search_complete_null_search);
    tcase_add_test (tc_search, test_search_get_waypoints_null_search);
    tcase_add_test (tc_search, test_asset_outlives_connection);
    tcase_add_test (tc_search, test_search_sweep_width);
    tcase_add_test (tc_search, test_search_distance_and_length);
    tcase_add_test (tc_search, test_get_search_absolute_url_ignored);
    tcase_add_test (tc_search, test_get_search_http_absolute_url_ignored);
    tcase_add_test (tc_search, test_get_search_nonstring_object_url_returns_null);
    tcase_add_test (tc_search, test_get_search_missing_object_url_returns_null);
    tcase_add_test (tc_search, test_get_search_relative_url_accepted);
    tcase_add_test (tc_search, test_get_search_real_numeric_fields);
    tcase_add_test (tc_search, test_get_search_negative_numeric_clamps_zero);
    tcase_add_test (tc_search, test_get_search_dotdot_url_rejected);
    tcase_add_test (tc_search, test_get_search_query_url_rejected);
    tcase_add_test (tc_search, test_get_search_encoded_url_rejected);
    suite_add_tcase (s, tc_search);

    TCase *tc_url = tcase_create ("URL");
    tcase_add_test (tc_url, test_url_path_safe_valid);
    tcase_add_test (tc_url, test_url_path_safe_dotdot);
    tcase_add_test (tc_url, test_url_path_safe_query);
    tcase_add_test (tc_url, test_url_path_safe_fragment);
    tcase_add_test (tc_url, test_url_path_safe_encoded);
    tcase_add_test (tc_url, test_url_path_safe_absolute);
    tcase_add_test (tc_url, test_url_path_safe_null);
    suite_add_tcase (s, tc_url);

    TCase *tc_buffer = tcase_create ("Buffer");
    tcase_add_test (tc_buffer, test_to_buffer_accumulates);
    tcase_add_test (tc_buffer, test_to_buffer_rejects_oversized_chunk);
    tcase_add_test (tc_buffer, test_to_buffer_rejects_when_full);
    tcase_add_test (tc_buffer, test_to_buffer_rejects_size_overflow);
    tcase_add_test (tc_buffer, test_buffer_reset_discards_content);
    tcase_add_test (tc_buffer, test_buffer_reset_null_safe);
    suite_add_tcase (s, tc_buffer);

    TCase *tc_content_type = tcase_create ("ContentType");
    tcase_add_test (tc_content_type, test_content_type_is_json_plain);
    tcase_add_test (tc_content_type, test_content_type_is_json_with_charset);
    tcase_add_test (tc_content_type, test_content_type_is_json_case_insensitive);
    tcase_add_test (tc_content_type, test_content_type_is_json_leading_whitespace);
    tcase_add_test (tc_content_type, test_content_type_is_json_rejects_lookalikes);
    suite_add_tcase (s, tc_content_type);

    TCase *tc_position_ext = tcase_create ("PositionExt");
    tcase_add_test (tc_position_ext, test_build_position_url_values);
    tcase_add_test (tc_position_ext, test_build_position_url_negative_altitude);
    tcase_add_test (tc_position_ext, test_build_position_url_altitude_int32_range);
    tcase_add_test (tc_position_ext, test_build_position_url_heading_boundary);
    tcase_add_test (tc_position_ext, test_asset_last_goto_pos_not_goto);
    tcase_add_test (tc_position_ext, test_asset_last_goto_pos_goto);
    suite_add_tcase (s, tc_position_ext);

    return s;
}

int
main (void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = smm_suite ();
    sr = srunner_create (s);

    srunner_run_all (sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
