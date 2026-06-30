#include "smm-asset-internal.h"
#include "smm-asset.h"
#include <arpa/inet.h>
#include <check.h>
#include <locale.h>
#include <math.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
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

START_TEST (test_assets_parsing_zero_id)
{
    /* id 0 is not a valid server primary key; the asset is dropped. */
    const char *json = "{\"assets\": [{\"id\": 0, \"type_id\": 2, \"name\": \"Asset 1\", \"type_name\": \"Type 1\"}]}";
    smm_assets assets;
    size_t count;
    bool res = smm_parse_assets (NULL, json, strlen (json), &assets, &count);

    ck_assert_uint_eq (res, true);
    ck_assert_uint_eq (count, 0);
    ck_assert_ptr_null (assets);
}
END_TEST

START_TEST (test_assets_parsing_negative_id)
{
    /* A negative id would build paths like /data/assets/-1/; reject it. */
    const char *json = "{\"assets\": [{\"id\": -1, \"type_id\": 2, \"name\": \"Asset 1\", \"type_name\": \"Type 1\"}]}";
    smm_assets assets;
    size_t count;
    bool res = smm_parse_assets (NULL, json, strlen (json), &assets, &count);

    ck_assert_uint_eq (res, true);
    ck_assert_uint_eq (count, 0);
    ck_assert_ptr_null (assets);
}
END_TEST

START_TEST (test_assets_parsing_negative_type_id)
{
    /* type_id is optional; a negative value is left at the sentinel and does
     * not drop an otherwise valid asset. */
    const char *json = "{\"assets\": [{\"id\": 1, \"type_id\": -2, \"name\": \"Asset 1\", \"type_name\": \"Type 1\"}]}";
    smm_assets assets;
    size_t count;
    bool res = smm_parse_assets (NULL, json, strlen (json), &assets, &count);

    ck_assert_uint_eq (res, true);
    ck_assert_uint_eq (count, 1);
    ck_assert_str_eq (smm_asset_name (assets[0]), "Asset 1");
    smm_asset_free_assets (assets, count);
}
END_TEST

START_TEST (test_assets_parsing_zero_id_drops_only_invalid)
{
    /* A valid asset is kept even when a sibling entry has a non-positive id. */
    const char *json = "{\"assets\": [{\"id\": 0, \"name\": \"Bad\"}, {\"id\": 7, \"type_id\": 2, \"name\": \"Good\", "
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

START_TEST (test_command_parsing_goto_missing_latitude)
{
    const char *json = "{\"action\": \"GOTO\", \"longitude\": 172.6}";
    smm_asset_command cmd;
    double lat = 0, lon = 0;
    bool res = smm_parse_command (json, strlen (json), &cmd, &lat, &lon);

    ck_assert_uint_eq (res, false);
    ck_assert_int_ne (cmd, SMM_COMMAND_GOTO);
}
END_TEST

START_TEST (test_command_parsing_goto_missing_longitude)
{
    const char *json = "{\"action\": \"GOTO\", \"latitude\": -43.5}";
    smm_asset_command cmd;
    double lat = 0, lon = 0;
    bool res = smm_parse_command (json, strlen (json), &cmd, &lat, &lon);

    ck_assert_uint_eq (res, false);
    ck_assert_int_ne (cmd, SMM_COMMAND_GOTO);
}
END_TEST

START_TEST (test_command_parsing_goto_nonnumeric)
{
    const char *json = "{\"action\": \"GOTO\", \"latitude\": \"x\", \"longitude\": \"y\"}";
    smm_asset_command cmd;
    double lat = 0, lon = 0;
    bool res = smm_parse_command (json, strlen (json), &cmd, &lat, &lon);

    ck_assert_uint_eq (res, false);
    ck_assert_int_ne (cmd, SMM_COMMAND_GOTO);
}
END_TEST

START_TEST (test_command_parsing_goto_out_of_range_lat)
{
    const char *json = "{\"action\": \"GOTO\", \"latitude\": 91.0, \"longitude\": 172.6}";
    smm_asset_command cmd;
    double lat = 0, lon = 0;
    bool res = smm_parse_command (json, strlen (json), &cmd, &lat, &lon);

    ck_assert_uint_eq (res, false);
    ck_assert_int_ne (cmd, SMM_COMMAND_GOTO);
}
END_TEST

START_TEST (test_command_parsing_goto_out_of_range_lon)
{
    const char *json = "{\"action\": \"GOTO\", \"latitude\": -43.5, \"longitude\": 181.0}";
    smm_asset_command cmd;
    double lat = 0, lon = 0;
    bool res = smm_parse_command (json, strlen (json), &cmd, &lat, &lon);

    ck_assert_uint_eq (res, false);
    ck_assert_int_ne (cmd, SMM_COMMAND_GOTO);
}
END_TEST

START_TEST (test_goto_then_malformed_goto_clears_position)
{
    /* A valid GOTO publishes a position; a following malformed GOTO must not
     * keep reporting the stale coordinates. */
    smm_connection conn = smm_asset_connect ("http://example.com", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    smm_asset asset = smm_asset_create (conn, "A", "T", 1, 1);
    ck_assert_ptr_nonnull (asset);
    double lat = 0, lon = 0;

    char good[] = "{\"action\": \"GOTO\", \"latitude\": -43.5, \"longitude\": 172.6}";
    struct buffer_s gbuf = { good, strlen (good) };
    smm_asset_update_command (asset, &gbuf);
    ck_assert_int_eq (smm_asset_last_goto_pos (asset, &lat, &lon), true);
    ck_assert_ldouble_eq_tol (lat, -43.5, 0.0001);
    ck_assert_ldouble_eq_tol (lon, 172.6, 0.0001);

    char bad[] = "{\"action\": \"GOTO\", \"longitude\": 172.6}"; /* missing latitude */
    struct buffer_s bbuf = { bad, strlen (bad) };
    smm_asset_update_command (asset, &bbuf);
    ck_assert_int_eq (smm_asset_last_goto_pos (asset, &lat, &lon), false);
    ck_assert_int_eq (smm_asset_last_command (asset), SMM_COMMAND_UNKNOWN);

    smm_asset_free_asset (asset);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_waypoint_parsing)
{
    const char *json = "{\"features\": [{\"geometry\": {\"type\": \"LineString\", \"coordinates\": [[172.6, -43.5], "
                       "[172.7, -43.6]]}}]}";
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

static smm_search
parse_search_with_object_url (const char *object_url)
{
    char *json = NULL;
    int n = asprintf (&json, "{\"object_url\": \"%s\", \"distance\": 10, \"length\": 100, \"sweep_width\": 50}",
                      object_url);
    ck_assert_int_ge (n, 0);
    smm_search search = smm_parse_search_json (NULL, json, strlen (json));
    free (json);
    return search;
}

START_TEST (test_get_search_root_url_rejected) { ck_assert_ptr_null (parse_search_with_object_url ("/")); }
END_TEST

START_TEST (test_get_search_assets_url_rejected) { ck_assert_ptr_null (parse_search_with_object_url ("/assets/1/")); }
END_TEST

START_TEST (test_get_search_logout_url_rejected)
{
    ck_assert_ptr_null (parse_search_with_object_url ("/accounts/logout/"));
}
END_TEST

START_TEST (test_get_search_non_numeric_id_rejected)
{
    ck_assert_ptr_null (parse_search_with_object_url ("/search/not-an-id/"));
}
END_TEST

START_TEST (test_get_search_negative_id_rejected) { ck_assert_ptr_null (parse_search_with_object_url ("/search/-1/")); }
END_TEST

START_TEST (test_get_search_zero_id_rejected) { ck_assert_ptr_null (parse_search_with_object_url ("/search/0/")); }
END_TEST

static smm_asset
make_connected_test_asset (smm_connection *conn_out)
{
    smm_connection conn = smm_asset_connect ("http://example.com", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    smm_asset asset = smm_asset_create (conn, "A", "T", 1, 1);
    ck_assert_ptr_nonnull (asset);
    *conn_out = conn;
    return asset;
}

START_TEST (test_search_from_response_404_is_clean_no_search)
{
    smm_connection conn;
    smm_asset asset = make_connected_test_asset (&conn);
    const char *body = "No suitable searches exist";
    smm_search search = smm_search_from_response (asset, 404, "text/plain", body, strlen (body));
    ck_assert_ptr_null (search);
    ck_assert_int_eq (smm_asset_get_last_error (asset, NULL, 0), SMM_ERROR_NONE);
    smm_asset_free_asset (asset);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_search_from_response_non_json_200_sets_protocol)
{
    smm_connection conn;
    smm_asset asset = make_connected_test_asset (&conn);
    const char *body = "<html>not json</html>";
    smm_search search = smm_search_from_response (asset, 200, "text/html", body, strlen (body));
    ck_assert_ptr_null (search);
    ck_assert_int_eq (smm_asset_get_last_error (asset, NULL, 0), SMM_ERROR_PROTOCOL);
    smm_asset_free_asset (asset);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_search_from_response_invalid_json_sets_parse)
{
    smm_connection conn;
    smm_asset asset = make_connected_test_asset (&conn);
    const char *body = "not json at all";
    smm_search search = smm_search_from_response (asset, 200, "application/json", body, strlen (body));
    ck_assert_ptr_null (search);
    ck_assert_int_eq (smm_asset_get_last_error (asset, NULL, 0), SMM_ERROR_PARSE);
    smm_asset_free_asset (asset);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_search_from_response_missing_object_url_sets_protocol)
{
    smm_connection conn;
    smm_asset asset = make_connected_test_asset (&conn);
    const char *body = "{\"distance\": 10, \"length\": 100, \"sweep_width\": 50}";
    smm_search search = smm_search_from_response (asset, 200, "application/json", body, strlen (body));
    ck_assert_ptr_null (search);
    ck_assert_int_eq (smm_asset_get_last_error (asset, NULL, 0), SMM_ERROR_PROTOCOL);
    smm_asset_free_asset (asset);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_search_from_response_unsafe_object_url_sets_protocol)
{
    smm_connection conn;
    smm_asset asset = make_connected_test_asset (&conn);
    const char *body
        = "{\"object_url\": \"/accounts/logout/\", \"distance\": 10, \"length\": 100, \"sweep_width\": 50}";
    smm_search search = smm_search_from_response (asset, 200, "application/json", body, strlen (body));
    ck_assert_ptr_null (search);
    ck_assert_int_eq (smm_asset_get_last_error (asset, NULL, 0), SMM_ERROR_PROTOCOL);
    smm_asset_free_asset (asset);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_search_from_response_valid_returns_search)
{
    smm_connection conn;
    smm_asset asset = make_connected_test_asset (&conn);
    const char *body = "{\"object_url\": \"/search/1/\", \"distance\": 10, \"length\": 100, \"sweep_width\": 50}";
    smm_search search = smm_search_from_response (asset, 200, "application/json", body, strlen (body));
    ck_assert_ptr_nonnull (search);
    ck_assert_int_eq (smm_asset_get_last_error (asset, NULL, 0), SMM_ERROR_NONE);
    smm_search_destroy (search);
    smm_asset_free_asset (asset);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_search_from_response_server_error_sets_server)
{
    smm_connection conn;
    smm_asset asset = make_connected_test_asset (&conn);
    smm_search search = smm_search_from_response (asset, 500, "text/plain", "oops", 4);
    ck_assert_ptr_null (search);
    ck_assert_int_eq (smm_asset_get_last_error (asset, NULL, 0), SMM_ERROR_SERVER);
    smm_asset_free_asset (asset);
    smm_connection_close (conn);
}
END_TEST

struct capture_request_server_s
{
    int listen_fd;
    uint16_t port;
    char request[2048];
};

static void *
capture_search_server_thread (void *arg)
{
    struct capture_request_server_s *srv = (struct capture_request_server_s *)arg;
    int fd = accept (srv->listen_fd, NULL, NULL);
    if (fd >= 0)
    {
        ssize_t nread = read (fd, srv->request, sizeof (srv->request) - 1);
        if (nread > 0)
        {
            srv->request[nread] = '\0';
        }
        else
        {
            srv->request[0] = '\0';
        }

        const char body[] = "{\"object_url\":\"/search/1/\",\"distance\":10,\"length\":100,\"sweep_width\":50}";
        char resp[512];
        int n = snprintf (resp, sizeof (resp),
                          "HTTP/1.1 200 OK\r\n"
                          "Content-Type: application/json\r\n"
                          "Content-Length: %zu\r\n"
                          "Connection: close\r\n"
                          "\r\n"
                          "%s",
                          sizeof (body) - 1, body);
        (void)!write (fd, resp, (size_t)n);
        close (fd);
    }
    return NULL;
}

START_TEST (test_get_search_requests_json)
{
    struct capture_request_server_s srv;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof (addr);

    memset (&srv, 0, sizeof (srv));
    srv.listen_fd = socket (AF_INET, SOCK_STREAM, 0);
    ck_assert_int_ge (srv.listen_fd, 0);
    memset (&addr, 0, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    addr.sin_port = 0;
    ck_assert_int_eq (bind (srv.listen_fd, (struct sockaddr *)&addr, sizeof (addr)), 0);
    ck_assert_int_eq (listen (srv.listen_fd, 1), 0);
    ck_assert_int_eq (getsockname (srv.listen_fd, (struct sockaddr *)&addr, &addr_len), 0);
    srv.port = ntohs (addr.sin_port);

    pthread_t thread;
    ck_assert_int_eq (pthread_create (&thread, NULL, capture_search_server_thread, &srv), 0);

    char host[64];
    snprintf (host, sizeof (host), "http://127.0.0.1:%u", srv.port);
    smm_connection conn = smm_asset_connect (host, "user", "pass");
    ck_assert_ptr_nonnull (conn);
    smm_asset asset = smm_asset_create (conn, "A", "T", 1, 1);
    ck_assert_ptr_nonnull (asset);

    smm_search search = smm_asset_get_search (asset, -43.5, 172.6);
    ck_assert_ptr_nonnull (search);

    smm_search_destroy (search);
    smm_asset_free_asset (asset);
    smm_connection_close (conn);
    pthread_join (thread, NULL);
    close (srv.listen_fd);

    ck_assert_ptr_nonnull (strstr (srv.request, "GET /search/find/closest/"));
    ck_assert_ptr_nonnull (strstr (srv.request, "Accept: application/json"));
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
    search_s.search_id = 1;
    bool r = smm_search_accept (&search_s);
    ck_assert_int_eq (r, false);
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

START_TEST (test_coords_valid_accepts_boundaries)
{
    ck_assert_int_eq (smm_coords_valid (0.0, 0.0), true);
    ck_assert_int_eq (smm_coords_valid (90.0, 180.0), true);
    ck_assert_int_eq (smm_coords_valid (-90.0, -180.0), true);
}
END_TEST

START_TEST (test_coords_valid_rejects_nan_inf)
{
    ck_assert_int_eq (smm_coords_valid (NAN, 0.0), false);
    ck_assert_int_eq (smm_coords_valid (0.0, NAN), false);
    ck_assert_int_eq (smm_coords_valid (INFINITY, 0.0), false);
    ck_assert_int_eq (smm_coords_valid (0.0, -INFINITY), false);
}
END_TEST

START_TEST (test_coords_valid_rejects_out_of_range)
{
    ck_assert_int_eq (smm_coords_valid (90.1, 0.0), false);
    ck_assert_int_eq (smm_coords_valid (-91.0, 0.0), false);
    ck_assert_int_eq (smm_coords_valid (0.0, 180.1), false);
    ck_assert_int_eq (smm_coords_valid (0.0, -180.1), false);
}
END_TEST

START_TEST (test_position_inputs_valid_heading)
{
    ck_assert_int_eq (smm_position_inputs_valid (0.0, 0.0, 359, 3), true);
    ck_assert_int_eq (smm_position_inputs_valid (0.0, 0.0, 360, 3), false);
}
END_TEST

START_TEST (test_position_inputs_valid_fix)
{
    ck_assert_int_eq (smm_position_inputs_valid (0.0, 0.0, 0, 0), true);
    ck_assert_int_eq (smm_position_inputs_valid (0.0, 0.0, 0, 2), true);
    ck_assert_int_eq (smm_position_inputs_valid (0.0, 0.0, 0, 3), true);
    ck_assert_int_eq (smm_position_inputs_valid (0.0, 0.0, 0, 1), false);
    ck_assert_int_eq (smm_position_inputs_valid (0.0, 0.0, 0, 4), false);
}
END_TEST

START_TEST (test_position_inputs_valid_full_boundary)
{
    ck_assert_int_eq (smm_position_inputs_valid (90.0, 180.0, 359, 3), true);
    ck_assert_int_eq (smm_position_inputs_valid (-90.0, -180.0, 0, 0), true);
}
END_TEST

START_TEST (test_report_position_nan_sets_invalid_arg)
{
    /* Invalid inputs are rejected before any network I/O, with the asset's
     * error recorded. */
    smm_connection conn = smm_asset_connect ("http://example.com", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    smm_asset asset = smm_asset_create (conn, "A", "T", 1, 1);
    ck_assert_ptr_nonnull (asset);

    ck_assert_int_eq (smm_asset_report_position (asset, NAN, 172.6, 100, 270, 3), false);
    ck_assert_int_eq (smm_asset_get_last_error (asset, NULL, 0), SMM_ERROR_INVALID_ARG);

    smm_asset_free_asset (asset);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_get_search_nan_sets_invalid_arg)
{
    smm_connection conn = smm_asset_connect ("http://example.com", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    smm_asset asset = smm_asset_create (conn, "A", "T", 1, 1);
    ck_assert_ptr_nonnull (asset);

    ck_assert_ptr_null (smm_asset_get_search (asset, NAN, 172.6));
    ck_assert_int_eq (smm_asset_get_last_error (asset, NULL, 0), SMM_ERROR_INVALID_ARG);

    smm_asset_free_asset (asset);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_get_search_out_of_range_sets_invalid_arg)
{
    /* get_search must enforce the same coordinate bounds as the position path. */
    smm_connection conn = smm_asset_connect ("http://example.com", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    smm_asset asset = smm_asset_create (conn, "A", "T", 1, 1);
    ck_assert_ptr_nonnull (asset);

    ck_assert_ptr_null (smm_asset_get_search (asset, 90.1, 0.0));
    ck_assert_int_eq (smm_asset_get_last_error (asset, NULL, 0), SMM_ERROR_INVALID_ARG);

    ck_assert_ptr_null (smm_asset_get_search (asset, 0.0, -180.1));
    ck_assert_int_eq (smm_asset_get_last_error (asset, NULL, 0), SMM_ERROR_INVALID_ARG);

    smm_asset_free_asset (asset);
    smm_connection_close (conn);
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

START_TEST (test_asset_create_balances_connection_ref)
{
    /* smm_asset_create takes one connection reference and smm_asset_free_asset
     * drops it; the count must return to where it started. */
    smm_connection conn = smm_asset_connect ("http://example.com", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    int before = conn->refcount;
    smm_asset asset = smm_asset_create (conn, "name", "type", 1, 2);
    ck_assert_ptr_nonnull (asset);
    ck_assert_int_eq (conn->refcount, before + 1);
    smm_asset_free_asset (asset);
    ck_assert_int_eq (conn->refcount, before);
    smm_connection_close (conn);
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

START_TEST (test_build_position_body_heading)
{
    char *body = smm_asset_build_position_body (-43.5, 172.6, 100, 270, 3);
    ck_assert_ptr_nonnull (body);
    ck_assert_ptr_nonnull (strstr (body, "heading="));
    ck_assert_ptr_null (strstr (body, "bearing="));
    free (body);
}
END_TEST

/* Coordinates must always use '.' as the decimal separator regardless of the
 * caller's LC_NUMERIC. We assert this under the current locale (always) and,
 * when a comma-decimal locale is installed, under that locale too. */
START_TEST (test_build_position_body_locale_independent)
{
    char *body = smm_asset_build_position_body (-43.5, 172.6, 100, 270, 3);
    ck_assert_ptr_nonnull (body);
    ck_assert_ptr_nonnull (strstr (body, "lat=-43.500000"));
    ck_assert_ptr_nonnull (strstr (body, "lon=172.600000"));
    free (body);

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
        body = smm_asset_build_position_body (-43.5, 172.6, 100, 270, 3);
        uselocale (old);
        freelocale (loc);

        ck_assert_ptr_nonnull (body);
        ck_assert_ptr_nonnull (strstr (body, "lat=-43.500000"));
        ck_assert_ptr_null (strstr (body, ","));
        free (body);
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
    search_s.search_id = 1;
    smm_search_accept (&search_s);
    ck_assert_int_ne (smm_search_get_last_error (&search_s, NULL, 0), SMM_ERROR_NONE);
}
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

START_TEST (test_secure_clear_zeroes)
{
    char *s = strdup ("s3cr3t-password");
    ck_assert_ptr_nonnull (s);
    size_t len = strlen (s);
    smm_secure_clear (s);
    for (size_t i = 0; i < len; i++)
    {
        ck_assert_int_eq (s[i], '\0');
    }
    free (s);
}
END_TEST

START_TEST (test_secure_clear_empty_string)
{
    char *s = strdup ("");
    ck_assert_ptr_nonnull (s);
    smm_secure_clear (s); /* nothing to clear, must not over-write */
    ck_assert_int_eq (s[0], '\0');
    free (s);
}
END_TEST

START_TEST (test_secure_clear_null_safe) { smm_secure_clear (NULL); /* must not crash */ }
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

START_TEST (test_try_https_upgrade_preserves_port)
{
    /* The upgrade only fires on an exact authority match, and it must carry a
     * non-default port through to the https host rather than silently dropping
     * it (which would point later requests at port 443). */
    smm_connection conn = smm_asset_connect ("http://example.com:8080", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    ck_assert_int_eq (smm_connection_try_https_upgrade (conn, "https://example.com:8080/accounts/login/"), true);
    ck_assert_str_eq (conn->host, "https://example.com:8080");
    smm_connection_close (conn);
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

/* One-shot server that answers the first request with a 200 and a tiny JSON
 * body, used to check that a successful API request marks the connection
 * CONNECTED. */
static void *
ok_200_server_thread (void *arg)
{
    struct redirect_server_s *srv = (struct redirect_server_s *)arg;
    int fd = accept (srv->listen_fd, NULL, NULL);
    if (fd >= 0)
    {
        char req[1024];
        (void)!read (fd, req, sizeof (req));
        const char body[] = "{}";
        char resp[256];
        int n = snprintf (resp, sizeof (resp),
                          "HTTP/1.1 200 OK\r\n"
                          "Content-Type: application/json\r\n"
                          "Content-Length: %zu\r\n"
                          "Connection: close\r\n"
                          "\r\n"
                          "%s",
                          sizeof (body) - 1, body);
        (void)!write (fd, resp, (size_t)n);
        close (fd);
    }
    return NULL;
}

START_TEST (test_successful_request_sets_connected)
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
    ck_assert_int_eq (listen (srv.listen_fd, 1), 0);
    ck_assert_int_eq (getsockname (srv.listen_fd, (struct sockaddr *)&addr, &addr_len), 0);
    srv.port = ntohs (addr.sin_port);

    pthread_t thread;
    ck_assert_int_eq (pthread_create (&thread, NULL, ok_200_server_thread, &srv), 0);

    char host[64];
    snprintf (host, sizeof (host), "http://127.0.0.1:%u", srv.port);
    smm_connection conn = smm_asset_connect (host, "user", "pass");
    ck_assert_ptr_nonnull (conn);
    /* Freshly connected: state is NEW until a request succeeds. */
    ck_assert_int_eq (smm_asset_connection_get_state (conn), SMM_CONNECTION_NEW);

    struct buffer_s buf = { NULL, 0 };
    struct smm_curl_res_s *res = smm_connection_curl_retrieve_url (conn, "/assets/", NULL, &buf, true);
    ck_assert_ptr_nonnull (res);
    ck_assert_int_eq (res->success, true);
    ck_assert_int_eq (res->httpcode, 200);
    /* The successful request must have transitioned the state to CONNECTED. */
    ck_assert_int_eq (smm_asset_connection_get_state (conn), SMM_CONNECTION_CONNECTED);

    smm_curl_res_free (res);
    free (buf.data);
    pthread_join (thread, NULL);
    close (srv.listen_fd);
    smm_connection_close (conn);
}
END_TEST

/* Drives the CSRF-403 re-auth flow over four sequential connections:
 *   1. the initial POST            -> 403 (CSRF rejected)
 *   2. the login-page GET          -> 200 with a csrfmiddlewaretoken form
 *   3. the login POST              -> 302 (login succeeds, CSRF cookie rotates)
 *   4. the retried POST            -> retry_status (200 happy path, or 403 to
 *                                     prove the re-auth is bounded to one try)
 * Each response sets Connection: close, so every request is a fresh accept. */
struct csrf_server_s
{
    int listen_fd;
    long retry_status;
};

static void *
csrf_retry_server_thread (void *arg)
{
    struct csrf_server_s *srv = (struct csrf_server_s *)arg;
    static const char login_html[] = "<html><body><form method=\"post\">"
                                     "<input type=\"hidden\" name=\"csrfmiddlewaretoken\" value=\"tok123abc\">"
                                     "</form></body></html>";
    for (int step = 0; step < 4; step++)
    {
        int fd = accept (srv->listen_fd, NULL, NULL);
        if (fd < 0)
        {
            break;
        }
        char req[2048];
        (void)!read (fd, req, sizeof (req));
        char resp[1024];
        int n = 0;
        switch (step)
        {
            case 0: /* initial POST: CSRF rejected */
                n = snprintf (resp, sizeof (resp),
                              "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
                              "Content-Length: 0\r\nConnection: close\r\n\r\n");
                break;
            case 1: /* login page with the CSRF token */
                n = snprintf (resp, sizeof (resp),
                              "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                              "Set-Cookie: csrftoken=tok123abc; Path=/\r\n"
                              "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                              sizeof (login_html) - 1, login_html);
                break;
            case 2: /* login POST succeeds (Django answers 302) */
                n = snprintf (resp, sizeof (resp),
                              "HTTP/1.1 302 Found\r\nLocation: /\r\n"
                              "Set-Cookie: csrftoken=tok456def; Path=/\r\n"
                              "Content-Length: 0\r\nConnection: close\r\n\r\n");
                break;
            default: /* the retried POST */
                if (srv->retry_status == 200)
                {
                    n = snprintf (resp, sizeof (resp),
                                  "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                  "Content-Length: 2\r\nConnection: close\r\n\r\n{}");
                }
                else
                {
                    n = snprintf (resp, sizeof (resp),
                                  "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
                                  "Content-Length: 0\r\nConnection: close\r\n\r\n");
                }
                break;
        }
        (void)!write (fd, resp, (size_t)n);
        close (fd);
    }
    return NULL;
}

static smm_connection
csrf_server_start (struct csrf_server_s *srv, pthread_t *thread, long retry_status)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof (addr);

    srv->retry_status = retry_status;
    srv->listen_fd = socket (AF_INET, SOCK_STREAM, 0);
    ck_assert_int_ge (srv->listen_fd, 0);
    memset (&addr, 0, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    addr.sin_port = 0; /* ephemeral */
    ck_assert_int_eq (bind (srv->listen_fd, (struct sockaddr *)&addr, sizeof (addr)), 0);
    ck_assert_int_eq (listen (srv->listen_fd, 4), 0);
    ck_assert_int_eq (getsockname (srv->listen_fd, (struct sockaddr *)&addr, &addr_len), 0);
    uint16_t port = ntohs (addr.sin_port);

    ck_assert_int_eq (pthread_create (thread, NULL, csrf_retry_server_thread, srv), 0);

    char host[64];
    snprintf (host, sizeof (host), "http://127.0.0.1:%u", port);
    smm_connection conn = smm_asset_connect (host, "user", "pass");
    ck_assert_ptr_nonnull (conn);
    return conn;
}

START_TEST (test_post_403_triggers_reauth_and_retry)
{
    struct csrf_server_s srv;
    pthread_t thread;
    smm_connection conn = csrf_server_start (&srv, &thread, 200);

    /* The first POST is rejected with 403; the library must re-authenticate
     * and retry, and the retried POST (now carrying the refreshed token)
     * succeeds. */
    struct buffer_s buf = { NULL, 0 };
    struct smm_curl_res_s *res
        = smm_connection_curl_retrieve_url (conn, "/data/assets/1/position/add/", "lat=0.0&lon=0.0", &buf, false);
    ck_assert_ptr_nonnull (res);
    ck_assert_int_eq (res->success, true);
    ck_assert_int_eq (res->httpcode, 200);
    ck_assert_ptr_nonnull (conn->csrfmiddlewaretoken);
    ck_assert_str_eq (conn->csrfmiddlewaretoken, "tok456def");

    smm_curl_res_free (res);
    free (buf.data);
    pthread_join (thread, NULL);
    close (srv.listen_fd);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_post_403_reauth_is_bounded)
{
    struct csrf_server_s srv;
    pthread_t thread;
    smm_connection conn = csrf_server_start (&srv, &thread, 403);

    /* Re-auth succeeds but the retried POST is still 403 (e.g. a genuine
     * permission denial). The library must not loop: it re-authenticates once,
     * then surfaces the 403 rather than retrying forever. */
    struct buffer_s buf = { NULL, 0 };
    struct smm_curl_res_s *res
        = smm_connection_curl_retrieve_url (conn, "/data/assets/1/position/add/", "lat=0.0&lon=0.0", &buf, false);
    ck_assert_ptr_nonnull (res);
    ck_assert_int_eq (res->httpcode, 403);

    smm_curl_res_free (res);
    free (buf.data);
    pthread_join (thread, NULL);
    close (srv.listen_fd);
    smm_connection_close (conn);
}
END_TEST

/* Concurrency exercise for a shared connection. A pool of worker threads issues
 * requests on the same smm_connection at once, so the shared state touched on
 * every request -- the libcurl cookie share, the connection status, and the
 * CSRF token tracked from each response's Set-Cookie -- is read and written
 * concurrently. Functionally every request must succeed; run under
 * ThreadSanitizer (the dedicated CI job) it also asserts the locking is race
 * free. */
#define CONC_THREADS 4
#define CONC_REQUESTS_PER_THREAD 5
#define CONC_CONNECT_TIMEOUT_SECS 1L
#define CONC_TRANSFER_TIMEOUT_SECS 5L
#define CONC_ACCEPT_TIMEOUT_SECS 5

struct conc_server_s
{
    int listen_fd;
    int total; /* exact number of requests to serve, then return */
    int served;
};

struct conc_worker_s
{
    smm_connection conn;
    unsigned int failures;
};

static void *
conc_server_thread (void *arg)
{
    struct conc_server_s *srv = (struct conc_server_s *)arg;
    for (int i = 0; i < srv->total; i++)
    {
        fd_set read_fds;
        struct timeval timeout;
        FD_ZERO (&read_fds);
        FD_SET (srv->listen_fd, &read_fds);
        timeout.tv_sec = CONC_ACCEPT_TIMEOUT_SECS;
        timeout.tv_usec = 0;
        if (select (srv->listen_fd + 1, &read_fds, NULL, NULL, &timeout) <= 0)
        {
            break;
        }

        int fd = accept (srv->listen_fd, NULL, NULL);
        if (fd < 0)
        {
            break;
        }
        srv->served++;
        char req[1024];
        (void)!read (fd, req, sizeof (req));
        const char body[] = "{}";
        char resp[256];
        int n = snprintf (resp, sizeof (resp),
                          "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                          "Set-Cookie: csrftoken=tok123abc; Path=/\r\n"
                          "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                          sizeof (body) - 1, body);
        (void)!write (fd, resp, (size_t)n);
        close (fd);
    }
    return NULL;
}

static void *
conc_worker_thread (void *arg)
{
    struct conc_worker_s *worker = (struct conc_worker_s *)arg;
    for (int i = 0; i < CONC_REQUESTS_PER_THREAD; i++)
    {
        struct buffer_s buf = { NULL, 0 };
        struct smm_curl_res_s *res = smm_connection_curl_retrieve_url (worker->conn, "/assets/", NULL, &buf, true);
        if (res == NULL || !res->success || res->httpcode != 200)
        {
            worker->failures++;
        }
        if (res != NULL)
        {
            smm_curl_res_free (res);
        }
        free (buf.data);
    }
    return NULL;
}

START_TEST (test_concurrent_requests_shared_connection)
{
    struct conc_server_s srv;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof (addr);

    srv.total = CONC_THREADS * CONC_REQUESTS_PER_THREAD;
    srv.served = 0;
    srv.listen_fd = socket (AF_INET, SOCK_STREAM, 0);
    ck_assert_int_ge (srv.listen_fd, 0);
    memset (&addr, 0, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    addr.sin_port = 0; /* ephemeral */
    ck_assert_int_eq (bind (srv.listen_fd, (struct sockaddr *)&addr, sizeof (addr)), 0);
    ck_assert_int_eq (listen (srv.listen_fd, CONC_THREADS), 0);
    ck_assert_int_eq (getsockname (srv.listen_fd, (struct sockaddr *)&addr, &addr_len), 0);
    uint16_t port = ntohs (addr.sin_port);

    pthread_t server;
    ck_assert_int_eq (pthread_create (&server, NULL, conc_server_thread, &srv), 0);

    char host[64];
    snprintf (host, sizeof (host), "http://127.0.0.1:%u", port);
    smm_connection conn = smm_asset_connect (host, "user", "pass");
    ck_assert_ptr_nonnull (conn);
    smm_asset_connection_timeouts_set (conn, CONC_CONNECT_TIMEOUT_SECS, CONC_TRANSFER_TIMEOUT_SECS);

    pthread_t workers[CONC_THREADS];
    struct conc_worker_s worker_ctx[CONC_THREADS];
    for (int i = 0; i < CONC_THREADS; i++)
    {
        worker_ctx[i].conn = conn;
        worker_ctx[i].failures = 0;
        ck_assert_int_eq (pthread_create (&workers[i], NULL, conc_worker_thread, &worker_ctx[i]), 0);
    }
    unsigned int worker_failures = 0;
    for (int i = 0; i < CONC_THREADS; i++)
    {
        pthread_join (workers[i], NULL);
        worker_failures += worker_ctx[i].failures;
    }

    pthread_join (server, NULL);
    close (srv.listen_fd);
    ck_assert_int_eq (srv.served, srv.total);
    ck_assert_uint_eq (worker_failures, 0);
    ck_assert_int_eq (smm_asset_connection_get_state (conn), SMM_CONNECTION_CONNECTED);
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

START_TEST (test_connect_ftp_scheme_invalid)
{
    smm_connection conn = smm_asset_connect ("ftp://example.com", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    ck_assert_int_eq (smm_asset_connection_get_state (conn), SMM_CONNECTION_HOST_INVALID);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_connect_file_scheme_invalid)
{
    smm_connection conn = smm_asset_connect ("file:///tmp/smm", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    ck_assert_int_eq (smm_asset_connection_get_state (conn), SMM_CONNECTION_HOST_INVALID);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_connect_mailto_scheme_invalid)
{
    smm_connection conn = smm_asset_connect ("mailto:user@example.com", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    ck_assert_int_eq (smm_asset_connection_get_state (conn), SMM_CONNECTION_HOST_INVALID);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_connect_schemeless_invalid)
{
    smm_connection conn = smm_asset_connect ("example.com", "user", "pass");
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
    const char *json
        = "{\"features\": [{\"geometry\": {\"type\": \"LineString\", \"coordinates\": [[173, -44], [172, -43]]}}]}";
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

START_TEST (test_waypoints_parsing_non_linestring)
{
    const char *json = "{\"features\": [{\"geometry\": {\"type\": \"Point\", \"coordinates\": [[172.6, -43.5], [172.7, "
                       "-43.6]]}}]}";
    smm_waypoints waypoints = NULL;
    size_t count = 0;
    bool res = smm_parse_waypoints (json, strlen (json), &waypoints, &count);
    ck_assert_uint_eq (res, false);
    ck_assert_uint_eq (count, 0);
}
END_TEST

START_TEST (test_waypoints_parsing_single_point)
{
    /* A LineString needs at least two points; one is a malformed route. */
    const char *json
        = "{\"features\": [{\"geometry\": {\"type\": \"LineString\", \"coordinates\": [[172.6, -43.5]]}}]}";
    smm_waypoints waypoints = NULL;
    size_t count = 0;
    bool res = smm_parse_waypoints (json, strlen (json), &waypoints, &count);
    ck_assert_uint_eq (res, false);
    ck_assert_uint_eq (count, 0);
}
END_TEST

START_TEST (test_waypoints_parsing_empty_coordinates)
{
    const char *json = "{\"features\": [{\"geometry\": {\"type\": \"LineString\", \"coordinates\": []}}]}";
    smm_waypoints waypoints = NULL;
    size_t count = 0;
    bool res = smm_parse_waypoints (json, strlen (json), &waypoints, &count);
    ck_assert_uint_eq (res, false);
    ck_assert_uint_eq (count, 0);
}
END_TEST

START_TEST (test_waypoints_parsing_non_array_entry)
{
    /* Coordinate entries must themselves be [lon, lat] arrays. */
    const char *json = "{\"features\": [{\"geometry\": {\"type\": \"LineString\", \"coordinates\": [172.6, -43.5]}}]}";
    smm_waypoints waypoints = NULL;
    size_t count = 0;
    bool res = smm_parse_waypoints (json, strlen (json), &waypoints, &count);
    ck_assert_uint_eq (res, false);
    ck_assert_uint_eq (count, 0);
}
END_TEST

START_TEST (test_waypoints_parsing_tuple_missing_lat)
{
    const char *json
        = "{\"features\": [{\"geometry\": {\"type\": \"LineString\", \"coordinates\": [[172.6], [172.7]]}}]}";
    smm_waypoints waypoints = NULL;
    size_t count = 0;
    bool res = smm_parse_waypoints (json, strlen (json), &waypoints, &count);
    ck_assert_uint_eq (res, false);
    ck_assert_uint_eq (count, 0);
}
END_TEST

START_TEST (test_waypoints_parsing_nonnumeric_coord)
{
    const char *json = "{\"features\": [{\"geometry\": {\"type\": \"LineString\", \"coordinates\": [[\"x\", \"y\"], "
                       "[\"a\", \"b\"]]}}]}";
    smm_waypoints waypoints = NULL;
    size_t count = 0;
    bool res = smm_parse_waypoints (json, strlen (json), &waypoints, &count);
    ck_assert_uint_eq (res, false);
    ck_assert_uint_eq (count, 0);
}
END_TEST

START_TEST (test_waypoints_parsing_one_valid_one_invalid)
{
    /* A single bad point fails the whole parse rather than returning a
     * truncated route; the partially-built list must be discarded. */
    const char *json = "{\"features\": [{\"geometry\": {\"type\": \"LineString\", \"coordinates\": [[172.6, -43.5], "
                       "[\"x\", \"y\"]]}}]}";
    smm_waypoints waypoints = NULL;
    size_t count = 0;
    bool res = smm_parse_waypoints (json, strlen (json), &waypoints, &count);
    ck_assert_uint_eq (res, false);
    ck_assert_uint_eq (count, 0);
    ck_assert_ptr_null (waypoints);
}
END_TEST

START_TEST (test_waypoints_parsing_out_of_range)
{
    const char *json
        = "{\"features\": [{\"geometry\": {\"type\": \"LineString\", \"coordinates\": [[200.0, 0.0], [0.0, "
          "0.0]]}}]}";
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

START_TEST (test_build_position_body_values)
{
    char *body = smm_asset_build_position_body (-43.5, 172.6, 35, 270, 3);
    ck_assert_ptr_nonnull (body);
    ck_assert_ptr_nonnull (strstr (body, "lat=-43.500000"));
    ck_assert_ptr_nonnull (strstr (body, "alt=35"));
    ck_assert_ptr_nonnull (strstr (body, "heading=270"));
    ck_assert_ptr_nonnull (strstr (body, "fix=3"));
    free (body);
}
END_TEST

START_TEST (test_build_position_body_negative_altitude)
{
    /* Altitude may be below mean sea level; it must be sent as a signed value,
     * not wrapped through an unsigned conversion. */
    char *body = smm_asset_build_position_body (-43.5, 172.6, -12, 270, 3);
    ck_assert_ptr_nonnull (body);
    ck_assert_ptr_nonnull (strstr (body, "alt=-12"));
    free (body);
}
END_TEST

START_TEST (test_build_position_body_altitude_int32_range)
{
    /* The altitude parameter is int32_t; the full range must format intact. */
    char *body = smm_asset_build_position_body (-43.5, 172.6, INT32_MIN, 270, 3);
    ck_assert_ptr_nonnull (body);
    ck_assert_ptr_nonnull (strstr (body, "alt=-2147483648"));
    free (body);

    body = smm_asset_build_position_body (-43.5, 172.6, INT32_MAX, 270, 3);
    ck_assert_ptr_nonnull (body);
    ck_assert_ptr_nonnull (strstr (body, "alt=2147483647"));
    free (body);
}
END_TEST

START_TEST (test_build_position_body_heading_boundary)
{
    char *body0 = smm_asset_build_position_body (0.0, 0.0, 0, 0, 0);
    ck_assert_ptr_nonnull (body0);
    ck_assert_ptr_nonnull (strstr (body0, "heading=0"));
    free (body0);

    char *body359 = smm_asset_build_position_body (0.0, 0.0, 0, 359, 0);
    ck_assert_ptr_nonnull (body359);
    ck_assert_ptr_nonnull (strstr (body359, "heading=359"));
    free (body359);
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

START_TEST (test_version_string_composed_from_components)
{
    /* SMM_VERSION_STRING is now derived from the numeric components by
     * preprocessor stringification; check it matches an independently composed
     * "major.minor.patch" so the derivation can never silently produce a
     * malformed string. */
    char expected[32];
    snprintf (expected, sizeof (expected), "%d.%d.%d", SMM_VERSION_MAJOR, SMM_VERSION_MINOR, SMM_VERSION_PATCH);
    ck_assert_str_eq (SMM_VERSION_STRING, expected);
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

START_TEST (test_curl_global_init_succeeds)
{
    /* The wrapper initialises libcurl's global state once and is safe to call
     * repeatedly; both calls must report success. */
    ck_assert_int_eq (smm_curl_global_init (), true);
    ck_assert_int_eq (smm_curl_global_init (), true);
}
END_TEST

START_TEST (test_connection_timeouts_default_unset)
{
    /* A fresh connection carries no timeout override (0 == use the defaults). */
    smm_connection conn = smm_asset_connect ("http://example.com", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    ck_assert_int_eq (conn->connect_timeout_secs, 0);
    ck_assert_int_eq (conn->transfer_timeout_secs, 0);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_connection_timeouts_set_stores)
{
    smm_connection conn = smm_asset_connect ("http://example.com", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    smm_asset_connection_timeouts_set (conn, 5, 10);
    ck_assert_int_eq (conn->connect_timeout_secs, 5);
    ck_assert_int_eq (conn->transfer_timeout_secs, 10);
    smm_connection_close (conn);
}
END_TEST

START_TEST (test_connection_timeouts_set_null_safe)
{
    /* Must not crash on a NULL connection. */
    smm_asset_connection_timeouts_set (NULL, 5, 10);
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
    tcase_add_test (tc_conn, test_try_https_upgrade_preserves_port);
    tcase_add_test (tc_conn, test_eager_login_follows_https_upgrade);
    tcase_add_test (tc_conn, test_successful_request_sets_connected);
    tcase_add_test (tc_conn, test_post_403_triggers_reauth_and_retry);
    tcase_add_test (tc_conn, test_post_403_reauth_is_bounded);
    tcase_add_test (tc_conn, test_state_for_curl_error_http_error_keeps_state);
    tcase_add_test (tc_conn, test_state_for_curl_error_connection_failures);
    tcase_add_test (tc_conn, test_invalid_host);
    tcase_add_test (tc_conn, test_connect_ftp_scheme_invalid);
    tcase_add_test (tc_conn, test_connect_file_scheme_invalid);
    tcase_add_test (tc_conn, test_connect_mailto_scheme_invalid);
    tcase_add_test (tc_conn, test_connect_schemeless_invalid);
    tcase_add_test (tc_conn, test_connect_null_host);
    tcase_add_test (tc_conn, test_connect_null_user);
    tcase_add_test (tc_conn, test_connect_null_pass);
    tcase_add_test (tc_conn, test_connection_login_fields_initialised);
    tcase_add_test (tc_conn, test_curl_global_init_succeeds);
    tcase_add_test (tc_conn, test_connection_timeouts_default_unset);
    tcase_add_test (tc_conn, test_connection_timeouts_set_stores);
    tcase_add_test (tc_conn, test_connection_timeouts_set_null_safe);
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
    tcase_add_test (tc_conn, test_version_string_composed_from_components);
    suite_add_tcase (s, tc_conn);

    TCase *tc_conc = tcase_create ("Concurrency");
    tcase_set_timeout (tc_conc, 30);
    tcase_add_test (tc_conc, test_concurrent_requests_shared_connection);
    suite_add_tcase (s, tc_conc);

    TCase *tc_position = tcase_create ("Position");
    tcase_add_test (tc_position, test_build_position_body_heading);
    tcase_add_test (tc_position, test_build_position_body_locale_independent);
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
    tcase_add_test (tc_position, test_coords_valid_accepts_boundaries);
    tcase_add_test (tc_position, test_coords_valid_rejects_nan_inf);
    tcase_add_test (tc_position, test_coords_valid_rejects_out_of_range);
    tcase_add_test (tc_position, test_position_inputs_valid_heading);
    tcase_add_test (tc_position, test_position_inputs_valid_fix);
    tcase_add_test (tc_position, test_position_inputs_valid_full_boundary);
    tcase_add_test (tc_position, test_report_position_nan_sets_invalid_arg);
    tcase_add_test (tc_position, test_get_search_nan_sets_invalid_arg);
    tcase_add_test (tc_position, test_get_search_out_of_range_sets_invalid_arg);
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
    tcase_add_test (tc_assets, test_assets_parsing_zero_id);
    tcase_add_test (tc_assets, test_assets_parsing_negative_id);
    tcase_add_test (tc_assets, test_assets_parsing_negative_type_id);
    tcase_add_test (tc_assets, test_assets_parsing_zero_id_drops_only_invalid);
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
    tcase_add_test (tc_commands, test_command_parsing_goto_missing_latitude);
    tcase_add_test (tc_commands, test_command_parsing_goto_missing_longitude);
    tcase_add_test (tc_commands, test_command_parsing_goto_nonnumeric);
    tcase_add_test (tc_commands, test_command_parsing_goto_out_of_range_lat);
    tcase_add_test (tc_commands, test_command_parsing_goto_out_of_range_lon);
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
    tcase_add_test (tc_waypoints, test_waypoints_parsing_non_linestring);
    tcase_add_test (tc_waypoints, test_waypoints_parsing_single_point);
    tcase_add_test (tc_waypoints, test_waypoints_parsing_empty_coordinates);
    tcase_add_test (tc_waypoints, test_waypoints_parsing_non_array_entry);
    tcase_add_test (tc_waypoints, test_waypoints_parsing_tuple_missing_lat);
    tcase_add_test (tc_waypoints, test_waypoints_parsing_nonnumeric_coord);
    tcase_add_test (tc_waypoints, test_waypoints_parsing_one_valid_one_invalid);
    tcase_add_test (tc_waypoints, test_waypoints_parsing_out_of_range);
    suite_add_tcase (s, tc_waypoints);

    TCase *tc_search = tcase_create ("Search");
    tcase_add_test (tc_search, test_search_accept_null_conn);
    tcase_add_test (tc_search, test_search_accept_null_search);
    tcase_add_test (tc_search, test_search_complete_null_search);
    tcase_add_test (tc_search, test_search_get_waypoints_null_search);
    tcase_add_test (tc_search, test_asset_outlives_connection);
    tcase_add_test (tc_search, test_asset_create_balances_connection_ref);
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
    tcase_add_test (tc_search, test_get_search_root_url_rejected);
    tcase_add_test (tc_search, test_get_search_assets_url_rejected);
    tcase_add_test (tc_search, test_get_search_logout_url_rejected);
    tcase_add_test (tc_search, test_get_search_non_numeric_id_rejected);
    tcase_add_test (tc_search, test_get_search_negative_id_rejected);
    tcase_add_test (tc_search, test_get_search_zero_id_rejected);
    tcase_add_test (tc_search, test_search_from_response_404_is_clean_no_search);
    tcase_add_test (tc_search, test_search_from_response_non_json_200_sets_protocol);
    tcase_add_test (tc_search, test_search_from_response_invalid_json_sets_parse);
    tcase_add_test (tc_search, test_search_from_response_missing_object_url_sets_protocol);
    tcase_add_test (tc_search, test_search_from_response_unsafe_object_url_sets_protocol);
    tcase_add_test (tc_search, test_search_from_response_valid_returns_search);
    tcase_add_test (tc_search, test_search_from_response_server_error_sets_server);
    tcase_add_test (tc_search, test_get_search_requests_json);
    suite_add_tcase (s, tc_search);

    TCase *tc_buffer = tcase_create ("Buffer");
    tcase_add_test (tc_buffer, test_to_buffer_accumulates);
    tcase_add_test (tc_buffer, test_to_buffer_rejects_oversized_chunk);
    tcase_add_test (tc_buffer, test_to_buffer_rejects_when_full);
    tcase_add_test (tc_buffer, test_to_buffer_rejects_size_overflow);
    tcase_add_test (tc_buffer, test_buffer_reset_discards_content);
    tcase_add_test (tc_buffer, test_buffer_reset_null_safe);
    suite_add_tcase (s, tc_buffer);

    TCase *tc_secure = tcase_create ("SecureClear");
    tcase_add_test (tc_secure, test_secure_clear_zeroes);
    tcase_add_test (tc_secure, test_secure_clear_empty_string);
    tcase_add_test (tc_secure, test_secure_clear_null_safe);
    suite_add_tcase (s, tc_secure);

    TCase *tc_content_type = tcase_create ("ContentType");
    tcase_add_test (tc_content_type, test_content_type_is_json_plain);
    tcase_add_test (tc_content_type, test_content_type_is_json_with_charset);
    tcase_add_test (tc_content_type, test_content_type_is_json_case_insensitive);
    tcase_add_test (tc_content_type, test_content_type_is_json_leading_whitespace);
    tcase_add_test (tc_content_type, test_content_type_is_json_rejects_lookalikes);
    suite_add_tcase (s, tc_content_type);

    TCase *tc_position_ext = tcase_create ("PositionExt");
    tcase_add_test (tc_position_ext, test_build_position_body_values);
    tcase_add_test (tc_position_ext, test_build_position_body_negative_altitude);
    tcase_add_test (tc_position_ext, test_build_position_body_altitude_int32_range);
    tcase_add_test (tc_position_ext, test_build_position_body_heading_boundary);
    tcase_add_test (tc_position_ext, test_asset_last_goto_pos_not_goto);
    tcase_add_test (tc_position_ext, test_asset_last_goto_pos_goto);
    tcase_add_test (tc_position_ext, test_goto_then_malformed_goto_clears_position);
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
