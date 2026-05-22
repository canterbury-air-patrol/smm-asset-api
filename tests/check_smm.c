#include "smm-asset-internal.h"
#include "smm-asset.h"
#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

START_TEST (test_search_accept_null_conn)
{
    struct smm_asset_s asset_s;
    memset (&asset_s, 0, sizeof (asset_s));
    asset_s.asset_id = 1;
    pthread_mutex_init (&asset_s.lock, NULL);
    struct smm_search_s search_s;
    memset (&search_s, 0, sizeof (search_s));
    search_s.asset = &asset_s;
    search_s.url = strdup ("/search/1/");
    bool r = smm_search_accept (&search_s);
    ck_assert_int_eq (r, false);
    free (search_s.url);
    pthread_mutex_destroy (&asset_s.lock);
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

START_TEST (test_get_state_null_connection)
{
    ck_assert_int_eq (smm_asset_connection_get_state (NULL), SMM_CONNECTION_UNKNOWN);
}
END_TEST

START_TEST (test_get_state_initial)
{
    smm_connection conn = smm_asset_connect ("http://localhost/", "user", "pass");
    ck_assert_ptr_nonnull (conn);
    ck_assert_int_eq (smm_asset_connection_get_state (conn), SMM_CONNECTION_UNKNOWN);
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
    tcase_add_test (tc_conn, test_login_in_progress_reset_on_failure);
    tcase_add_test (tc_conn, test_invalid_host);
    tcase_add_test (tc_conn, test_connect_null_host);
    tcase_add_test (tc_conn, test_connect_null_user);
    tcase_add_test (tc_conn, test_connect_null_pass);
    tcase_add_test (tc_conn, test_connection_login_fields_initialised);
    tcase_add_test (tc_conn, test_get_state_null_connection);
    tcase_add_test (tc_conn, test_get_state_initial);
    tcase_add_test (tc_conn, test_debugging_set);
    suite_add_tcase (s, tc_conn);

    TCase *tc_position = tcase_create ("Position");
    tcase_add_test (tc_position, test_build_position_url_heading);
    tcase_add_test (tc_position, test_set_command_from_plaintext_continue);
    tcase_add_test (tc_position, test_set_command_from_plaintext_other);
    tcase_add_test (tc_position, test_set_command_from_plaintext_null);
    tcase_add_test (tc_position, test_set_command_from_plaintext_zero_length);
    tcase_add_test (tc_position, test_set_command_from_plaintext_with_trailing);
    tcase_add_test (tc_position, test_report_position_null_conn);
    suite_add_tcase (s, tc_position);

    tc_csrf = tcase_create ("CSRF");
    tcase_add_test (tc_csrf, test_csrf_extraction);
    tcase_add_test (tc_csrf, test_csrf_extraction_missing);
    tcase_add_test (tc_csrf, test_csrf_extraction_invalid_chars);
    tcase_add_test (tc_csrf, test_csrf_extraction_too_long);
    suite_add_tcase (s, tc_csrf);

    TCase *tc_assets = tcase_create ("Assets");
    tcase_add_test (tc_assets, test_assets_parsing);
    tcase_add_test (tc_assets, test_assets_parsing_empty);
    tcase_add_test (tc_assets, test_assets_parsing_invalid);
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
    suite_add_tcase (s, tc_waypoints);

    TCase *tc_search = tcase_create ("Search");
    tcase_add_test (tc_search, test_search_accept_null_conn);
    tcase_add_test (tc_search, test_search_sweep_width);
    tcase_add_test (tc_search, test_search_distance_and_length);
    tcase_add_test (tc_search, test_get_search_absolute_url_ignored);
    tcase_add_test (tc_search, test_get_search_http_absolute_url_ignored);
    tcase_add_test (tc_search, test_get_search_nonstring_object_url_returns_null);
    tcase_add_test (tc_search, test_get_search_missing_object_url_returns_null);
    tcase_add_test (tc_search, test_get_search_relative_url_accepted);
    suite_add_tcase (s, tc_search);

    TCase *tc_position_ext = tcase_create ("PositionExt");
    tcase_add_test (tc_position_ext, test_build_position_url_values);
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
