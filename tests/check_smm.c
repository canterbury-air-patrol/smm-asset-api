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
	const char *html
	    = "<html><body><input type=\"hidden\" name=\"somethingelse\" value=\"abcd1234\"></body></html>";
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

START_TEST (test_build_position_url_heading)
{
	char *url = smm_asset_build_position_url (42, -43.5, 172.6, 100, 270, 3);
	ck_assert_ptr_nonnull (url);
	ck_assert_ptr_nonnull (strstr (url, "heading="));
	ck_assert_ptr_null (strstr (url, "bearing="));
	free (url);
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

Suite *
smm_suite (void)
{
	Suite *s;
	TCase *tc_csrf;
	TCase *tc_conn;

	s = suite_create ("SMM");

	tc_conn = tcase_create ("Connection");
	tcase_add_test (tc_conn, test_invalid_host);
	tcase_add_test (tc_conn, test_connection_login_fields_initialised);
	suite_add_tcase (s, tc_conn);

	TCase *tc_position = tcase_create ("Position");
	tcase_add_test (tc_position, test_build_position_url_heading);
	tcase_add_test (tc_position, test_set_command_from_plaintext_continue);
	tcase_add_test (tc_position, test_set_command_from_plaintext_other);
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
	tcase_add_test (tc_commands, test_command_parsing_rtl);
	tcase_add_test (tc_commands, test_command_parsing_unknown);
	suite_add_tcase (s, tc_commands);

	TCase *tc_waypoints = tcase_create ("Waypoints");
	tcase_add_test (tc_waypoints, test_waypoint_parsing);
	suite_add_tcase (s, tc_waypoints);

	TCase *tc_search = tcase_create ("Search");
	tcase_add_test (tc_search, test_search_accept_null_conn);
	suite_add_tcase (s, tc_search);

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
