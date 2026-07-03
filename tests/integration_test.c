#include "smm-asset.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main (void)
{
    smm_connection conn;
    smm_assets assets;
    size_t count;
    bool res;
    const char *host;
    const char *user;
    const char *pass;

    host = getenv ("SMM_HOST");
    if (!host)
        host = "http://localhost:8000";

    user = getenv ("SMM_USER");
    if (!user)
        user = "testuser";

    pass = getenv ("SMM_PASS");
    if (!pass)
        pass = "testpass";

    smm_asset_debugging_set (true);
    printf ("Connecting to SMM at %s...\n", host);
    conn = smm_asset_connect (host, user, pass);
    if (!conn)
    {
        fprintf (stderr, "No server available at %s, skipping\n", host);
        return 1;
    }

    printf ("Retrieving assets...\n");
    res = smm_asset_get_assets (conn, &assets, &count);
    if (!res)
    {
        fprintf (stderr, "Failed to get assets\n");
        smm_connection_close (conn);
        return 1;
    }

    printf ("Found %zu assets\n", count);
    assert (count > 0);

    for (size_t i = 0; i < count; i++)
    {
        printf ("Asset: %s (%s)\n", smm_asset_name (assets[i]), smm_asset_type (assets[i]));
    }

    /* Report a position. The endpoint is POST-only and CSRF-protected, so this
     * exercises the POST body and the X-CSRFToken header against a live server. */
    printf ("Reporting position for asset %s...\n", smm_asset_name (assets[0]));
    if (!smm_asset_report_position (assets[0], -43.5, 172.6, 35, 270, 3))
    {
        char msg[256];
        smm_error_code code = smm_asset_get_last_error (assets[0], msg, sizeof (msg));
        fprintf (stderr, "Failed to report position (error %d: %s)\n", code, msg);
        smm_asset_free_assets (assets, count);
        smm_connection_close (conn);
        return 1;
    }
    printf ("Position reported.\n");

    /* Full search lifecycle against the live server: find the closest search,
     * fetch its waypoints, accept it, report a position mid-search, and mark
     * it complete. This is the layer that catches the server changing its
     * contract — both GET->POST endpoint migrations (position reports, then
     * search begin/finished) shipped as regressions because only connect +
     * report-position was exercised here. Provisioning creates a sector
     * search centred on the position reported above. */
    printf ("Requesting a search for asset %s...\n", smm_asset_name (assets[0]));
    smm_search search = smm_asset_get_search (assets[0], -43.5, 172.6);
    if (!search)
    {
        char msg[256];
        smm_error_code code = smm_asset_get_last_error (assets[0], msg, sizeof (msg));
        fprintf (stderr, "No search offered (error %d: %s)\n", code, msg);
        smm_asset_free_assets (assets, count);
        smm_connection_close (conn);
        return 1;
    }
    printf ("Search offered: distance %" PRIu64 "m, length %" PRIu64 "m, sweep width %" PRIu64 "m\n",
            smm_search_distance (search), smm_search_length (search), smm_search_sweep_width (search));

    smm_waypoints waypoints = NULL;
    size_t waypoints_count = 0;
    if (!smm_search_get_waypoints (search, &waypoints, &waypoints_count))
    {
        char msg[256];
        smm_error_code code = smm_search_get_last_error (search, msg, sizeof (msg));
        fprintf (stderr, "Failed to get waypoints (error %d: %s)\n", code, msg);
        smm_search_destroy (search);
        smm_asset_free_assets (assets, count);
        smm_connection_close (conn);
        return 1;
    }
    printf ("Search has %zu waypoints\n", waypoints_count);
    assert (waypoints_count >= 2);

    if (!smm_search_accept (search))
    {
        char msg[256];
        smm_error_code code = smm_search_get_last_error (search, msg, sizeof (msg));
        fprintf (stderr, "Failed to accept search (error %d: %s)\n", code, msg);
        smm_waypoints_free (waypoints, waypoints_count);
        smm_search_destroy (search);
        smm_asset_free_assets (assets, count);
        smm_connection_close (conn);
        return 1;
    }
    printf ("Search accepted.\n");

    /* Report a position at the first waypoint, as an asset running the
     * search would. */
    if (!smm_asset_report_position (assets[0], waypoints[0]->lat, waypoints[0]->lon, 35, 270, 3))
    {
        char msg[256];
        smm_error_code code = smm_asset_get_last_error (assets[0], msg, sizeof (msg));
        fprintf (stderr, "Failed to report position mid-search (error %d: %s)\n", code, msg);
        smm_waypoints_free (waypoints, waypoints_count);
        smm_search_destroy (search);
        smm_asset_free_assets (assets, count);
        smm_connection_close (conn);
        return 1;
    }
    smm_waypoints_free (waypoints, waypoints_count);

    if (!smm_search_complete (search))
    {
        char msg[256];
        smm_error_code code = smm_search_get_last_error (search, msg, sizeof (msg));
        fprintf (stderr, "Failed to complete search (error %d: %s)\n", code, msg);
        smm_search_destroy (search);
        smm_asset_free_assets (assets, count);
        smm_connection_close (conn);
        return 1;
    }
    printf ("Search completed.\n");
    smm_search_destroy (search);

    smm_asset_free_assets (assets, count);
    smm_connection_close (conn);

    printf ("Integration test passed!\n");
    return 0;
}
