#include "smm-asset.h"
#include <assert.h>
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

    smm_asset_free_assets (assets, count);
    smm_connection_close (conn);

    printf ("Integration test passed!\n");
    return 0;
}
