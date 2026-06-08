# Search Management Map Asset API

A C library for accessing the asset side of the API for [Search Management Map](https://github.com/canterbury-air-patrol/search-management-map)

## Getting started
### Prerequisites

 * [libcurl](https://curl.haxx.se)
 * [libtidy](http://html-tidy.org)
 * [Jansson](http://www.digip.org/jansson/)

### Fetching and building

```
git clone https://github.com/canterbury-air-patrol/smm-asset-api.git
cd smm-asset-api
./autogen.sh
./configure --prefix=/usr
make
make install
```

### Using

Link your program against -lsmmasset or use pkg-config with the installed smm-asset.pc.

Basic API usage example
```c
#include <smm-asset.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
	smm_assets assets;
	size_t assets_count;
	smm_asset asset = NULL;

	smm_connection conn = smm_asset_connect ("http://localhost/", "asset", "assetpassword");
	if (smm_asset_get_assets (conn, &assets, &assets_count))
	{
		for (size_t i = 0; i < assets_count; i++)
		{
			if (strcmp (smm_asset_name (assets[i]), "my-asset") == 0)
			{
				asset = assets[i];
			}
		}
	}
	if (asset != NULL)
	{
		/* Report this assets position as 43 deg South, 172 deg East, 35 meters high, heading west, 3d fix */ 
		smm_asset_report_position (asset, -43, 172, 35, 270, 3);

		/* You can also get a search to conduct by */
		smm_search search;
		while ((search = smm_asset_get_search (asset, -43, 172)) != NULL)
		{
			if (smm_search_accept (search))
			{
				break;
			}
			/* The server declined this search; discard it and ask again */
			smm_search_destroy (search);
		}

		if (search != NULL)
		{
			/* All the waypoints for the search are accessible with */
			smm_waypoints waypoints;
			size_t waypoints_count;
			if (smm_search_get_waypoints (search, &waypoints, &waypoints_count))
			{
				/* Iterate them the same as assets, then free with */
				smm_waypoints_free (waypoints, waypoints_count);
			}
			/* Once the search is completed then */
			smm_search_complete (search);
			smm_search_destroy (search);
		}
	}

	smm_asset_free_assets (assets, assets_count);
	smm_connection_close (conn);
}
```

## Authors
See the list of [contributors](https://github.com/canterbury-air-patrol/smm-asset-api/contributors).

## License
This project is licensed under GNU LGPLv2.1 see the [LICENSE.md](LICENSE.md) file for details.
