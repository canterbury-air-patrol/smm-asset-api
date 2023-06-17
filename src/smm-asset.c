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
#include "smm-asset.h"
#include "smm-asset-internal.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

enum http_return_codes {
	HTTP_SUCCESS = 200,
};

bool smm_debug = false;

void
smm_asset_debugging_set (bool debug)
{
	smm_debug = debug;
}

smm_connection
smm_asset_connect (const char *host, const char *user, const char *pass)
{
	smm_connection conn = calloc (1, sizeof (struct smm_connection_s));
	if (conn == NULL)
	{
		return NULL;
	}

	conn->host = strdup (host);
	conn->user = strdup (user);
	conn->pass = strdup (pass);
	pthread_mutex_init (&conn->lock, NULL);

	smm_connection_login (conn);

	return conn;
}

smm_connection_status
smm_asset_connection_get_state (smm_connection connection)
{
	if (connection == NULL)
	{
		return SMM_CONNECTION_UNKNOWN;
	}
	return connection->state;
}

void
smm_connection_close (smm_connection connection)
{
	if (connection != NULL)
	{
		free (connection->host);
		free (connection->user);
		free (connection->pass);
		free (connection->csrfmiddlewaretoken);
		curl_easy_cleanup (connection->curl);
		pthread_mutex_destroy(&connection->lock);
	}
	free (connection);
}

smm_asset
smm_asset_create (smm_connection conn, const char *name, const char *type, long long asset_id, long long asset_type_id)
{
	smm_asset asset = calloc (1, sizeof (struct smm_asset_s));
	asset->conn = conn;
	asset->name = name ? strdup (name) : NULL;
	asset->type = type ? strdup (type) : NULL;
	asset->asset_id = asset_id;
	asset->asset_type_id = asset_type_id;

	return asset;
}

bool
smm_asset_get_assets (smm_connection connection, smm_assets * assets, size_t * assets_count)
{
	struct buffer_s buf = { NULL, 0 };
	json_error_t json_error;

	struct smm_curl_res_s *res = smm_connection_curl_retrieve_url (connection, "/assets/mine/json/", NULL, to_buffer, &buf);
	if (res == NULL)
	{
		return false;
	}
	if (!(res->success && res->httpcode == HTTP_SUCCESS))
	{
		smm_curl_res_free (res);
		return false;
	}
	smm_curl_res_free (res);

	/* Parse the assets */
	*assets_count = 0;
	*assets = NULL;

	json_t *json_root = json_loadb (buf.data, buf.bytes, 0, &json_error);
	if (json_root)
	{
		json_t *json_assets = json_object_get (json_root, "assets");
		if (json_assets)
		{
			size_t index = 0;
			json_t *value = NULL;

			json_array_foreach (json_assets, index, value)
			{
				const char *key = NULL;
				json_t *val = NULL;
				json_int_t asset_id = -1;
				json_int_t asset_type_id = -1;
				const char *name = NULL;
				const char *type = NULL;
				json_object_foreach (value, key, val)
				{
					if (strcmp (key, "id") == 0)
					{
						asset_id = json_integer_value (val);
					}
					else if (strcmp (key, "type_id") == 0)
					{
						asset_type_id = json_integer_value (val);
					}
					else if (strcmp (key, "name") == 0)
					{
						name = json_string_value (val);
					}
					else if (strcmp (key, "type_name") == 0)
					{
						type = json_string_value (val);
					}
					else
					{
						if (json_is_integer (val))
						{
							printf ("%s = %lli\n", key, json_integer_value (val));
						}
						else if (json_is_string (val))
						{
							printf ("%s = %s\n", key, json_string_value (val));
						}
					}
				}
				*(assets_count) += 1;
				*assets = realloc (*assets, *assets_count * sizeof (smm_asset));
				(*assets)[(*assets_count) - 1] = smm_asset_create (connection, name, type, asset_id, asset_type_id);
			}
		}
		else
		{
			printf ("Didn't find assets\n");
		}
	}
	else
	{
		printf ("Error on line %i: %s\n", json_error.line, json_error.text);
	}

	json_decref (json_root);


	free (buf.data);
	return true;
}


void
smm_asset_free_asset (smm_asset asset)
{
	free (asset->name);
	free (asset->type);
	free (asset);
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

static long long
smm_asset_get_asset_id (smm_asset asset)
{
	return asset->asset_id;
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

static bool
smm_asset_update_command (smm_asset asset, struct buffer_s *buf)
{
	json_error_t json_error;

	json_t *json_root = json_loadb (buf->data, buf->bytes, 0, &json_error);
	if (json_root)
	{
		const char *command = NULL;

		json_t *tmp = json_object_get (json_root, "action");
		if (tmp)
		{
			command = json_string_value (tmp);
			if (strcmp (command, "GOTO") == 0)
			{
				/* Get lat and long as well */
				tmp = json_object_get (json_root, "latitude");
				if (tmp)
				{
					asset->last_command_lat = json_real_value (tmp);
				}
				tmp = json_object_get (json_root, "longitude");
				if (tmp)
				{
					asset->last_command_lon = json_real_value (tmp);
				}
				asset->last_command = SMM_COMMAND_GOTO;
			}
			else if (strcmp (command, "RON") == 0)
			{
				asset->last_command = SMM_COMMAND_CONTINUE;
			}
			else if (strcmp (command, "RTL") == 0)
			{
				asset->last_command = SMM_COMMAND_RTL;
			}
			else if (strcmp (command, "CIR") == 0)
			{
				asset->last_command = SMM_COMMAND_CIRCLE;
			}
			else if (strcmp (command, "AS") == 0)
			{
				asset->last_command = SMM_COMMAND_ABANDON_SEARCH;
			}
			else if (strcmp (command, "MC") == 0)
			{
				asset->last_command = SMM_COMMAND_MISSION_COMPLETE;
			}
			else
			{
				asset->last_command = SMM_COMMAND_UNKNOWN;
			}
		}

		json_decref (json_root);
	}
	else
	{
		printf ("Error on line %i: %s\n", json_error.line, json_error.text);
		asset->last_command = SMM_COMMAND_UNKNOWN;
	}

	return true;
}


smm_asset_command
smm_asset_last_command (smm_asset asset)
{
	return asset->last_command;
}

bool
smm_asset_last_goto_pos (smm_asset asset, double *lat, double *lon)
{
	if (asset->last_command != SMM_COMMAND_GOTO)
	{
		return false;
	}
	if (lat == NULL || lon == NULL)
	{
		return false;
	}
	*lat = asset->last_command_lat;
	*lon = asset->last_command_lon;
	return true;
}


bool
smm_asset_report_position (smm_asset asset, double latitude, double longitude, unsigned int altitude, uint16_t bearing, uint8_t fix)
{
	struct buffer_s buf = { NULL, 0 };

	char *page = NULL;
	if (asprintf (&page, "/data/assets/%s/position/add/?lat=%lf&lon=%lf&alt=%u&bearing=%u&fix=%u", asset->name, latitude, longitude, altitude, bearing, fix)
	    < 0)
	{
		return false;
	}

	struct smm_curl_res_s *res = smm_connection_curl_retrieve_url (asset->conn, page, NULL, to_buffer, &buf);
	if (res == NULL)
	{
		free (page);
		return false;
	}
	if (!(res->success && res->httpcode == HTTP_SUCCESS))
	{
		smm_curl_res_free (res);
		free (page);
		return false;
	}

	free (page);

	/* if json data was returned, update the current action */
	if (res->content_type != NULL && strcmp (res->content_type, "application/json") == 0)
	{
		smm_asset_update_command (asset, &buf);
	}
	else
	{
		if (buf.data && strncmp (buf.data, "Continue", buf.bytes) == 0)
		{
			asset->last_command = SMM_COMMAND_CONTINUE;
		}
		else
		{
			asset->last_command = SMM_COMMAND_NONE;
		}
	}

	free (buf.data);

	smm_curl_res_free (res);

	return true;
}

static smm_search
smm_search_create (smm_asset asset, const char *url, uint64_t length, uint64_t distance, uint64_t sweep_width)
{
	smm_search search = calloc (1, sizeof (struct smm_search_s));
	search->asset = asset;
	search->url = url ? strdup (url) : NULL;
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
smm_search_sweep_width(smm_search search)
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
		free (search->url);
		free (search);
	}
}

static smm_waypoint
smm_waypoint_create (double lat, double lon)
{
	smm_waypoint wp = calloc (1, sizeof (struct smm_waypoint_s));
	wp->lat = lat;
	wp->lon = lon;
	return wp;
}

static void
smm_waypoint_free (smm_waypoint waypoint)
{
	free (waypoint);
}


bool
smm_search_get_waypoints (smm_search search, smm_waypoints * waypoints, size_t * waypoints_count)
{
	struct buffer_s buf = { NULL, 0 };
	json_t *json_root = NULL;
	json_error_t json_error;

	struct smm_curl_res_s *res = smm_connection_curl_retrieve_url (search->asset->conn, search->url, NULL, to_buffer, &buf);

	if (res == NULL)
	{
		return false;
	}
	else if (!(res->success && res->httpcode == HTTP_SUCCESS))
	{
		/* Login, try again */
		smm_curl_res_free (res);
		return false;
	}

	smm_curl_res_free (res);


	/* Parse the assets */
	*waypoints_count = 0;
	*waypoints = NULL;

	json_root = json_loadb (buf.data, buf.bytes, 0, &json_error);
	if (json_root)
	{
		json_t *json_features = json_object_get (json_root, "features");
		if (json_features)
		{
			if (json_array_size (json_features) == 1)
			{

				printf ("Parsing waypoints\n");
				size_t index = 0;
				json_t *value = NULL;

				json_t *json_search = json_array_get (json_features, 0);
				if (json_search == NULL)
				{
					printf ("No json_search :(\n");
				}
				json_t *json_geometry = json_object_get (json_search, "geometry");
				if (json_geometry == NULL)
				{
					printf ("No json_geometry \n");
				}
				json_t *json_coords = json_object_get (json_geometry, "coordinates");
				if (json_coords == NULL)
				{
					printf ("No json_coords\n");
				}
				json_array_foreach (json_coords, index, value)
				{
					double lat = 0.0;
					double lon = 0.0;
					json_t *json_lat = json_array_get (value, 1);
					json_t *json_lon = json_array_get (value, 0);
					lat = json_real_value (json_lat);
					lon = json_real_value (json_lon);
					*(waypoints_count) += 1;
					*waypoints = realloc (*waypoints, *waypoints_count * sizeof (smm_waypoint));
					(*waypoints)[(*waypoints_count) - 1] = smm_waypoint_create (lat, lon);
				}
			}
			else
			{
				printf ("array size != 1 (%zi)", json_array_size (json_features));
			}
		}
		else
		{
			printf ("Didn't find waypoints\n");
		}
	}
	else
	{
		printf ("Error on line %i: %s\n", json_error.line, json_error.text);
	}

	json_decref (json_root);

	free (buf.data);

	return true;
}

static bool
smm_search_action (smm_search search, const char *action)
{
	char *action_page = NULL;
	struct buffer_s buf = { NULL, 0 };

	{
		char *tmp = strdup (search->url);
		char *json_str = strstr (tmp, "/json/");
		if (json_str)
		{
			*json_str = '\0';
			if (asprintf (&action_page, "%s/%s/?asset_id=%lli", tmp, action, smm_asset_get_asset_id (search->asset)) < 0)
			{
				free (tmp);
				return false;
			}
		}
		free (tmp);
	}
	if (action_page == NULL)
	{
		return false;
	}

	struct smm_curl_res_s *res = smm_connection_curl_retrieve_url (search->asset->conn, action_page, NULL, to_buffer, &buf);
	if (res == NULL)
	{
		return false;
	}
	else if (!(res->success && res->httpcode == HTTP_SUCCESS))
	{
		smm_curl_res_free (res);
		return false;
	}

	smm_curl_res_free (res);
	free (action_page);
	action_page = NULL;

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

smm_search
smm_asset_get_search (smm_asset asset, double latitude, double longitude)
{
	smm_search search = NULL;
	struct buffer_s buf = { NULL, 0 };

	char *page = NULL;
	if (asprintf (&page, "/search/find/closest/?asset_id=%lli&latitude=%lf&longitude=%lf", asset->asset_id, latitude, longitude) < 0)
	{
		return NULL;
	}

	struct smm_curl_res_s *res = smm_connection_curl_retrieve_url (asset->conn, page, NULL, to_buffer, &buf);
	if (res == NULL)
	{
		free (page);
		return false;
	}
	if (!(res->success && res->httpcode == HTTP_SUCCESS))
	{
		/* login and try again */
		smm_curl_res_free (res);
		free (page);
		return false;
	}
	free (page);

	if (res->content_type != NULL && strcmp (res->content_type, "application/json") == 0)
	{
		json_t *json_root = NULL;
		json_error_t json_error;

		json_root = json_loadb (buf.data, buf.bytes, 0, &json_error);
		if (json_root)
		{
			const char *url = NULL;
			uint64_t distance = 0;
			uint64_t length = 0;
			uint64_t sweep_width = 0;
			json_t *tmp = json_object_get (json_root, "object_url");
			if (tmp)
			{
				url = json_string_value (tmp);
			}
			tmp = json_object_get (json_root, "distance");
			if (tmp)
			{
				distance = json_integer_value (tmp);
			}
			tmp = json_object_get (json_root, "length");
			if (tmp)
			{
				length = json_integer_value (tmp);
			}
			tmp = json_object_get (json_root, "sweep_width");
			if (tmp)
			{
				sweep_width = json_integer_value (tmp);
			}
			search = smm_search_create (asset, url, length, distance, sweep_width);
			json_decref (json_root);
		}
	}
	smm_curl_res_free (res);
	free (buf.data);
	return search;
}
