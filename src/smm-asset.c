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

_Atomic bool smm_debug = false;

void
smm_asset_debugging_set (bool debug)
{
	smm_debug = debug;
}

smm_connection
smm_asset_connect (const char *host, const char *user, const char *pass)
{
	if (host == NULL || user == NULL || pass == NULL)
		{
			return NULL;
		}

	smm_connection conn = calloc (1, sizeof (struct smm_connection_s));
	if (conn == NULL)
		{
			return NULL;
		}

	conn->host = strdup (host);
	conn->user = strdup (user);
	conn->pass = strdup (pass);
	conn->verify_tls = true;
	conn->refcount = 1;

	if (!conn->host || !conn->user || !conn->pass)
		{
			free (conn->host);
			free (conn->user);
			free (conn->pass);
			free (conn);
			return NULL;
		}

	pthread_mutex_init (&conn->lock, NULL);
	conn->login_in_progress = false;
	pthread_cond_init (&conn->login_cond, NULL);
	if (!smm_connection_share_init (conn))
		{
			conn->state = SMM_CONNECTION_FAILURE;
		}

	/* Early host validation */
	CURLU *curlu = curl_url ();
	if (curlu)
		{
			if (curl_url_set (curlu, CURLUPART_URL, host, 0) != CURLUE_OK)
				{
					conn->state = SMM_CONNECTION_HOST_INVALID;
				}
			curl_url_cleanup (curlu);
		}
	else
		{
			conn->state = SMM_CONNECTION_FAILURE;
		}

	return conn;
}

smm_connection_status
smm_asset_connection_get_state (smm_connection connection)
{
	if (connection == NULL)
		{
			return SMM_CONNECTION_UNKNOWN;
		}
	pthread_mutex_lock (&connection->lock);
	smm_connection_status state = connection->state;
	pthread_mutex_unlock (&connection->lock);
	return state;
}

void
smm_asset_connection_tls_verify_set (smm_connection connection, bool verify)
{
	if (connection != NULL)
		{
			pthread_mutex_lock (&connection->lock);
			connection->verify_tls = verify;
			pthread_mutex_unlock (&connection->lock);
		}
}

void
smm_connection_unref (smm_connection connection)
{
	if (connection == NULL)
		{
			return;
		}

	pthread_mutex_lock (&connection->lock);
	connection->refcount--;
	if (connection->refcount == 0)
		{
			pthread_mutex_unlock (&connection->lock);
			free (connection->host);
			free (connection->user);
			free (connection->pass);
			free (connection->csrfmiddlewaretoken);
			smm_connection_share_destroy (connection);
			pthread_cond_destroy (&connection->login_cond);
			pthread_mutex_destroy (&connection->lock);
			free (connection);
		}
	else
		{
			pthread_mutex_unlock (&connection->lock);
		}
}

void
smm_connection_close (smm_connection connection)
{
	smm_connection_unref (connection);
}

smm_asset
smm_asset_create (smm_connection conn, const char *name, const char *type, long long asset_id, long long asset_type_id)
{
	smm_asset asset = calloc (1, sizeof (struct smm_asset_s));
	if (asset == NULL)
		{
			return NULL;
		}

	asset->conn = conn;
	asset->name = name ? strdup (name) : NULL;
	asset->type = type ? strdup (type) : NULL;

	if ((name && !asset->name) || (type && !asset->type))
		{
			free (asset->name);
			free (asset->type);
			free (asset);
			return NULL;
		}

	asset->asset_id = asset_id;
	asset->asset_type_id = asset_type_id;

	pthread_mutex_init (&asset->lock, NULL);

	return asset;
}

bool
smm_parse_assets (smm_connection connection, const char *data, size_t len, smm_assets *assets, size_t *assets_count)
{
	json_error_t json_error;
	bool res = false;

	/* Parse the assets */
	*assets_count = 0;
	*assets = NULL;

	json_t *json_root = json_loadb (data, len, 0, &json_error);
	if (json_root)
		{
			json_t *json_assets = json_object_get (json_root, "assets");
			if (json_is_array (json_assets))
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
						}
						smm_asset new_asset = smm_asset_create (connection, name, type,
											asset_id, asset_type_id);
						if (new_asset)
							{
								smm_asset *tmp = realloc (
								    *assets, (*assets_count + 1) * sizeof (smm_asset));
								if (tmp)
									{
										*assets = tmp;
										(*assets)[*assets_count] = new_asset;
										*assets_count += 1;
									}
								else
									{
										smm_asset_free_asset (new_asset);
										smm_asset_free_assets (*assets,
												       *assets_count);
										*assets = NULL;
										*assets_count = 0;
										json_decref (json_root);
										return false;
									}
							}
					}
					res = true;
				}
			else
				{
					DEBUG ("Didn't find assets array in JSON\n");
				}
			json_decref (json_root);
		}
	else
		{
			DEBUG ("JSON Parse Error on line %i: %s\n", json_error.line, json_error.text);
		}

	return res;
}

bool
smm_asset_get_assets (smm_connection connection, smm_assets *assets, size_t *assets_count)
{
	struct buffer_s buf = { NULL, 0 };

	if (assets == NULL || assets_count == NULL)
		{
			return false;
		}

	*assets = NULL;
	*assets_count = 0;

	struct smm_curl_res_s *res
	    = smm_connection_curl_retrieve_url (connection, "/assets/", NULL, to_buffer, &buf, true);
	if (res == NULL)
		{
			return false;
		}
	if (!(res->success && res->httpcode == HTTP_SUCCESS))
		{
			smm_curl_res_free (res);
			free (buf.data);
			return false;
		}
	smm_curl_res_free (res);

	bool parse_res = smm_parse_assets (connection, buf.data, buf.bytes, assets, assets_count);

	free (buf.data);
	return parse_res;
}

void
smm_asset_free_asset (smm_asset asset)
{
	if (asset)
		{
			free (asset->name);
			free (asset->type);
			pthread_mutex_destroy (&asset->lock);
			free (asset);
		}
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

bool
smm_parse_command (const char *data, size_t len, smm_asset_command *command, double *lat, double *lon)
{
	json_error_t json_error;
	bool res = false;

	*command = SMM_COMMAND_UNKNOWN;

	json_t *json_root = json_loadb (data, len, 0, &json_error);
	if (json_root)
		{
			json_t *tmp = json_object_get (json_root, "action");
			if (json_is_string (tmp))
				{
					const char *cmd_str = json_string_value (tmp);
					if (cmd_str)
						{
							res = true;
							if (strcmp (cmd_str, "GOTO") == 0)
								{
									/* Get lat and long as well. Accept any
									 * JSON number (real or integer); the
									 * server normally emits floats but the
									 * contract does not guarantee it. */
									tmp = json_object_get (json_root, "latitude");
									if (json_is_number (tmp))
										{
											*lat = json_number_value (tmp);
										}
									tmp = json_object_get (json_root, "longitude");
									if (json_is_number (tmp))
										{
											*lon = json_number_value (tmp);
										}
									*command = SMM_COMMAND_GOTO;
								}
							else if (strcmp (cmd_str, "RON") == 0)
								{
									*command = SMM_COMMAND_CONTINUE;
								}
							else if (strcmp (cmd_str, "RTL") == 0)
								{
									*command = SMM_COMMAND_RTL;
								}
							else if (strcmp (cmd_str, "CIR") == 0)
								{
									*command = SMM_COMMAND_CIRCLE;
								}
							else if (strcmp (cmd_str, "AS") == 0)
								{
									*command = SMM_COMMAND_ABANDON_SEARCH;
								}
							else if (strcmp (cmd_str, "MC") == 0)
								{
									*command = SMM_COMMAND_MISSION_COMPLETE;
								}
							else
								{
									*command = SMM_COMMAND_UNKNOWN;
								}
						}
				}

			json_decref (json_root);
		}
	else
		{
			DEBUG ("JSON Parse Error on line %i: %s\n", json_error.line, json_error.text);
		}

	return res;
}

static bool
smm_asset_update_command (smm_asset asset, struct buffer_s *buf)
{
	bool res;
	pthread_mutex_lock (&asset->lock);
	res = smm_parse_command (buf->data, buf->bytes, &asset->last_command, &asset->last_command_lat,
				 &asset->last_command_lon);
	pthread_mutex_unlock (&asset->lock);
	return res;
}

smm_asset_command
smm_asset_last_command (smm_asset asset)
{
	smm_asset_command cmd;
	pthread_mutex_lock (&asset->lock);
	cmd = asset->last_command;
	pthread_mutex_unlock (&asset->lock);
	return cmd;
}

bool
smm_asset_last_goto_pos (smm_asset asset, double *lat, double *lon)
{
	bool res = false;
	pthread_mutex_lock (&asset->lock);
	if (asset->last_command == SMM_COMMAND_GOTO)
		{
			if (lat != NULL && lon != NULL)
				{
					*lat = asset->last_command_lat;
					*lon = asset->last_command_lon;
					res = true;
				}
		}
	pthread_mutex_unlock (&asset->lock);
	return res;
}

#define CONTINUE_STR "Continue"
#define CONTINUE_LEN (sizeof (CONTINUE_STR) - 1)

void
smm_asset_set_command_from_plaintext (smm_asset asset, const char *data, size_t len)
{
	pthread_mutex_lock (&asset->lock);
	if (data && len >= CONTINUE_LEN && strncmp (data, CONTINUE_STR, CONTINUE_LEN) == 0)
		{
			asset->last_command = SMM_COMMAND_CONTINUE;
		}
	else
		{
			asset->last_command = SMM_COMMAND_NONE;
		}
	pthread_mutex_unlock (&asset->lock);
}

char *
smm_asset_build_position_url (long long asset_id, double lat, double lon, unsigned int alt, uint16_t heading,
			      uint8_t fix)
{
	char *page = NULL;
	if (asprintf (&page, "/data/assets/%lld/position/add/?lat=%lf&lon=%lf&alt=%u&heading=%u&fix=%u", asset_id, lat,
		      lon, alt, heading, fix)
	    < 0)
		{
			return NULL;
		}
	return page;
}

bool
smm_asset_report_position (smm_asset asset, double latitude, double longitude, unsigned int altitude, uint16_t heading,
			   uint8_t fix)
{
	struct buffer_s buf = { NULL, 0 };

	char *page = smm_asset_build_position_url (asset->asset_id, latitude, longitude, altitude, heading, fix);
	if (page == NULL)
		{
			return false;
		}

	struct smm_curl_res_s *res = smm_connection_curl_retrieve_url (asset->conn, page, NULL, to_buffer, &buf, false);
	if (res == NULL)
		{
			free (page);
			return false;
		}
	if (!(res->success && res->httpcode == HTTP_SUCCESS))
		{
			smm_curl_res_free (res);
			free (page);
			free (buf.data);
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
			smm_asset_set_command_from_plaintext (asset, buf.data, buf.bytes);
		}

	free (buf.data);

	smm_curl_res_free (res);

	return true;
}

static smm_search
smm_search_create (smm_asset asset, const char *url, uint64_t length, uint64_t distance, uint64_t sweep_width)
{
	smm_search search = calloc (1, sizeof (struct smm_search_s));
	if (search == NULL)
		{
			return NULL;
		}

	search->asset = asset;
	search->url = url ? strdup (url) : NULL;

	if (url && !search->url)
		{
			free (search);
			return NULL;
		}

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
smm_search_sweep_width (smm_search search)
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
	if (wp == NULL)
		{
			return NULL;
		}
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
smm_parse_waypoints (const char *data, size_t len, smm_waypoints *waypoints, size_t *waypoints_count)
{
	json_error_t json_error;
	bool res = false;

	/* Parse the waypoints */
	*waypoints_count = 0;
	*waypoints = NULL;

	json_t *json_root = json_loadb (data, len, 0, &json_error);
	if (json_root)
		{
			json_t *json_features = json_object_get (json_root, "features");
			if (json_is_array (json_features))
				{
					if (json_array_size (json_features) == 1)
						{
							json_t *json_search = json_array_get (json_features, 0);
							if (json_is_object (json_search))
								{
									json_t *json_geometry
									    = json_object_get (json_search, "geometry");
									if (json_is_object (json_geometry))
										{
											json_t *json_coords
											    = json_object_get (
												json_geometry,
												"coordinates");
											if (json_is_array (json_coords))
												{
													size_t index
													    = 0;
													json_t *value
													    = NULL;
													json_array_foreach (
													    json_coords,
													    index,
													    value)
													{
														double
														    lat
														    = 0.0;
														double
														    lon
														    = 0.0;
														json_t *
														    json_lat
														    = json_array_get (
															value,
															1);
														json_t *
														    json_lon
														    = json_array_get (
															value,
															0);
														if (!json_is_number (json_lat) || !json_is_number (json_lon))
															{
															    continue;
															}
														lat = json_number_value (
														    json_lat);
														lon = json_number_value (
														    json_lon);
														smm_waypoint
														    new_wp
														    = smm_waypoint_create (
															lat,
															lon);
														if (new_wp)
															{
																smm_waypoint *tmp = realloc (
																    *waypoints,
																    (*waypoints_count
																     + 1)
																	* sizeof (
																	    smm_waypoint));
																if (tmp)
																	{
																		*waypoints
																		    = tmp;
																		(*waypoints)
																		    [*waypoints_count]
																		    = new_wp;
																		*waypoints_count
																		    += 1;
																	}
																else
																	{
																		smm_waypoint_free (
																		    new_wp);
																		smm_waypoints_free (
																		    *waypoints,
																		    *waypoints_count);
																		*waypoints
																		    = NULL;
																		*waypoints_count
																		    = 0;
																		json_decref (
																		    json_root);
																		return false;
																	}
															}
													}
													res = true;
												}
										}
								}
						}
					else
						{
							DEBUG ("GeoJSON features array size != 1 (%zi)\n",
							       json_array_size (json_features));
						}
				}
			else
				{
					DEBUG ("Didn't find features array in GeoJSON\n");
				}
			json_decref (json_root);
		}
	else
		{
			DEBUG ("JSON Parse Error on line %i: %s\n", json_error.line, json_error.text);
		}

	return res;
}

bool
smm_search_get_waypoints (smm_search search, smm_waypoints *waypoints, size_t *waypoints_count)
{
	struct buffer_s buf = { NULL, 0 };

	if (waypoints == NULL || waypoints_count == NULL)
		{
			return false;
		}

	*waypoints = NULL;
	*waypoints_count = 0;

	struct smm_curl_res_s *res
	    = smm_connection_curl_retrieve_url (search->asset->conn, search->url, NULL, to_buffer, &buf, true);

	if (res == NULL)
		{
			return false;
		}
	else if (!(res->success && res->httpcode == HTTP_SUCCESS))
		{
			smm_curl_res_free (res);
			free (buf.data);
			return false;
		}
	smm_curl_res_free (res);

	bool parse_res = smm_parse_waypoints (buf.data, buf.bytes, waypoints, waypoints_count);

	free (buf.data);

	return parse_res;
}

static bool
smm_search_action (smm_search search, const char *action)
{
	char *action_page = NULL;
	struct buffer_s buf = { NULL, 0 };

	if (asprintf (&action_page, "%s%s/?asset_id=%lli", search->url, action, smm_asset_get_asset_id (search->asset))
	    < 0)
		{
			return false;
		}

	struct smm_curl_res_s *res
	    = smm_connection_curl_retrieve_url (search->asset->conn, action_page, NULL, to_buffer, &buf, false);
	if (res == NULL)
		{
			free (action_page);
			return false;
		}
	else if (!(res->success && res->httpcode == HTTP_SUCCESS))
		{
			smm_curl_res_free (res);
			free (action_page);
			free (buf.data);
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
smm_parse_search_json (smm_asset asset, const char *data, size_t len)
{
	smm_search search = NULL;
	json_t *json_root = NULL;
	json_error_t json_error;

	json_root = json_loadb (data, len, 0, &json_error);
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
			/* The server contract emits object_url as a relative path
			 * (e.g. "/search/42/"). Reject absolute URLs defensively in
			 * case the contract ever changes — accepting them blindly
			 * here would let the server steer us at an arbitrary host. */
			if (url && (strncmp (url, "http://", 7) == 0 || strncmp (url, "https://", 8) == 0))
				{
					DEBUG ("object_url is absolute; ignoring\n");
					url = NULL;
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
			if (url)
				{
					search = smm_search_create (asset, url, length, distance, sweep_width);
				}
			json_decref (json_root);
		}
	else
		{
			DEBUG ("JSON Parse Error on line %i: %s\n", json_error.line, json_error.text);
		}
	return search;
}

smm_search
smm_asset_get_search (smm_asset asset, double latitude, double longitude)
{
	smm_search search = NULL;
	struct buffer_s buf = { NULL, 0 };

	char *page = NULL;
	if (asprintf (&page, "/search/find/closest/?asset_id=%lli&latitude=%lf&longitude=%lf", asset->asset_id,
		      latitude, longitude)
	    < 0)
		{
			return NULL;
		}

	struct smm_curl_res_s *res = smm_connection_curl_retrieve_url (asset->conn, page, NULL, to_buffer, &buf, false);
	if (res == NULL)
		{
			free (page);
			return NULL;
		}
	if (!(res->success && res->httpcode == HTTP_SUCCESS))
		{
			/* login and try again */
			smm_curl_res_free (res);
			free (page);
			free (buf.data);
			return NULL;
		}
	free (page);

	if (res->content_type != NULL && strcmp (res->content_type, "application/json") == 0)
		{
			search = smm_parse_search_json (asset, buf.data, buf.bytes);
		}
	smm_curl_res_free (res);
	free (buf.data);
	return search;
}
