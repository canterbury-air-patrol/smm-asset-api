#pragma once

/**
 * smm-asset-internal.h, Internal structures and headers for libsmm-asset
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

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>

#include <curl/curl.h>

enum http_return_codes
{
	HTTP_SUCCESS = 200,
	HTTP_MOVED_PERMANENTLY = 301,
	HTTP_FOUND = 302,
	HTTP_SEE_OTHER = 303,
};

extern _Atomic bool smm_debug;
#define DEBUG(...)                                                                                                     \
	do                                                                                                             \
	{                                                                                                              \
		if (smm_debug)                                                                                         \
		{                                                                                                      \
			printf ("%s:%i ", __func__, __LINE__);                                                         \
			printf (__VA_ARGS__);                                                                          \
		}                                                                                                      \
	} while (0)

struct smm_connection_s
{
	char *host;
	char *user;
	char *pass;
	smm_connection_status state;
	CURLSH *share;
	char *csrfmiddlewaretoken;
	pthread_mutex_t lock;
	bool verify_tls;
	int refcount;
	bool login_in_progress;
	pthread_cond_t login_cond;
};

struct smm_asset_s
{
	smm_connection conn;
	char *name;
	char *type;
	long long asset_id;
	long long asset_type_id;
	smm_asset_command last_command;
	double last_command_lat;
	double last_command_lon;
	pthread_mutex_t lock;
};

struct smm_search_s
{
	smm_asset asset;
	char *url;
	uint64_t distance;
	uint64_t length;
	uint64_t sweep_width;
};

struct smm_curl_res_s
{
	bool success;
	long httpcode;
	char *full_uri;
	char *redirect_url;
	char *content_type;
};

struct buffer_s
{
	char *data;
	size_t bytes;
};

size_t to_buffer (char *ptr, size_t size, size_t nmemb, void *userdata);

bool smm_connection_share_init (smm_connection conn);
void smm_connection_share_destroy (smm_connection conn);

void smm_connection_unref (smm_connection conn);

void smm_curl_res_free (struct smm_curl_res_s *);
/* Raw single-shot fetch: no retry, no login redirect, no HTTPS upgrade.
 * Use this inside login itself to avoid re-entrant login attempts. */
struct smm_curl_res_s *smm_connection_curl_retrieve_url_r (smm_connection conn, const char *path, const char *post_data,
							   size_t (*write_func) (char *ptr, size_t size, size_t nmemb,
										 void *userdata),
							   void *write_data, bool json);
struct smm_curl_res_s *smm_connection_curl_retrieve_url (smm_connection conn, const char *path, const char *post_data,
							 size_t (*write_func) (char *ptr, size_t size, size_t nmemb,
									       void *userdata),
							 void *write_data, bool json);
bool smm_asset_connection_login (smm_connection connection);
char *smm_parse_csrf_token (const char *data, size_t len);
bool smm_parse_assets (smm_connection connection, const char *data, size_t len, smm_assets *assets,
		       size_t *assets_count);
bool smm_parse_command (const char *data, size_t len, smm_asset_command *command, double *lat, double *lon);
bool smm_parse_waypoints (const char *data, size_t len, smm_waypoints *waypoints, size_t *waypoints_count);

smm_asset smm_asset_create (smm_connection connection, const char *name, const char *type, long long asset_id,
			    long long asset_type_id);
void smm_asset_free_asset (smm_asset assets);

char *smm_asset_build_position_url (long long asset_id, double lat, double lon, unsigned int alt, uint16_t heading,
				    uint8_t fix);

void smm_asset_set_command_from_plaintext (smm_asset asset, const char *data, size_t len);

smm_search smm_parse_search_json (smm_asset asset, const char *data, size_t len);
