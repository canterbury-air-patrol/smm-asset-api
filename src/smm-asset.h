#pragma once

/**
 * smm-asset.h, The Asset interface to Search Management Map
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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * An opaque object for accessing the smm
 */
typedef struct smm_connection_s *smm_connection;

/**
 * An opaque object that represents an asset on the smm
 */
typedef struct smm_asset_s *smm_asset;

/**
 * A list of opaque objects that represent assets on the smm
 */
typedef struct smm_asset_s **smm_assets;

/**
 * An opaque objec that represents a search on the smm
 */
typedef struct smm_search_s *smm_search;

/**
 * A waypoint
 */
typedef struct smm_waypoint_s
{
	double lat;
	double lon;
} *smm_waypoint;

/**
 * A list of waypoints
 */
typedef struct smm_waypoint_s **smm_waypoints;

/**
 * Possible current states for an smm_connection object
 */
typedef enum
{
	SMM_CONNECTION_UNKNOWN,		       /*!< Unknown state or invalid object */
	SMM_CONNECTION_CONNECTED,	       /*!< Currently connected */
	SMM_CONNECTION_HOST_INVALID,	       /*!< Host URL invalid, i.e. not http(s):// or not a valid domain */
	SMM_CONNECTION_NO_HOST_CONNECTION,     /*!< Unable to connect to host */
	SMM_CONNECTION_AUTHENTICATION_FAILURE, /*!< Unable to authenticate with host */
	SMM_CONNECTION_PROTOCOL_ERROR,	       /*!< Unexpected response from host */
	SMM_CONNECTION_FAILURE,		       /*!< Unable to communicate, for another reason */
} smm_connection_status;

/**
 * Possible commands for an asset
 */
typedef enum
{
	SMM_COMMAND_NONE,	      /*!< No restriction on current operation */
	SMM_COMMAND_CIRCLE,	      /*!< Circle/Hold at current position */
	SMM_COMMAND_RTL,	      /*!< Return to launch site */
	SMM_COMMAND_GOTO,	      /*!< Goto to the specified position */
	SMM_COMMAND_CONTINUE,	      /*!< Previous command revoked, resume own navigation */
	SMM_COMMAND_ABANDON_SEARCH,   /*!< Abandon the current search, expect reassignment */
	SMM_COMMAND_MISSION_COMPLETE, /*!< The mission has concluded, return to base */
	SMM_COMMAND_UNKNOWN,	      /*!< The command from the server is not known */
} smm_asset_command;

/**
 * Enable/disable the debugging
 *
 * @param debug true to enable debugging, false to disable
 *
 */
void smm_asset_debugging_set (bool debug);

/**
 * Connect to the specified smm
 *
 * @param host the URI of the smm server (i.e. https://smm.example.com)
 * @param user the username to authenticate as
 * @param pass the password to authenticate with
 *
 * @return an smm_connection object, check the status with @ref smm_asset_connection_status
 */
smm_connection smm_asset_connect (const char *host, const char *user, const char *pass);

/**
 * Check the state of a connection
 *
 * @param connection the smm_connection object to check
 *
 * @return The current state of the connection
 */
smm_connection_status smm_asset_connection_get_state (smm_connection connection);

/**
 * Enable/disable TLS verification for a connection.
 * TLS verification is enabled by default.
 *
 * @param connection the smm_connection object
 * @param verify true to enable TLS verification, false to disable
 */
void smm_asset_connection_tls_verify_set (smm_connection connection, bool verify);

/**
 * Close a connection to smm and free associated resources.
 *
 * This function should only be called when no other threads are actively
 * using the connection. Calling this while network requests are in flight
 * or being initiated on other threads leads to undefined behavior.
 *
 * @param connection the smm_connection object to close and free
 */
void smm_connection_close (smm_connection connection);

/**
 * Get all the assets that this user account has access to
 *
 * @param connection the smm_connection object to get the assets from
 * @param assets Where to store the assets
 * @param assets_count Where to store how many assets there are
 *
 * @return true if assets were successfully retrieved (even if there are none), false if there was an error
 */
bool smm_asset_get_assets (smm_connection connection, smm_assets *assets, size_t *assets_count);

/**
 * Free a set of assets
 *
 * @param assets the assets to free
 * @param assets_count how many assets to free
 */
void smm_asset_free_assets (smm_assets assets, size_t assets_count);

/**
 * Get the name of the specified asset
 *
 * @param asset the Asset
 *
 * @return The name of the asset, or NULL if asset is invalid
 */
const char *smm_asset_name (smm_asset asset);

/**
 * Get the type of the specified asset
 *
 * @param asset the Asset
 *
 * @return The type of the asset, or NULL if asset is invalid
 */
const char *smm_asset_type (smm_asset asset);

/**
 * Report the current position of the asset to the server
 *
 * @param asset the Asset
 * @param latitude The current latitude in degrees
 * @param longitude The current longitude in degrees
 * @param altitude The current altitude in meters
 * @param bearing the current course over ground in degrees true
 * @param fix the accurancy of the current fix (0=unknown, 2=2d only, 3 = 3d fix)
 *
 * @return true if the position was reported to the server
 */
bool smm_asset_report_position (smm_asset asset, double latitude, double longitude, unsigned int altitude,
				uint16_t bearing, uint8_t fix);

/**
 * Get the last command we saw from the server
 * the command is set in response to a position report,
 * normally this is checked after @ref smm_asset_report_position
 *
 * @param asset the Asset
 *
 * @return The command that currently applies to the asset
 */
smm_asset_command smm_asset_last_command (smm_asset asset);

/**
 * The position associated with a goto command
 *
 * @param asset the Asset
 * @param lat A place to store the latitude
 * @param lon A place to store the longitude
 *
 * @return true if the current command is goto and the fields were set
 */
bool smm_asset_last_goto_pos (smm_asset asset, double *lat, double *lon);

/**
 * Get a search to perform from the SMM
 *
 * @param asset The Asset to conduct the search
 * @param latitude the current latitude of the asset in degrees
 * @param longitude the current longitude of the asset in degrees
 *
 * @return the closest or next queued search for this asset type, it will need to be accepted with @ref
 * smm_search_accept before searching begins
 */
smm_search smm_asset_get_search (smm_asset asset, double latitude, double longitude);

/**
 * Get the distance to the start of the search
 * This value was correct at the point it was requested
 *
 * @param search the search
 *
 * @return the distance in meters to the start of the search, 0 on error
 */
uint64_t smm_search_distance (smm_search search);

/**
 * Get the total length of the search
 *
 * @param search the search
 *
 * @return the total length of the search in meters, 0 on error
 */
uint64_t smm_search_length (smm_search search);

/**
 * Get the sweep width
 *
 * @param search the search
 *
 * @return the sweep width of the search in meters, 0 on error
 */
uint64_t smm_search_sweep_width (smm_search search);

/**
 * Get all the waypoints associated with a a search
 *
 * @param search the search
 * @param waypoints a place to store the list of waypoints
 * @param waypoints_count a place to store the count of waypoints
 *
 * @return true if waypoints for the search were stored in waypoints
 */
bool smm_search_get_waypoints (smm_search search, smm_waypoints *waypoints, size_t *waypoints_count);

/**
 * Accept a search
 * This is an agreement with the server to conduct this search
 * all subsequent attempts to get a search will only return this search
 *
 * @param search the search to accept
 *
 * @return true if the server accepted this search begining, otherwise @ref smm_search_destory the search and @ref
 * smm_asset_get_search again
 */
bool smm_search_accept (smm_search search);

/**
 * Mark a search as completed
 * Once the current search has been completed, call this function to notify the server
 * this will mark the search as completed and allow the asset to select another search.
 *
 * @param search the search that has been completed
 *
 * @return true if the server accepted the search as completed, false in other cases
 */
bool smm_search_complete (smm_search search);

/**
 * Destroy a search object
 *
 * @param search the search object to free
 */
void smm_search_destroy (smm_search search);

/**
 * Free a list of waypoints
 * i.e. from @ref smm_search_get_waypoints
 *
 * @param waypoints the set of waypoints to free
 * @param waypoints_count the number of waypoints
 */
void smm_waypoints_free (smm_waypoints waypoints, size_t waypoints_count);
