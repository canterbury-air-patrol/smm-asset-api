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
 * Library version. Keep in sync with the package version in configure.ac.
 */
#define SMM_VERSION_MAJOR 1
#define SMM_VERSION_MINOR 0
#define SMM_VERSION_PATCH 0
#define SMM_VERSION_STRING "1.0.0"

/**
 * Error codes returned by smm_connection_get_last_error()
 */
typedef enum
{
    SMM_ERROR_NONE = 0,    /*!< No error */
    SMM_ERROR_NETWORK,     /*!< Network or connection failure */
    SMM_ERROR_AUTH,        /*!< Authentication failure */
    SMM_ERROR_PROTOCOL,    /*!< Unexpected or malformed response */
    SMM_ERROR_PARSE,       /*!< JSON or HTML parse failure */
    SMM_ERROR_INVALID_ARG, /*!< Invalid argument (e.g. NULL pointer) */
    SMM_ERROR_SERVER,      /*!< Server returned an unexpected HTTP status */
} smm_error_code;

/**
 * Structured error detail attached to an smm_connection.
 */
typedef struct
{
    smm_error_code code; /*!< Machine-readable error code */
    char message[256];   /*!< Human-readable description */
} smm_error;

/**
 * @section thread_safety Thread-safety guarantees
 *
 * - A single smm_connection may be shared across threads.  The connection's
 *   shared state (cookies, CSRF token, DNS/TLS cache, connection status and
 *   error record) is protected by an internal mutex, so concurrent calls on
 *   the same connection are safe.  Calls are not globally serialised: the
 *   mutex is not held across network I/O, so independent requests on the same
 *   connection may be in flight in parallel.
 *
 * - smm_asset_connect() and smm_connection_close() are safe to call from any
 *   thread, but smm_connection_close() must not be called while another thread
 *   is still creating assets or searches from the same connection.
 *   smm_asset_create() acquires a reference on the connection, so closing the
 *   connection before freeing all assets is safe.
 *
 * - Each smm_asset is owned by a single thread at a time.  Two threads must
 *   not call functions on the same asset concurrently.
 *
 * - Each smm_search is owned by a single thread at a time.  Two threads must
 *   not call functions on the same search concurrently.
 *
 * - smm_asset_debugging_set() must be called before any other threads are
 *   started; the smm_debug flag is declared _Atomic but toggling it after
 *   threads are running may produce interleaved debug output.
 */

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
    SMM_CONNECTION_UNKNOWN,                /*!< Invalid object (e.g. NULL connection) */
    SMM_CONNECTION_CONNECTED,              /*!< Currently connected */
    SMM_CONNECTION_HOST_INVALID,           /*!< Host URL invalid, i.e. not http(s):// or not a valid domain */
    SMM_CONNECTION_NO_HOST_CONNECTION,     /*!< Unable to connect to host */
    SMM_CONNECTION_AUTHENTICATION_FAILURE, /*!< Unable to authenticate with host */
    SMM_CONNECTION_PROTOCOL_ERROR,         /*!< Unexpected response from host */
    SMM_CONNECTION_FAILURE,                /*!< Unable to communicate, for another reason */
    SMM_CONNECTION_NEW,                    /*!< Valid host accepted, but no request made yet (login is lazy) */
} smm_connection_status;

/**
 * Possible commands for an asset
 */
typedef enum
{
    SMM_COMMAND_NONE,             /*!< No restriction on current operation */
    SMM_COMMAND_CIRCLE,           /*!< Circle/Hold at current position */
    SMM_COMMAND_RTL,              /*!< Return to launch site */
    SMM_COMMAND_GOTO,             /*!< Goto to the specified position */
    SMM_COMMAND_CONTINUE,         /*!< Previous command revoked, resume own navigation */
    SMM_COMMAND_ABANDON_SEARCH,   /*!< Abandon the current search, expect reassignment */
    SMM_COMMAND_MISSION_COMPLETE, /*!< The mission has concluded, return to base */
    SMM_COMMAND_UNKNOWN,          /*!< The command from the server is not known */
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
 * This only validates the host and allocates the connection object; it does
 * not authenticate. Authentication happens lazily on the first request, so the
 * returned object reports SMM_CONNECTION_NEW (not SMM_CONNECTION_CONNECTED)
 * until then. To establish the session up front and check the result, call
 * @ref smm_asset_connection_login.
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
 * Authentication is performed lazily on the first request, so a freshly
 * connected object with a valid host reports SMM_CONNECTION_NEW until a
 * request (or an explicit @ref smm_asset_connection_login) transitions it to
 * SMM_CONNECTION_CONNECTED (or an error state). Do not gate the first request
 * on this returning SMM_CONNECTION_CONNECTED; either call
 * smm_asset_connection_login() first, or simply check the result of the
 * request itself (e.g. @ref smm_asset_get_assets).
 *
 * @param connection the smm_connection object to check
 *
 * @return The current state of the connection
 */
smm_connection_status smm_asset_connection_get_state (smm_connection connection);

/**
 * Authenticate the connection now, rather than waiting for the first request
 * to trigger login lazily.
 *
 * On success the connection transitions to SMM_CONNECTION_CONNECTED; on
 * failure it reflects the relevant error state (see @ref
 * smm_asset_connection_get_state and @ref smm_connection_get_last_error).
 * Concurrent calls on the same connection are serialised internally.
 *
 * Calling it on an already-connected connection is a cheap no-op that returns
 * true. Any other state — including a connection that previously failed to
 * authenticate (e.g. bad credentials) — causes a fresh login attempt, which
 * updates the connection's state and last error accordingly; it is not a
 * no-op, so a repeatedly-failing call will keep re-contacting the server.
 *
 * Passing a NULL @a connection is allowed: the call returns false immediately
 * with no side effects (no state is changed and no last error is recorded).
 *
 * @param connection the smm_connection object to authenticate, or NULL
 *
 * @return true if the connection is authenticated, false otherwise
 */
bool smm_asset_connection_login (smm_connection connection);

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
 * @param altitude The current altitude in metres (may be negative, e.g. below
 *                 mean sea level)
 * @param heading the current course over ground in degrees true
 * @param fix the accurancy of the current fix (0=unknown, 2=2d only, 3 = 3d fix)
 *
 * @return true if the position was reported to the server
 */
bool smm_asset_report_position (smm_asset asset, double latitude, double longitude, int altitude, uint16_t heading,
                                uint8_t fix);

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
 * @return true if the server accepted this search beginning, otherwise @ref smm_search_destroy the search and @ref
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

/**
 * Retrieve the most recent error recorded on a connection.
 *
 * Only reflects errors from connection-level operations: login and
 * smm_asset_get_assets.  Asset-level and search-level errors are
 * stored on the respective asset or search object; use
 * smm_asset_get_last_error() and smm_search_get_last_error() instead.
 *
 * Returns a snapshot of the last error, copied under the connection lock.
 * Safe to call concurrently with other library functions.
 * Returns a zeroed smm_error (code == SMM_ERROR_NONE) if connection is NULL.
 *
 * @param connection the smm_connection to query
 * @return a copy of the last recorded error
 */
smm_error smm_connection_get_last_error (smm_connection connection);

/**
 * Retrieve the most recent error recorded on an asset.
 *
 * Reflects errors from smm_asset_report_position() and
 * smm_asset_get_search().  The error is stored per-asset so concurrent
 * operations on different assets sharing the same connection do not
 * clobber each other's error state.
 *
 * Returns a zeroed smm_error (code == SMM_ERROR_NONE) if asset is NULL.
 *
 * @param asset the smm_asset to query
 * @return a copy of the last recorded error
 */
smm_error smm_asset_get_last_error (smm_asset asset);

/**
 * Retrieve the most recent error recorded on a search.
 *
 * Reflects errors from smm_search_get_waypoints(), smm_search_accept(),
 * and smm_search_complete().  The error is stored per-search so
 * concurrent operations on different searches sharing the same connection
 * do not clobber each other's error state.
 *
 * Returns a zeroed smm_error (code == SMM_ERROR_NONE) if search is NULL.
 *
 * @param search the smm_search to query
 * @return a copy of the last recorded error
 */
smm_error smm_search_get_last_error (smm_search search);
