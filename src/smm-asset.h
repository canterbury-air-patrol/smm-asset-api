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
 * Library version. These three numbers are the single source of truth for the
 * version: configure.ac derives the package version from them, and
 * SMM_VERSION_STRING / SMM_VERSION_NUMBER below are composed from them, so the
 * forms cannot drift apart. Bump these on a release.
 */
#define SMM_VERSION_MAJOR 1
#define SMM_VERSION_MINOR 1
#define SMM_VERSION_PATCH 1

/* Compose "major.minor.patch" from the numbers above (two-step expansion so the
 * macro values, not their names, are stringified). */
#define SMM_VERSION_STRINGIFY_(x) #x
#define SMM_VERSION_STRINGIFY(x) SMM_VERSION_STRINGIFY_ (x)
#define SMM_VERSION_STRING                                                                                             \
    SMM_VERSION_STRINGIFY (SMM_VERSION_MAJOR)                                                                          \
    "." SMM_VERSION_STRINGIFY (SMM_VERSION_MINOR) "." SMM_VERSION_STRINGIFY (SMM_VERSION_PATCH)

/**
 * Numeric library version: (major << 16) | (minor << 8) | patch.
 * Suitable for comparisons, e.g. #if SMM_VERSION_NUMBER >= 0x010100.
 */
#define SMM_VERSION_NUMBER ((SMM_VERSION_MAJOR << 16) | (SMM_VERSION_MINOR << 8) | SMM_VERSION_PATCH)

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
 * @section thread_safety Thread-safety guarantees
 *
 * - A single smm_connection may be shared across threads.  The connection's
 *   shared state (cookies, CSRF token, connection status and error record) is
 *   protected by internal mutexes, so concurrent calls on the same connection
 *   are safe. Network I/O is serialised per connection to keep the shared
 *   cookie jar consistent; use separate connections for parallel transfers.
 *
 * - smm_asset_connect() and smm_connection_close() are safe to call from any
 *   thread, but smm_connection_close() must not be called while another thread
 *   is still creating assets or searches from the same connection.
 *   Each asset returned by smm_asset_get_assets() holds a reference on the
 *   connection, so closing the connection before freeing all assets is safe.
 *
 * - Each smm_asset is owned by a single thread at a time.  Two threads must
 *   not call functions on the same asset concurrently.
 *
 * - Each smm_search is owned by a single thread at a time.  Two threads must
 *   not call functions on the same search concurrently.
 *
 * - smm_asset_debugging_set() may be called from any thread at any time (the
 *   flag is _Atomic). Debug output goes to stderr; each message is written
 *   whole, so concurrent threads' messages do not interleave mid-line.
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
 * Get the version string of the library linked at runtime.
 *
 * This may differ from the SMM_VERSION_STRING the application was compiled
 * against when a different library version is installed.
 *
 * @return a static string such as "1.0.0"; do not free it
 */
const char *smm_asset_version_string (void);

/**
 * Get the numeric version of the library linked at runtime.
 *
 * @return the version in @ref SMM_VERSION_NUMBER format:
 *         (major << 16) | (minor << 8) | patch
 */
uint32_t smm_asset_version_number (void);

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
 * @param host the URI of the smm server (i.e. https://smm.example.com); any
 *             trailing '/' is ignored, and a base path is allowed (i.e.
 *             https://example.com/smm)
 * @param user the username to authenticate as
 * @param pass the password to authenticate with
 *
 * @return NULL only for NULL arguments or allocation failure; otherwise an
 *         smm_connection object whose state reflects any initialisation
 *         failure — check it with @ref smm_asset_connection_get_state and
 *         @ref smm_connection_get_last_error. A connection in
 *         SMM_CONNECTION_FAILURE from initialisation refuses all requests.
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
 * Override the connect and transfer timeouts for this connection.
 *
 * Applies to every subsequent request made on the connection. A non-positive
 * value for either argument keeps the library default (30s connect, 60s
 * transfer). The defaults suit general use; a latency-sensitive caller (e.g. a
 * control loop that reports position roughly once a second) can set an
 * aggressive bound so a single slow or hung endpoint cannot block a call for
 * the full TCP window.
 *
 * @param connection the smm_connection object; NULL is a no-op
 * @param connect_secs connect timeout in seconds, or <= 0 to keep the default
 * @param transfer_secs total transfer timeout in seconds, or <= 0 to keep the default
 */
void smm_asset_connection_timeouts_set (smm_connection connection, long connect_secs, long transfer_secs);

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
 * @param assets Where to store the assets (must be non-NULL; otherwise
 *               SMM_ERROR_INVALID_ARG is recorded on the connection)
 * @param assets_count Where to store how many assets there are (must be
 *                     non-NULL, as above)
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
bool smm_asset_report_position (smm_asset asset, double latitude, double longitude, int32_t altitude, uint16_t heading,
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
 * A NULL return is ambiguous without consulting the error state, which this
 * call clears on entry: NULL with @ref smm_asset_get_last_error reporting
 * SMM_ERROR_NONE means the server has no suitable search right now (a clean
 * outcome, worth retrying later); NULL with any other code is a failure
 * (network, server, parse, ...).
 *
 * @param asset The Asset to conduct the search
 * @param latitude the current latitude of the asset in degrees
 * @param longitude the current longitude of the asset in degrees
 *
 * @return the closest or next queued search for this asset type, or NULL (see
 * above). A returned search must be accepted with @ref smm_search_accept
 * before searching begins
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
 * @param waypoints a place to store the list of waypoints (must be non-NULL;
 *                  otherwise SMM_ERROR_INVALID_ARG is recorded on the search)
 * @param waypoints_count a place to store the count of waypoints (must be
 *                        non-NULL, as above)
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
 * The code and message are a consistent snapshot of one error, copied
 * together under the connection lock.  Safe to call concurrently with other
 * library functions.
 *
 * @param connection the smm_connection to query; NULL reports SMM_ERROR_NONE
 * @param message buffer for the NUL-terminated human-readable description
 *                (truncated to fit), or NULL to query only the code
 * @param message_len size of @a message in bytes; ignored when message is NULL
 * @return the machine-readable code of the last recorded error
 */
smm_error_code smm_connection_get_last_error (smm_connection connection, char *message, size_t message_len);

/**
 * Retrieve the most recent error recorded on an asset.
 *
 * Reflects errors from smm_asset_report_position() and
 * smm_asset_get_search().  The error is stored per-asset so concurrent
 * operations on different assets sharing the same connection do not
 * clobber each other's error state.
 *
 * @param asset the smm_asset to query; NULL reports SMM_ERROR_NONE
 * @param message buffer for the NUL-terminated human-readable description
 *                (truncated to fit), or NULL to query only the code
 * @param message_len size of @a message in bytes; ignored when message is NULL
 * @return the machine-readable code of the last recorded error
 */
smm_error_code smm_asset_get_last_error (smm_asset asset, char *message, size_t message_len);

/**
 * Retrieve the most recent error recorded on a search.
 *
 * Reflects errors from smm_search_get_waypoints(), smm_search_accept(),
 * and smm_search_complete().  The error is stored per-search so
 * concurrent operations on different searches sharing the same connection
 * do not clobber each other's error state.
 *
 * @param search the smm_search to query; NULL reports SMM_ERROR_NONE
 * @param message buffer for the NUL-terminated human-readable description
 *                (truncated to fit), or NULL to query only the code
 * @param message_len size of @a message in bytes; ignored when message is NULL
 * @return the machine-readable code of the last recorded error
 */
smm_error_code smm_search_get_last_error (smm_search search, char *message, size_t message_len);
