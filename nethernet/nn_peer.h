/*
 * MIT License
 *
 * Copyright (c) 2026 vp817
 * Copyright (c) 2026 Laith98Dev
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#pragma once

#include "nn_thread.h"
#include "nn_ivec.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
typedef bool nn_atomic_bool;
typedef size_t nn_atomic_size;
extern "C"
{
#else
#include <stdatomic.h>
typedef atomic_bool nn_atomic_bool;
typedef atomic_size_t nn_atomic_size;
#endif

#define NETHERNET_INVALID_RTC_VAR -1

#define NN_MAX_MESSAGE_SIZE 262144
#define NN_MAX_REASSEMBLY_SIZE (8 * 1024 * 1024)
#define NN_HANDSHAKE_TIMEOUT_SEC 15
#define NN_OPERATOR_TOKEN_TTL_SEC (30LL * 24 * 60 * 60)
#define NN_TOKEN_CLOCK_LEEWAY_SEC 60
#define NN_MAX_ADVERTISE_ADDRESSES 8
#define NN_MAX_TRUSTED_PROXIES 16
#define NN_RELIABLE_CHANNEL_LABEL "ReliableDataChannel"
#define NN_UNRELIABLE_CHANNEL_LABEL "UnreliableDataChannel"

#define NN_DEFAULT_MAX_PENDING 256
#define NN_DEFAULT_MAX_PENDING_PER_IP 8
#define NN_DEFAULT_MAX_CONNECTIONS_PER_IP 32
#define NN_MAX_QUEUED_BYTES_PER_CONN (16 * 1024 * 1024)
#define NN_MAX_QUEUED_BYTES_TOTAL (256 * 1024 * 1024)
#define NN_MAX_SEND_BUFFERED (32 * 1024 * 1024)
#define NN_MAX_REMOTE_CANDIDATES 32
#define NN_MAX_INBOUND_BUFFERED_TOTAL (256 * 1024 * 1024)
#define NN_HTTP_MAX_CONNECTIONS 1024
#define NN_HTTP_MAX_CONNECTIONS_PER_IP 16
#define NN_HTTP_MAX_RESPONSE_SIZE (256 * 1024)
#define NN_HTTP_MAX_REQUEST_SIZE (64 * 1024)
#define NN_HTTP_ACCEPT_BURST 20
#define NN_HTTP_ACCEPT_PER_SEC 5
#define NN_HTTP_MAX_CONNECTIONS_PER_PROXY (NN_HTTP_MAX_CONNECTIONS >> 1)
#define NN_HTTP_PROXY_ACCEPT_BURST 200
#define NN_HTTP_PROXY_ACCEPT_PER_SEC 100
#ifndef NN_KEYS_REFRESH_INTERVAL_MS
#define NN_KEYS_REFRESH_INTERVAL_MS (6ULL * 60 * 60 * 1000)
#endif
#ifndef NN_KEYS_REFRESH_MIN_GAP_MS
#define NN_KEYS_REFRESH_MIN_GAP_MS (5ULL * 60 * 1000)
#endif
#define NN_HTTP_CONN_LIFETIME_MS 30000

typedef enum
{
	NN_SUCCESS,
	NN_NN_INVALID,
	NN_DESTROY_SUCCESS,
	NN_TISS_FAILED,
	NN_ALREADY_INITIALIZED,
	NN_HTTP_THREAD_CREATION_FAIL,
	NN_HTTP_THREAD_DETACH_FAIL,
	NN_NOT_INITIALIZED,
	NN_OPERATOR_KEY_FAIL,
	NN_LISTEN_FAIL,
	NN_INVALID_ARGS,
	NN_CONNECTION_NOT_FOUND,
	NN_CONNECTION_NOT_READY,
	NN_MESSAGE_TOO_LARGE,
	NN_SEND_FAIL,
	NN_HTTP_FAIL,
	NN_CLIENT_KEY_FAIL,
	NN_SERVER_REJECTED,
	NN_SERVER_IDENTITY_INVALID,
	NN_SERVER_IDENTITY_MISMATCH,
	NN_WEBRTC_FAIL,
	NN_TIMEOUT,
	NN_TLS_FAIL,
	NN_CA_STORE_FAIL
} NetherNetResult;

typedef enum
{
	NN_CHANNEL_RELIABLE = 0,
	NN_CHANNEL_UNRELIABLE = 1
} NetherNetChannel;

typedef enum
{
	NN_EVENT_NONE = 0,
	NN_EVENT_CONNECTED,
	NN_EVENT_DATA,
	NN_EVENT_DISCONNECTED
} NetherNetEventType;

typedef struct
{
	char xid[32];
	char xname[64];
} PlayerIdentity;

typedef struct _NetherNetEvent
{
	NetherNetEventType type;
	uint64_t connection_id;
	char network_id[128];
	PlayerIdentity identity;
	char remote_address[64];
	NetherNetChannel channel;
	uint8_t *data;
	size_t len;

	struct _NetherNetEvent *_next;
} NetherNetEvent;

typedef struct _NetherNetConnection NetherNetConnection;

typedef struct
{
	const char *server_information;
	const char *operator_key_path;
	const char *operator_domain;
	bool operator_cpk_spki;
	const char *tls_cert_path;
	const char *tls_key_path;
	bool allow_unauthenticated;
	int max_pending;
	int max_pending_per_ip;
	int max_connections_per_ip;
	int ice_port;
	int mtu;
	const char *advertise_addresses;
	const char *trusted_proxies;
	const char *real_ip_header;

	char *_server_information;
	char *_tls_cert;
	char *_tls_key;
	void *_ca_store;
	char (*_advertise)[48];
	size_t _advertise_count;
	void *_proxies;
	size_t _proxy_count;

	nn_mutex_t _mg_mgr_mtx;
	struct mg_mgr *_mg_mgr;
	bool _initialized;
	bool _listening;
	volatile bool _worker_running;
	nn_thread_t _worker_thread;
	nn_thread_t _refresh_thread;
	bool _refresh_started;
	nn_atomic_bool _starting;
	nn_atomic_bool _stopping;
	nn_atomic_bool _keys_refresh_requested;

	void *_operator_key;

	nn_mutex_t _conns_mtx;
	NetherNetConnection *_conns;
	uint64_t _next_connection_id;

	nn_mutex_t _events_mtx;
	NetherNetEvent *_events_head;
	NetherNetEvent *_events_tail;
	size_t _events_bytes;
	nn_atomic_size _inbound_bytes;

	struct NetherNetAcceptBucket
	{
		uint64_t key;
		double tokens;
		uint64_t last_ms;
	} _accept_buckets[1024];

	nn_mutex_t _acl_mtx;
	IVec _banned_names;
	IVec _banned_ips;
	IVec _whitelist;
	bool _whitelist_enabled;
	bool _reject_banned;
	bool _reject_not_whitelisted;
	bool _reject_when_full;
	int _players;
	int _max_players;
	uint64_t _name_seed;
} NetherNet;

typedef enum
{
	NN_ACL_BANNED_NAMES,
	NN_ACL_BANNED_IPS,
	NN_ACL_WHITELIST
} NetherNetAclList;

NetherNetResult nn_peer_init(NetherNet *nn);

NetherNetResult nn_startup(NetherNet *nn, const char *server_url);

bool nn_update_cycle(NetherNet *nn);

bool nn_set_server_information(NetherNet *nn, const char *json);

bool nn_poll_event(NetherNet *nn, NetherNetEvent *out);
void nn_free_event(NetherNetEvent *ev);

NetherNetResult nn_send(NetherNet *nn, uint64_t connection_id, const void *data, size_t len, NetherNetChannel channel);
NetherNetResult nn_disconnect(NetherNet *nn, uint64_t connection_id);

bool nn_acl_set(NetherNet *nn, NetherNetAclList list, const char *const *entries, size_t count);
void nn_acl_set_whitelist_enabled(NetherNet *nn, bool enabled);
void nn_acl_set_policy(NetherNet *nn, bool reject_banned, bool reject_not_whitelisted, bool reject_when_full);
void nn_acl_set_capacity(NetherNet *nn, int players, int max_players);

typedef struct
{
	const char *server_url;
	const char *network_id;
	const char *game_server_token;
	const char *client_key_pem;
	const char *idp_domain;
	const char *expected_fingerprint;
	bool allow_missing_identity;
	int timeout_ms;
} NetherNetClientConfig;

char *nn_query(NetherNet *nn, const char *url);

NetherNetResult nn_client_connect(NetherNet *nn, const NetherNetClientConfig *cfg, uint64_t *connection_id, char *fingerprint_out, size_t fingerprint_size);

NetherNetResult nn_destroy(NetherNet *nn);

#ifdef __cplusplus
}
#endif
