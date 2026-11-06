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

#ifndef MG_TLS
#define MG_TLS MG_TLS_OPENSSL
#endif

#include "nn_crypto.h"
#include "nn_internal.h"
#include <rtc/rtc.h>
#include <mongoose.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

_Static_assert(sizeof(nn_atomic_bool) == sizeof(bool) && _Alignof(nn_atomic_bool) == _Alignof(bool), "atomic_bool != bool, C++ users would see another NetherNet");
_Static_assert(sizeof(nn_atomic_size) == sizeof(size_t) && _Alignof(nn_atomic_size) == _Alignof(size_t), "atomic_size_t != size_t, C++ users would see another NetherNet");

typedef struct
{
	const char *fetch_url;
	const char *method;
	const char *content_type;
	const char *body;
	size_t body_len;
	char *fetch_body;
	size_t fetch_body_len;
	int status;
	X509_STORE *ca_store;
	atomic_bool fetch_done;
} HttpFetchUserArgs;

typedef struct _EarlyMessage
{
	struct _EarlyMessage *next;

	NetherNetChannel channel;
	size_t size;
	uint8_t data[];
} EarlyMessage;

#define NN_EARLY_MAX_BYTES (1024 * 1024)

typedef struct _NetherNetConnection
{
	NetherNet *nn;
	uint64_t id;
	char network_id[128];
	PlayerIdentity identity;
	char remote_address[64];
	char remote_ip[48];
	size_t queued_bytes;

	int pc;
	atomic_int reliable_dc;
	atomic_int unreliable_dc;
	unsigned long http_conn_id;
	uint64_t created_ms;
	bool outgoing;

	atomic_bool gathered;
	atomic_bool answered;
	atomic_bool reliable_open;
	atomic_bool unreliable_open;
	atomic_bool connected;
	atomic_bool closed;
	atomic_bool pinned;
	atomic_bool disconnect_sent;

	nn_mutex_t reasm_mtx;
	uint8_t *reasm;
	size_t reasm_len;
	size_t reasm_cap;
	int reasm_expect;

	EarlyMessage *early_head;
	EarlyMessage *early_tail;
	size_t early_bytes;

	struct _NetherNetConnection *next;
} NetherNetConnection;

static void discard_log(char c, void *param)
{}

static void close_connection(NetherNetConnection *conn);
static void inbound_release(NetherNet *nn, size_t n);

static bool push_event(NetherNet *nn, NetherNetEventType type, NetherNetConnection *conn, NetherNetChannel channel, uint8_t *data, size_t len)
{
	size_t cost = type == NN_EVENT_DATA ? len + sizeof(NetherNetEvent) : 0;
	NetherNetEvent *ev = (NetherNetEvent *)calloc(1, sizeof(NetherNetEvent));
	if (!ev) {
		free(data);
		if (cost) {
			close_connection(conn);
		}
		return false;
	}
	ev->type = type;
	ev->connection_id = conn->id;
	snprintf(ev->network_id, sizeof(ev->network_id), "%s", conn->network_id);
	ev->identity = conn->identity;
	ev->channel = channel;
	ev->data = data;
	ev->len = len;

	nn_mutex_lock(&nn->_events_mtx);
	if (cost && (conn->queued_bytes + cost > NN_MAX_QUEUED_BYTES_PER_CONN || nn->_events_bytes + cost > NN_MAX_QUEUED_BYTES_TOTAL)) {
		nn_mutex_unlock(&nn->_events_mtx);
		nn_trace("conn %llu: event queue limit reached, closing", (unsigned long long)conn->id);
		free(data);
		free(ev);
		close_connection(conn);
		return false;
	}
	conn->queued_bytes += cost;
	nn->_events_bytes += cost;
	snprintf(ev->remote_address, sizeof(ev->remote_address), "%s", conn->remote_address);
	if (nn->_events_tail) {
		nn->_events_tail->_next = ev;
	} else {
		nn->_events_head = ev;
	}
	nn->_events_tail = ev;
	nn_mutex_unlock(&nn->_events_mtx);
	return true;
}

static void emit_disconnected(NetherNetConnection *conn)
{
	if (!atomic_exchange(&conn->disconnect_sent, true)) {
		push_event(conn->nn, NN_EVENT_DISCONNECTED, conn, NN_CHANNEL_RELIABLE, NULL, 0);
	}
}

static void close_connection(NetherNetConnection *conn)
{
	if (atomic_exchange(&conn->closed, true)) {
		return;
	}
	if (atomic_load(&conn->connected)) {
		emit_disconnected(conn);
	}
}

static void free_connection(NetherNetConnection *conn)
{
	if (conn->pc >= 0) {
		rtcSetStateChangeCallback(conn->pc, NULL);
		rtcSetGatheringStateChangeCallback(conn->pc, NULL);
		rtcSetIceStateChangeCallback(conn->pc, NULL);
		rtcSetDataChannelCallback(conn->pc, NULL);
		rtcSetUserPointer(conn->pc, NULL);
	}
	int dcs[2] = { atomic_load(&conn->reliable_dc), atomic_load(&conn->unreliable_dc) };
	for (int i = 0; i < 2; ++i) {
		if (dcs[i] >= 0) {
			rtcSetOpenCallback(dcs[i], NULL);
			rtcSetClosedCallback(dcs[i], NULL);
			rtcSetMessageCallback(dcs[i], NULL);
			rtcSetUserPointer(dcs[i], NULL);
		}
	}
	for (int i = 0; i < 2; ++i) {
		if (dcs[i] >= 0) {
			rtcDeleteDataChannel(dcs[i]);
		}
	}
	if (conn->pc >= 0) {
		rtcDeletePeerConnection(conn->pc);
	}
	inbound_release(conn->nn, conn->reasm_cap);
	free(conn->reasm);
	while (conn->early_head) {
		EarlyMessage *m = conn->early_head;
		conn->early_head = m->next;
		inbound_release(conn->nn, sizeof(EarlyMessage) + m->size);
		free(m);
	}
	nn_mutex_destroy(&conn->reasm_mtx);
	free(conn);
}

static void RTC_API on_rtc_state_change(int pc, rtcState state, void *ptr)
{
	NetherNetConnection *conn = (NetherNetConnection *)ptr;
	nn_trace("conn %llu: peer state %d", (unsigned long long)conn->id, (int)state);
	if (state == RTC_DISCONNECTED || state == RTC_FAILED || state == RTC_CLOSED) {
		close_connection(conn);
	}
}

static void RTC_API on_rtc_ice_state_change(int pc, rtcIceState state, void *ptr)
{
	NetherNetConnection *conn = (NetherNetConnection *)ptr;
	static const char *names[] = { "new", "checking", "connected", "completed", "failed", "disconnected", "closed" };
	nn_trace("conn %llu: ice %s", (unsigned long long)conn->id, (unsigned)state < 7 ? names[state] : "?");
}

static void RTC_API on_rtc_gathering_change(int pc, rtcGatheringState state, void *ptr)
{
	NetherNetConnection *conn = (NetherNetConnection *)ptr;
	if (state == RTC_GATHERING_COMPLETE) {
		atomic_store(&conn->gathered, true);
	}
}

static bool inbound_reserve(NetherNet *nn, size_t n)
{
	if (atomic_fetch_add(&nn->_inbound_bytes, n) + n > NN_MAX_INBOUND_BUFFERED_TOTAL) {
		atomic_fetch_sub(&nn->_inbound_bytes, n);
		return false;
	}
	return true;
}

static void inbound_release(NetherNet *nn, size_t n)
{
	atomic_fetch_sub(&nn->_inbound_bytes, n);
}

static bool reasm_append(NetherNetConnection *conn, const uint8_t *data, size_t len)
{
	if (conn->reasm_len + len > NN_MAX_REASSEMBLY_SIZE) {
		return false;
	}
	if (conn->reasm_len + len > conn->reasm_cap) {
		size_t cap = conn->reasm_cap ? conn->reasm_cap : 4096;
		while (cap < conn->reasm_len + len) {
			cap *= 2;
		}
		if (!inbound_reserve(conn->nn, cap - conn->reasm_cap)) {
			return false;
		}
		uint8_t *p = (uint8_t *)realloc(conn->reasm, cap);
		if (!p) {
			inbound_release(conn->nn, cap - conn->reasm_cap);
			return false;
		}
		conn->reasm = p;
		conn->reasm_cap = cap;
	}
	memcpy(conn->reasm + conn->reasm_len, data, len);
	conn->reasm_len += len;
	return true;
}

static void emit_copy(NetherNetConnection *conn, NetherNetChannel channel, const uint8_t *data, size_t len)
{
	uint8_t *copy = (uint8_t *)malloc(len ? len : 1);
	if (!copy) {
		close_connection(conn);
		return;
	}
	memcpy(copy, data, len);
	push_event(conn->nn, NN_EVENT_DATA, conn, channel, copy, len);
}

static bool handle_message_locked(NetherNetConnection *conn, NetherNetChannel channel, const uint8_t *message, size_t size)
{
	uint8_t remaining = message[0];
	const uint8_t *body = message + 1;
	size_t body_len = size - 1;

	if (channel == NN_CHANNEL_UNRELIABLE) {
		if (remaining == 0) {
			emit_copy(conn, NN_CHANNEL_UNRELIABLE, body, body_len);
		}
		return true;
	}

	if (conn->reasm_expect < 0) {
		if (remaining == 0) {
			emit_copy(conn, NN_CHANNEL_RELIABLE, body, body_len);
		} else if (reasm_append(conn, body, body_len)) {
			conn->reasm_expect = remaining - 1;
		} else {
			return false;
		}
		return true;
	}
	if (remaining != conn->reasm_expect || !reasm_append(conn, body, body_len)) {
		conn->reasm_len = 0;
		conn->reasm_expect = -1;
		return false;
	}
	if (remaining == 0) {
		inbound_release(conn->nn, conn->reasm_cap);
		push_event(conn->nn, NN_EVENT_DATA, conn, NN_CHANNEL_RELIABLE, conn->reasm, conn->reasm_len);
		conn->reasm = NULL;
		conn->reasm_len = 0;
		conn->reasm_cap = 0;
		conn->reasm_expect = -1;
	} else {
		conn->reasm_expect = remaining - 1;
	}
	return true;
}

static void check_connected(NetherNetConnection *conn)
{
	if (!atomic_load(&conn->reliable_open) || !atomic_load(&conn->unreliable_open) || atomic_load(&conn->closed)) {
		return;
	}
	nn_mutex_lock(&conn->reasm_mtx);
	if (!atomic_load(&conn->connected) && !atomic_load(&conn->closed)) {
		push_event(conn->nn, NN_EVENT_CONNECTED, conn, NN_CHANNEL_RELIABLE, NULL, 0);
		atomic_store(&conn->connected, true);
		if (atomic_load(&conn->closed)) {
			emit_disconnected(conn);
		}

		while (conn->early_head) {
			EarlyMessage *m = conn->early_head;
			conn->early_head = m->next;
			bool ok = !atomic_load(&conn->closed) && handle_message_locked(conn, m->channel, m->data, m->size);
			inbound_release(conn->nn, sizeof(EarlyMessage) + m->size);
			free(m);
			if (!ok) {
				close_connection(conn);
			}
		}
		conn->early_tail = NULL;
		conn->early_bytes = 0;
	}
	nn_mutex_unlock(&conn->reasm_mtx);
}

static void RTC_API on_dc_open(int dc, void *ptr)
{
	NetherNetConnection *conn = (NetherNetConnection *)ptr;
	if (dc == atomic_load(&conn->reliable_dc)) {
		atomic_store(&conn->reliable_open, true);
	} else if (dc == atomic_load(&conn->unreliable_dc)) {
		atomic_store(&conn->unreliable_open, true);
	}
	check_connected(conn);
}

static void RTC_API on_dc_closed(int dc, void *ptr)
{
	close_connection((NetherNetConnection *)ptr);
}

static void RTC_API on_dc_message(int dc, const char *message, int size, void *ptr)
{
	NetherNetConnection *conn = (NetherNetConnection *)ptr;
	NetherNetChannel channel = dc == atomic_load(&conn->unreliable_dc) ? NN_CHANNEL_UNRELIABLE : NN_CHANNEL_RELIABLE;
	nn_trace("conn %llu: recv %s size %d remaining %d connected %d", (unsigned long long)conn->id, channel == NN_CHANNEL_UNRELIABLE ? "unreliable" : "reliable", size, size > 0 ? (uint8_t)message[0] : -1, (int)atomic_load(&conn->connected));
	if (size < 1) {
		close_connection(conn);
		return;
	}
	if (atomic_load(&conn->closed)) {
		return;
	}

	nn_mutex_lock(&conn->reasm_mtx);
	bool ok = true;
	if (!atomic_load(&conn->connected)) {
		if (conn->early_bytes + (size_t)size > NN_EARLY_MAX_BYTES) {
			ok = false;
		} else {
			size_t cost = sizeof(EarlyMessage) + (size_t)size;
			EarlyMessage *m = NULL;
			if (inbound_reserve(conn->nn, cost)) {
				m = (EarlyMessage *)malloc(cost);
				if (!m) {
					inbound_release(conn->nn, cost);
				}
			}
			if (!m) {
				ok = false;
			} else {
				m->next = NULL;
				m->channel = channel;
				m->size = (size_t)size;
				memcpy(m->data, message, (size_t)size);
				if (conn->early_tail) {
					conn->early_tail->next = m;
				} else {
					conn->early_head = m;
				}
				conn->early_tail = m;
				conn->early_bytes += (size_t)size;
				nn_trace("conn %llu: queued until both channels are open", (unsigned long long)conn->id);
			}
		}
	} else {
		ok = handle_message_locked(conn, channel, (const uint8_t *)message, (size_t)size);
	}
	nn_mutex_unlock(&conn->reasm_mtx);
	if (!ok) {
		close_connection(conn);
	}
}

static void RTC_API on_rtc_data_channel(int pc, int dc, void *ptr)
{
	NetherNetConnection *conn = (NetherNetConnection *)ptr;
	char label[64];
	if (rtcGetDataChannelLabel(dc, label, sizeof(label)) < 0) {
		rtcDeleteDataChannel(dc);
		close_connection(conn);
		return;
	}

	int expected = -1;
	if ((strcmp(label, NN_RELIABLE_CHANNEL_LABEL) || !atomic_compare_exchange_strong(&conn->reliable_dc, &expected, dc)) && (strcmp(label, NN_UNRELIABLE_CHANNEL_LABEL) || !atomic_compare_exchange_strong(&conn->unreliable_dc, &expected, dc))) {
		nn_trace("unexpected data channel: %s", label);
		rtcDeleteDataChannel(dc);
		close_connection(conn);
		return;
	}

	rtcSetUserPointer(dc, conn);
	rtcSetOpenCallback(dc, on_dc_open);
	rtcSetClosedCallback(dc, on_dc_closed);
	rtcSetMessageCallback(dc, on_dc_message);
	if (rtcIsOpen(dc)) {
		on_dc_open(dc, conn);
	}
}

static uint64_t now_ms(void)
{
#if defined(_WIN32) || defined(__WIN32__) || defined(_WIN64)
	return (uint64_t)GetTickCount64();
#else
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
#endif
}

static void send_request(struct mg_connection *c, HttpFetchUserArgs *args)
{
	const char *uri = mg_url_uri(args->fetch_url);
	struct mg_str host = mg_url_host(args->fetch_url);
	if (args->body) {
		mg_printf(c, "%s %s HTTP/1.1\r\nHost: %.*s\r\nConnection: close\r\nContent-Type: %s\r\nContent-Length: %lu\r\n\r\n", args->method, uri, (int)host.len, host.buf, args->content_type, (unsigned long)args->body_len);
		mg_send(c, args->body, args->body_len);
	} else {
		mg_printf(c, "%s %s HTTP/1.1\r\nHost: %.*s\r\nConnection: close\r\n\r\n", args->method, uri, (int)host.len, host.buf);
	}
}

static void fetch_cb(struct mg_connection *c, int ev, void *ev_data)
{
	HttpFetchUserArgs *args = (HttpFetchUserArgs *)c->fn_data;
	if (ev == MG_EV_CONNECT) {
		if (c->is_tls) {
			struct mg_tls_opts opts = {0};
			opts.name = mg_url_host(args->fetch_url);
			mg_tls_init(c, &opts);
			struct mg_tls *tls = (struct mg_tls *)c->tls;
			if (!tls || !args->ca_store) {
				c->is_closing = 1;
				return;
			}
			SSL_CTX_set1_cert_store(tls->ctx, args->ca_store);
			SSL_set_verify(tls->ssl, SSL_VERIFY_PEER, NULL);
		} else {
			send_request(c, args);
		}
	} else if (ev == MG_EV_TLS_HS) {
		send_request(c, args);
	} else if (ev == MG_EV_HTTP_MSG) {
		struct mg_http_message *hm = (struct mg_http_message *)ev_data;
		if (args->fetch_body || hm->body.len > NN_HTTP_MAX_RESPONSE_SIZE) {
			c->is_closing = 1;
			return;
		}
		args->status = mg_http_status(hm);
		args->fetch_body = (char *)malloc(hm->body.len + 1);
		if (args->fetch_body) {
			memcpy(args->fetch_body, hm->body.buf, hm->body.len);
			args->fetch_body[hm->body.len] = '\0';
			args->fetch_body_len = hm->body.len;
		}
		c->is_closing = 1;
	} else if (ev == MG_EV_CLOSE) {
		atomic_store(&args->fetch_done, true);
	}
}

static X509_STORE *load_ca_store(void)
{
	X509_STORE *store = X509_STORE_new();
	if (!store) {
		return NULL;
	}
	bool loaded = false;
	const char *file = getenv("SSL_CERT_FILE");
	const char *dir = getenv("SSL_CERT_DIR");
	if (file && *file && X509_STORE_load_file(store, file) == 1) {
		loaded = true;
	}
	if (dir && *dir && X509_STORE_load_path(store, dir) == 1) {
		loaded = true;
	}
	if (!loaded) {
#if defined(_WIN32) || defined(__WIN32__) || defined(_WIN64)
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
		loaded = X509_STORE_load_store(store, "org.openssl.winstore://") == 1;
#endif
#else
		static const char *bundles[] = {
			"/etc/ssl/certs/ca-certificates.crt",
			"/etc/pki/tls/certs/ca-bundle.crt",
			"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
			"/etc/ssl/ca-bundle.pem",
			"/etc/ssl/cert.pem",
			"/usr/local/etc/openssl/cert.pem"
		};
		for (size_t i = 0; i < sizeof(bundles) / sizeof(bundles[0]) && !loaded; ++i) {
			loaded = X509_STORE_load_file(store, bundles[i]) == 1;
		}
#endif
	}
	if (!loaded) {
		X509_STORE_free(store);
		return NULL;
	}
	return store;
}

static bool ensure_ca_store(NetherNet *nn)
{
	if (!nn->_ca_store) {
		nn->_ca_store = load_ca_store();
	}
	return nn->_ca_store != NULL;
}

static bool valid_url(const char *url)
{
	for (const unsigned char *p = (const unsigned char *)url; *p; ++p) {
		if (*p <= 0x20 || *p == 0x7f) {
			return false;
		}
	}
	return *url != '\0';
}

static char *http_request(NetherNet *nn, const char *method, const char *url, const char *content_type, const char *body, size_t body_len, int *status, size_t *body_len_out, int timeout_ms)
{
	HttpFetchUserArgs args;
	args.fetch_url = url;
	args.method = method;
	args.content_type = content_type;
	args.body = body;
	args.body_len = body_len;
	args.fetch_body = NULL;
	atomic_store(&args.fetch_done, false);
	if (!valid_url(url)) {
		return NULL;
	}
	if (!strncmp(url, "https://", 8)) {
		if (!ensure_ca_store(nn)) {
			return NULL;
		}
		args.ca_store = (X509_STORE *)nn->_ca_store;
	}

	nn_mutex_lock(&nn->_mg_mgr_mtx);
	struct mg_connection *c = mg_http_connect(nn->_mg_mgr, url, fetch_cb, (void *)&args);
	unsigned long id = c ? c->id : 0;
	nn_mutex_unlock(&nn->_mg_mgr_mtx);
	if (!c) {
		return NULL;
	}

	uint64_t deadline = now_ms() + (uint64_t)(timeout_ms > 0 ? timeout_ms : 10000);
	bool abandoned = false;
	while (!atomic_load(&args.fetch_done)) {
		if (!abandoned && (now_ms() > deadline || atomic_load(&nn->_stopping))) {
			nn_mutex_lock(&nn->_mg_mgr_mtx);
			for (struct mg_connection *x = nn->_mg_mgr->conns; x; x = x->next) {
				if (x->id == id) {
					x->is_closing = 1;
				}
			}
			nn_mutex_unlock(&nn->_mg_mgr_mtx);
			abandoned = true;
		}
		nn_thread_sleep_ms(1);
	}
	if (abandoned) {
		free(args.fetch_body);
		return NULL;
	}
	if (status) {
		*status = args.status;
	}
	if (body_len_out) {
		*body_len_out = args.fetch_body_len;
	}
	return args.fetch_body;
}

char *nn_http_get(NetherNet *nn, const char *url)
{
	int status = 0;
	char *body = http_request(nn, "GET", url, NULL, NULL, 0, &status, NULL, 10000);
	if (body && status != 200) {
		free(body);
		body = NULL;
	}
	return body;
}

static bool next_attribute(struct mg_str sdp, const char *attr, size_t *cursor, struct mg_str *value)
{
	const size_t attr_len = strlen(attr);
	size_t pos = *cursor;
	while (pos < sdp.len) {
		size_t line_start = pos;
		while (pos < sdp.len && sdp.buf[pos] != '\n') {
			++pos;
		}
		size_t line_len = pos - line_start;
		if (pos < sdp.len) {
			++pos;
		}
		if (line_len > 0 && sdp.buf[line_start + line_len - 1] == '\r') {
			--line_len;
		}
		if (line_len >= attr_len && !memcmp(sdp.buf + line_start, attr, attr_len)) {
			*value = mg_str_n(sdp.buf + line_start + attr_len, line_len - attr_len);
			*cursor = pos;
			return true;
		}

	}
	*cursor = pos;
	return false;
}

static bool get_attribute(struct mg_str sdp, const char *attr, char *out, size_t out_size)
{
	size_t cursor = 0;
	struct mg_str value;
	if (!next_attribute(sdp, attr, &cursor, &value)) {
		return false;
	}
	if (value.len + 1 > out_size) {
		return false;
	}
	memcpy(out, value.buf, value.len);
	out[value.len] = '\0';
	return true;
}

static bool valid_fingerprint_field(struct mg_str s, size_t max, bool is_digset)
{
	if (s.len == 0 || s.len > max) {
		return false;
	}
	for (size_t i = 0; i < s.len; ++i) {
		char x = s.buf[i];
		bool ok = is_digset
					? ((x >= '0' && x <= '9') || (x >= 'A' && x <= 'F') || (x >= 'a' && x <= 'f') || x == ':')
					: ((x >= '0' && x <= '9') || (x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z') || x == '-');
		if (!ok) {
			return false;
		}
	}
	return true;
}

static int build_fingerprints_json(struct mg_str sdp, char *out, size_t out_size, size_t *out_len)
{
	size_t cursor = 0;
	struct mg_str fp;
	int count = 0;
	size_t n = mg_snprintf(out, out_size, "{\"fingerprint\":[");
	while (next_attribute(sdp, "a=fingerprint:", &cursor, &fp)) {
		while (fp.len > 0 && fp.buf[0] == ' ') ++fp.buf, --fp.len;
		const char *sp = memchr(fp.buf, ' ', fp.len);
		if (sp == NULL) {
			continue;
		}
		struct mg_str algo = mg_str_n(fp.buf, (size_t)(sp - fp.buf));
		struct mg_str digset = mg_str_n(sp + 1, fp.len - algo.len - 1);

		if (!valid_fingerprint_field(algo, MAX_FINGERPRINT_ALGO_LEN, false) || !valid_fingerprint_field(digset, MAX_FINGERPRINT_DIGEST_LEN, true)) {
			return 1;
		}
		if (count >= MAX_FINGERPRINTS_COUNT) {
			return 2;
		}

		n += mg_snprintf(out + n, out_size - n, "%s{\"algorithm\":\"%.*s\",\"digest\":\"%.*s\"}", (count > 0 ? "," : ""), (int)algo.len, algo.buf, (int)digset.len, digset.buf);

		++count;
		if (n >= out_size) {
			return 3;
		}
	}

	if (count == 0) {
		return 4;
	}

	n += mg_snprintf(out + n, out_size - n, "]}");
	if (n >= out_size) {
		return 3;
	}
	*out_len = n;
	return 0;
}

static bool numeric_candidate(const char *line, size_t len)
{
	size_t pos = 12, field = 0;
	while (pos < len && field < 4) {
		while (pos < len && line[pos] != ' ') {
			++pos;
		}
		while (pos < len && line[pos] == ' ') {
			++pos;
		}
		++field;
	}
	size_t start = pos;
	while (pos < len && line[pos] != ' ' && line[pos] != '\r' && line[pos] != '\n') {
		++pos;
	}
	size_t alen = pos - start;
	if (field < 4 || alen == 0 || alen >= INET6_ADDRSTRLEN) {
		return false;
	}
	char address[INET6_ADDRSTRLEN] = {0};
	memcpy(address, line + start, alen);
	struct in_addr v4;
	struct in6_addr v6;
	return inet_pton(AF_INET, address, &v4) == 1 || inet_pton(AF_INET6, address, &v6) == 1;
}

static char *strip_identity(struct mg_str sdp)
{
	char *out = (char *)malloc(sdp.len + 1);
	if (!out) {
		return NULL;
	}
	size_t pos = 0, n = 0, candidates = 0;
	while (pos < sdp.len) {
		size_t line_start = pos;
		while (pos < sdp.len && sdp.buf[pos] != '\n') {
			++pos;
		}
		if (pos < sdp.len) {
			++pos;
		}
		if (pos - line_start >= 11 && !memcmp(sdp.buf + line_start, "a=identity:", 11)) {
			continue;
		}
		if (pos - line_start >= 12 && !memcmp(sdp.buf + line_start, "a=candidate:", 12)) {
			size_t line_len = pos - line_start;
			while (line_len && (sdp.buf[line_start + line_len - 1] == '\n' || sdp.buf[line_start + line_len - 1] == '\r')) {
				--line_len;
			}
			if (candidates >= NN_MAX_REMOTE_CANDIDATES || !numeric_candidate(sdp.buf + line_start, pos - line_start)) {
				nn_trace("remote candidate dropped (%s): %.*s", candidates >= NN_MAX_REMOTE_CANDIDATES ? "over the cap" : "not a numeric address", (int)line_len, sdp.buf + line_start);
				continue;
			}
			nn_trace("remote candidate kept: %.*s", (int)line_len, sdp.buf + line_start);
			++candidates;
		}
		memcpy(out + n, sdp.buf + line_start, pos - line_start);
		n += pos - line_start;
	}
	out[n] = '\0';
	return out;
}

static bool valid_network_id(struct mg_str id)
{
	if (id.len == 0 || id.len >= 128) {
		return false;
	}
	for (size_t i = 0; i < id.len; ++i) {
		char x = id.buf[i];
		if (!((x >= '0' && x <= '9') || (x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z') || x == '-' || x == '_' || x == '.' || x == '~')) {
			return false;
		}
	}
	return true;
}

static uint64_t ip_group(const struct mg_addr *addr)
{
	const uint8_t *ip = addr->addr.ip;
	static const uint8_t v4_mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
	const uint8_t *v4 = !addr->is_ip6 ? ip : !memcmp(ip, v4_mapped, sizeof(v4_mapped)) ? ip + 12 : NULL;
	if (v4) {
		return (1ULL << 63) | ((uint64_t)v4[0] << 24) | ((uint64_t)v4[1] << 16) | ((uint64_t)v4[2] << 8) | v4[3];
	}
	uint64_t prefix = 0;
	for (int i = 0; i < 8; ++i) {
		prefix = (prefix << 8) | ip[i];
	}
	return prefix & ~(1ULL << 63);
}

static bool same_ip(const struct mg_addr *a, const struct mg_addr *b)
{
	return ip_group(a) == ip_group(b);
}

static void ip_limit_key(const struct mg_addr *addr, char *out, size_t out_size)
{
	uint64_t g = ip_group(addr);
	if (g >> 63) {
		snprintf(out, out_size, "%u.%u.%u.%u", (unsigned)(g >> 24) & 255, (unsigned)(g >> 16) & 255, (unsigned)(g >> 8) & 255, (unsigned)g & 255);
	} else {
		const uint8_t *ip = addr->addr.ip;
		snprintf(out, out_size, "%02x%02x:%02x%02x:%02x%02x:%02x%02x::/64", ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7]);
	}
}

static bool accept_rate_ok(NetherNet *nn, const struct mg_addr *addr, double burst, double per_sec)
{
	uint64_t key = ip_group(addr);
	uint64_t h = key * 0x9e3779b97f4a7c15ULL;
	struct NetherNetAcceptBucket *b = &nn->_accept_buckets[(h >> 32) % (sizeof(nn->_accept_buckets) / sizeof(nn->_accept_buckets[0]))];
	uint64_t now = now_ms();
	if (b->key != key || !b->last_ms) {
		b->key = key;
		b->tokens = burst;
	} else {
		b->tokens += (double)(now - b->last_ms) * per_sec / 1000.0;
		if (b->tokens > burst) {
			b->tokens = burst;
		}
	}
	b->last_ms = now ? now : 1;
	if (b->tokens < 1.0) {
		return false;
	}
	b->tokens -= 1.0;
	return true;
}

static bool is_trusted_proxy(const NetherNet *nn, const struct mg_addr *addr);

static bool admit_http_connection(const NetherNet *nn, struct mg_connection *c, bool proxied)
{
	size_t total = 0, from_ip = 0, from_proxies = 0;
	for (struct mg_connection *x = c->mgr->conns; x; x = x->next) {
		if (!x->is_accepted || x->is_closing || x == c) {
			continue;
		}
		++total;
		if (same_ip(&x->rem, &c->rem)) {
			++from_ip;
		}
		if (proxied && is_trusted_proxy(nn, &x->rem)) {
			++from_proxies;
		}
	}
	return total < NN_HTTP_MAX_CONNECTIONS && (proxied ? from_proxies < NN_HTTP_MAX_CONNECTIONS_PER_PROXY : from_ip < NN_HTTP_MAX_CONNECTIONS_PER_IP);
}

static bool next_list_item(const char **s, struct mg_str *item)
{
	const char *p = *s;
	while (*p == ',' || *p == ' ' || *p == '\t') {
		++p;
	}
	if (!*p) {
		*s = p;
		return false;
	}
	const char *start = p;
	while (*p && *p != ',') {
		++p;
	}
	const char *end = p;
	while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
		--end;
	}
	*item = mg_str_n(start, (size_t)(end - start));
	*s = p;
	return true;
}

static void addr_bytes(const struct mg_addr *a, uint8_t out[16])
{
	static const uint8_t v4_mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
	if (a->is_ip6) {
		memcpy(out, a->addr.ip, 16);
	} else {
		memcpy(out, v4_mapped, 12);
		memcpy(out + 12, a->addr.ip, 4);
	}
}

static bool is_trusted_proxy(const NetherNet *nn, const struct mg_addr *addr)
{
	uint8_t x[16], y[16];
	addr_bytes(addr, x);
	const struct mg_addr *proxies = (const struct mg_addr *)nn->_proxies;
	for (size_t i = 0; i < nn->_proxy_count; ++i) {
		addr_bytes(&proxies[i], y);
		if (!memcmp(x, y, sizeof(x))) {
			return true;
		}
	}
	return false;
}

static const char *real_ip_header_name(const NetherNet *nn)
{
	return nn->real_ip_header && *nn->real_ip_header ? nn->real_ip_header : "X-Forwarded-For";
}

static bool client_address(const NetherNet *nn, const struct mg_connection *c, struct mg_http_message *hm, struct mg_addr *out)
{
	*out = c->rem;
	if (!is_trusted_proxy(nn, &c->rem)) {
		return true;
	}
	const char *name = real_ip_header_name(nn);
	const struct mg_str *header = NULL;
	size_t slots = sizeof(hm->headers) / sizeof(hm->headers[0]), used = 0;
	for (; used < slots && hm->headers[used].name.len; ++used) {
		if (!mg_strcasecmp(hm->headers[used].name, mg_str(name))) {
			header = &hm->headers[used].value;
		}
	}
	if (!header || used == slots) {
		return false;
	}
	size_t start = 0;
	for (size_t i = 0; i < header->len; ++i) {
		if (header->buf[i] == ',') {
			start = i + 1;
		}
	}
	struct mg_str v = mg_str_n(header->buf + start, header->len - start);
	while (v.len && (v.buf[0] == ' ' || v.buf[0] == '\t')) {
		++v.buf, --v.len;
	}
	while (v.len && (v.buf[v.len - 1] == ' ' || v.buf[v.len - 1] == '\t')) {
		--v.len;
	}
	if (v.len >= 2 && v.buf[0] == '[' && v.buf[v.len - 1] == ']') {
		++v.buf, v.len -= 2;
	}
	char text[INET6_ADDRSTRLEN] = {0};
	struct in_addr v4;
	struct in6_addr v6;
	if (!v.len || v.len >= sizeof(text)) {
		return false;
	}
	memcpy(text, v.buf, v.len);
	if (inet_pton(AF_INET, text, &v4) != 1 && inet_pton(AF_INET6, text, &v6) != 1) {
		return false;
	}
	struct mg_addr a;
	if (!mg_aton(mg_str(text), &a)) {
		return false;
	}
	a.port = 0;
	*out = a;
	return true;
}

static char *add_advertised_candidates(const NetherNet *nn, const char *sdp)
{
	if (!nn->_advertise_count) {
		return NULL;
	}
	typedef struct
	{
		char component[8],
			transport[8],
			priority[16],
			port[8];
		bool v6;
	} HostCandidate;
	HostCandidate found[32];
	char addresses[32][INET6_ADDRSTRLEN];
	size_t found_count = 0, address_count = 0, insert_at = 0;

	size_t pos = 0, len = strlen(sdp);
	while (pos < len) {
		size_t line_start = pos;
		while (pos < len && sdp[pos] != '\n') {
			++pos;
		}
		size_t line_end = pos;
		if (pos < len) {
			++pos;
		}
		if (line_end > line_start && sdp[line_end - 1] == '\r') {
			--line_end;
		}
		if (line_end - line_start < 12 || memcmp(sdp + line_start, "a=candidate:", 12)) {
			continue;
		}
		insert_at = pos;
		struct mg_str fields[8];
		size_t n = 0, p = line_start + 12;
		while (n < 8 && p < line_end) {
			size_t f = p;
			while (p < line_end && sdp[p] != ' ') {
				++p;
			}
			fields[n++] = mg_str_n(sdp + f, p - f);
			while (p < line_end && sdp[p] == ' ') {
				++p;
			}
		}
		if (n < 8 || mg_strcmp(fields[6], mg_str("typ")) || mg_strcmp(fields[7], mg_str("host"))
			|| fields[1].len >= sizeof(found[0].component) || fields[2].len >= sizeof(found[0].transport)
			|| fields[3].len >= sizeof(found[0].priority) || fields[5].len >= sizeof(found[0].port)
			|| fields[4].len >= sizeof(addresses[0])) {
			continue;
		}
		if (address_count < sizeof(addresses) / sizeof(addresses[0])) {
			snprintf(addresses[address_count++], sizeof(addresses[0]), "%.*s", (int)fields[4].len, fields[4].buf);
		}
		HostCandidate hc;
		snprintf(hc.component, sizeof(hc.component), "%.*s", (int)fields[1].len, fields[1].buf);
		snprintf(hc.transport, sizeof(hc.transport), "%.*s", (int)fields[2].len, fields[2].buf);
		snprintf(hc.priority, sizeof(hc.priority), "%.*s", (int)fields[3].len, fields[3].buf);
		snprintf(hc.port, sizeof(hc.port), "%.*s", (int)fields[5].len, fields[5].buf);
		hc.v6 = memchr(fields[4].buf, ':', fields[4].len) != NULL;
		bool duplicate = false;
		for (size_t i = 0; i < found_count && !duplicate; ++i) {
			duplicate = !strcmp(found[i].component, hc.component) && !strcmp(found[i].transport, hc.transport)
					&& !strcmp(found[i].port, hc.port) && found[i].v6 == hc.v6;
		}
		if (!duplicate && found_count < sizeof(found) / sizeof(found[0])) {
			found[found_count++] = hc;
		}
	}
	if (!found_count) {
		return NULL;
	}

	size_t cap = len + 2 + found_count * nn->_advertise_count * 160 + 1;
	char *out = (char *)malloc(cap);
	if (!out) {
		return NULL;
	}
	memcpy(out, sdp, insert_at);
	size_t n = insert_at;
	if (n && out[n - 1] != '\n') {
		out[n++] = '\r';
		out[n++] = '\n';
	}
	for (size_t a = 0; a < nn->_advertise_count; ++a) {
		const char *adv = nn->_advertise[a];
		bool adv_v6 = strchr(adv, ':') != NULL, local = false;
		for (size_t i = 0; i < address_count && !local; ++i) {
			local = !strcmp(addresses[i], adv);
		}
		for (size_t i = 0; i < found_count && !local; ++i) {
			if (found[i].v6 != adv_v6) {
				continue;
			}
			int w = snprintf(out + n, cap - n, "a=candidate:nnadv%zu %s %s %s %s %s typ host\r\n", a, found[i].component, found[i].transport, found[i].priority, adv, found[i].port);
			if (w < 0 || (size_t)w >= cap - n - (len - insert_at)) {
				free(out);
				return NULL;
			}
			n += (size_t)w;
		}
	}
	memcpy(out + n, sdp + insert_at, len - insert_at);
	n += len - insert_at;
	out[n] = '\0';
	return out;
}

static bool load_network_options(NetherNet *nn)
{
	free(nn->_advertise);
	nn->_advertise = NULL;
	nn->_advertise_count = 0;
	free(nn->_proxies);
	nn->_proxies = NULL;
	nn->_proxy_count = 0;
	if (nn->mtu && (nn->mtu < 576 || nn->mtu > 9000)) {
		return false;
	}
	if (nn->real_ip_header && *nn->real_ip_header) {
		size_t hl = strlen(nn->real_ip_header);
		if (hl > 64) {
			return false;
		}
		for (size_t i = 0; i < hl; ++i) {
			char x = nn->real_ip_header[i];
			if (!((x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z') || (x >= '0' && x <= '9') || x == '-' || x == '_')) {
				return false;
			}
		}
	}
	struct mg_str item;
	const char *s = nn->advertise_addresses ? nn->advertise_addresses : "";
	while (next_list_item(&s, &item)) {
		char ip[48] = {0};
		struct in_addr v4;
		struct in6_addr v6;
		if (nn->_advertise_count >= NN_MAX_ADVERTISE_ADDRESSES || item.len >= sizeof(ip)) {
			return false;
		}
		memcpy(ip, item.buf, item.len);
		char canonical[48];
		if (inet_pton(AF_INET, ip, &v4) == 1) {
			inet_ntop(AF_INET, &v4, canonical, sizeof(canonical));
		} else if (inet_pton(AF_INET6, ip, &v6) == 1) {
			inet_ntop(AF_INET6, &v6, canonical, sizeof(canonical));
		} else {
			return false;
		}
		if (!nn->_advertise && !(nn->_advertise = (char (*)[48])calloc(NN_MAX_ADVERTISE_ADDRESSES, sizeof(*nn->_advertise)))) {
			return false;
		}
		memcpy(nn->_advertise[nn->_advertise_count++], canonical, sizeof(canonical));
	}
	s = nn->trusted_proxies ? nn->trusted_proxies : "";
	while (next_list_item(&s, &item)) {
		char ip[48] = {0};
		struct in_addr v4;
		struct in6_addr v6;
		if (nn->_proxy_count >= NN_MAX_TRUSTED_PROXIES || item.len >= sizeof(ip)) {
			return false;
		}
		memcpy(ip, item.buf, item.len);
		struct mg_addr a;
		if ((inet_pton(AF_INET, ip, &v4) != 1 && inet_pton(AF_INET6, ip, &v6) != 1) || !mg_aton(mg_str(ip), &a)) {
			return false;
		}
		if (!nn->_proxies && !(nn->_proxies = calloc(NN_MAX_TRUSTED_PROXIES, sizeof(struct mg_addr)))) {
			return false;
		}
		((struct mg_addr *)nn->_proxies)[nn->_proxy_count++] = a;
	}
	return true;
}

static void expire_http_connections(NetherNet *nn)
{
	uint64_t now = now_ms();
	for (struct mg_connection *c = nn->_mg_mgr->conns; c; c = c->next) {
		uint64_t deadline;
		if (!c->is_accepted || c->is_closing) {
			continue;
		}
		memcpy(&deadline, c->data, sizeof(deadline));
		if (deadline && now > deadline) {
			c->is_closing = 1;
		}
	}
}

static int limit_or(int value, int fallback)
{
	return value > 0 ? value : fallback;
}

static bool admit_offer_locked(NetherNet *nn, const char *ip)
{
	int pending = 0, pending_ip = 0, from_ip = 0;
	for (NetherNetConnection *conn = nn->_conns; conn; conn = conn->next) {
		if (conn->outgoing || atomic_load(&conn->closed)) {
			continue;
		}
		bool connected = atomic_load(&conn->connected);
		pending += !connected;
		if (!strcmp(conn->remote_ip, ip)) {
			++from_ip;
			pending_ip += !connected;
		}
	}
	return pending < limit_or(nn->max_pending, NN_DEFAULT_MAX_PENDING)
		&& pending_ip < limit_or(nn->max_pending_per_ip, NN_DEFAULT_MAX_PENDING_PER_IP)
		&& from_ip < limit_or(nn->max_connections_per_ip, NN_DEFAULT_MAX_CONNECTIONS_PER_IP);
}

typedef struct
{
	uint64_t key;
	char name[64];
} AclName;

typedef struct
{
	uint64_t key;
} AclIp;

static bool acl_lower_name(const char *in, char out[64])
{
	size_t n = strlen(in);
	if (!n || n >= 64) {
		return false;
	}
	for (size_t i = 0; i <= n; ++i) {
		char x = in[i];
		out[i] = x >= 'A' && x <= 'Z' ? (char)(x + 32) : x;
	}
	return true;
}

static uint64_t acl_name_hash(uint64_t seed, const char *lower)
{
	uint64_t h = 0xcbf29ce484222325ULL ^ seed;
	for (const unsigned char *p = (const unsigned char *)lower; *p; ++p) {
		h ^= *p;
		h *= 0x100000001b3ULL;
	}
	return h;
}

static bool acl_has_name_locked(NetherNet *nn, const IVec *list, const char *name)
{
	AclName k;
	if (!acl_lower_name(name, k.name)) {
		return false;
	}
	k.key = acl_name_hash(nn->_name_seed, k.name);
	const AclName *e = (const AclName *)nn_ivec_find(list, &k);
	return e && !strcmp(e->name, k.name);
}

bool nn_acl_set(NetherNet *nn, NetherNetAclList list, const char *const *entries, size_t count)
{
	if (!nn || !nn->_initialized || (count && !entries)) {
		return false;
	}
	bool ips = list == NN_ACL_BANNED_IPS;
	IVec fresh;
	if (nn_ivec_new(&fresh, ips ? sizeof(AclIp) : sizeof(AclName))) {
		return false;
	}
	for (size_t i = 0; i < count; ++i) {
		if (!entries[i]) {
			continue;
		}
		int rc = 0;
		if (ips) {
			struct mg_addr addr;
			if (!mg_aton(mg_str(entries[i]), &addr)) {
				continue;
			}
			AclIp e = { ip_group(&addr) };
			rc = nn_ivec_put(&fresh, &e);
		} else {
			AclName e;
			if (!acl_lower_name(entries[i], e.name)) {
				continue;
			}
			e.key = acl_name_hash(nn->_name_seed, e.name);
			rc = nn_ivec_put(&fresh, &e);
		}
		if (rc) {
			nn_ivec_destroy(&fresh);
			return false;
		}
	}
	IVec *target = ips ? &nn->_banned_ips : list == NN_ACL_WHITELIST ? &nn->_whitelist : &nn->_banned_names;
	nn_mutex_lock(&nn->_acl_mtx);
	IVec old = *target;
	*target = fresh;
	nn_mutex_unlock(&nn->_acl_mtx);
	nn_ivec_destroy(&old);
	return true;
}

void nn_acl_set_whitelist_enabled(NetherNet *nn, bool enabled)
{
	if (!nn || !nn->_initialized) {
		return;
	}
	nn_mutex_lock(&nn->_acl_mtx);
	nn->_whitelist_enabled = enabled;
	nn_mutex_unlock(&nn->_acl_mtx);
}

void nn_acl_set_policy(NetherNet *nn, bool reject_banned, bool reject_not_whitelisted, bool reject_when_full)
{
	if (!nn || !nn->_initialized) {
		return;
	}
	nn_mutex_lock(&nn->_acl_mtx);
	nn->_reject_banned = reject_banned;
	nn->_reject_not_whitelisted = reject_not_whitelisted;
	nn->_reject_when_full = reject_when_full;
	nn_mutex_unlock(&nn->_acl_mtx);
}

void nn_acl_set_capacity(NetherNet *nn, int players, int max_players)
{
	if (!nn || !nn->_initialized) {
		return;
	}
	nn_mutex_lock(&nn->_acl_mtx);
	nn->_players = players;
	nn->_max_players = max_players;
	nn_mutex_unlock(&nn->_acl_mtx);
}

static const char *acl_check_address(NetherNet *nn, const struct mg_addr *addr, int *status)
{
	AclIp k = { ip_group(addr) };
	nn_mutex_lock(&nn->_acl_mtx);
	bool banned = nn->_reject_banned && nn_ivec_find(&nn->_banned_ips, &k);
	bool full = nn->_reject_when_full && nn->_max_players > 0 && nn->_players >= nn->_max_players;
	nn_mutex_unlock(&nn->_acl_mtx);
	if (banned) {
		*status = 403;
		return "Banned.\n";
	}
	if (full) {
		*status = 503;
		return "Server is full.\n";
	}
	return NULL;
}

static const char *acl_check_player(NetherNet *nn, const char *name, int *status)
{
	nn_mutex_lock(&nn->_acl_mtx);
	bool banned = nn->_reject_banned && acl_has_name_locked(nn, &nn->_banned_names, name);
	bool not_listed = nn->_reject_not_whitelisted && nn->_whitelist_enabled && !acl_has_name_locked(nn, &nn->_whitelist, name);
	nn_mutex_unlock(&nn->_acl_mtx);
	*status = 403;
	return banned ? "Banned.\n" : not_listed ? "Not whitelisted.\n" : NULL;
}

static bool fingerprint_lines_equal(struct mg_str a, struct mg_str b)
{
	if (a.len != b.len) {
		return false;
	}
	for (size_t i = 0; i < a.len; ++i) {
		char x = a.buf[i], y = b.buf[i];
		if (x >= 'a' && x <= 'z') {
			x -= 32;
		}
		if (y >= 'a' && y <= 'z') {
			y -= 32;
		}
		if (x != y) {
			return false;
		}
	}
	return true;
}

static bool remote_fingerprints_signed(int pc, struct mg_str signed_sdp)
{
	int size = rtcGetRemoteDescription(pc, NULL, 0);
	char *remote = size > 0 ? (char *)malloc((size_t)size) : NULL;
	if (!remote || rtcGetRemoteDescription(pc, remote, size) < 0) {
		free(remote);
		return false;
	}
	bool ok = true, any = false;
	size_t cursor = 0;
	struct mg_str fp;
	while (ok && next_attribute(mg_str(remote), "a=fingerprint:", &cursor, &fp)) {
		any = true;
		bool found = false;
		size_t signed_cursor = 0;
		struct mg_str sfp;
		while (!found && next_attribute(signed_sdp, "a=fingerprint:", &signed_cursor, &sfp)) {
			found = fingerprint_lines_equal(fp, sfp);
		}
		ok = found;
	}
	free(remote);
	return ok && any;
}

static void http_server_listener(struct mg_connection *c, int ev, void *ev_data)
{
	if (ev == MG_EV_ACCEPT) {
		NetherNet *accept_nn = (NetherNet *)c->fn_data;
		bool proxied = is_trusted_proxy(accept_nn, &c->rem);
		bool rate_ok = proxied
					? accept_rate_ok(accept_nn, &c->rem, NN_HTTP_PROXY_ACCEPT_BURST, NN_HTTP_PROXY_ACCEPT_PER_SEC)
					: accept_rate_ok(accept_nn, &c->rem, NN_HTTP_ACCEPT_BURST, NN_HTTP_ACCEPT_PER_SEC);
		if (!rate_ok || !admit_http_connection(accept_nn, c, proxied)) {
			c->is_closing = 1;
			return;
		}
		if (c->is_tls) {
			struct mg_tls_opts opts = {0};
			opts.cert = mg_str(accept_nn->_tls_cert);
			opts.key = mg_str(accept_nn->_tls_key);
			mg_tls_init(c, &opts);
		}
		uint64_t deadline = now_ms() + NN_HTTP_CONN_LIFETIME_MS;
		memcpy(c->data, &deadline, sizeof(deadline));
		return;
	}
	if (ev == MG_EV_READ && c->is_accepted && c->recv.len > NN_HTTP_MAX_REQUEST_SIZE) {
		c->is_closing = 1;
		return;
	}
	if (ev != MG_EV_HTTP_MSG) {
		return;
	}

	NetherNet *nn = (NetherNet *)c->fn_data;
	struct mg_http_message *hm = (struct mg_http_message *)ev_data;
	if (mg_match(hm->method, mg_str("GET"), NULL) && mg_match(hm->uri, mg_str("/v1/join"), NULL)) {
		const char *info = nn->_server_information ? nn->_server_information : nn->server_information;
		mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s", info ? info : "{}");
	} else if (mg_match(hm->method, mg_str("POST"), NULL) && mg_match(hm->uri, mg_str("/v1/join/#"), NULL)) {
		struct mg_addr client;
		if (!client_address(nn, c, hm, &client)) {
			char proxy[64];
			mg_snprintf(proxy, sizeof(proxy), "%M", mg_print_ip, &c->rem);
			nn_trace("offer through proxy %s refused: no client address in %s", proxy, real_ip_header_name(nn));
			mg_http_reply(c, 400, "Content-Type: text/plain\r\n", "No client address in the %s header.\n", real_ip_header_name(nn));
			c->is_draining = 1;
			return;
		}
		char remote_ip[48];
		ip_limit_key(&client, remote_ip, sizeof(remote_ip));
		nn_mutex_lock(&nn->_conns_mtx);
		bool admitted = admit_offer_locked(nn, remote_ip);
		nn_mutex_unlock(&nn->_conns_mtx);
		if (!admitted) {
			mg_http_reply(c, 429, "Content-Type: text/plain\r\n", "Too many connections.\n");
			c->is_draining = 1;
			return;
		}
		int acl_status = 0;
		const char *refusal = acl_check_address(nn, &client, &acl_status);
		if (refusal) {
			nn_trace("offer from %s refused (%d): %.*s", remote_ip, acl_status, (int)strcspn(refusal, ""), refusal);
			mg_http_reply(c, acl_status, "Content-Type: text/plain\r\n", "%s", refusal);
			c->is_draining = 1;
			return;
		}

		bool identity_verified = false;
		PlayerIdentity player_identity = {0};
		char raw_identity[8192];
		size_t identity_cursor = 0;
		struct mg_str identity_attr;
		if (nn->allow_unauthenticated && !next_attribute(hm->body, "a=identity:", &identity_cursor, &identity_attr)) {
			goto accept_offer;
		}
		if (!get_attribute(hm->body, "a=identity:", raw_identity, sizeof(raw_identity))) {
			mg_http_reply(c, 404, "Content-Type: text/plain\r\n", "Unable to parse identity.\n");
			return;
		}

		size_t identity_len = strlen(raw_identity);
		identity_len = mg_base64_decode(raw_identity, identity_len, raw_identity, identity_len);
		if (!identity_len) {
			mg_http_reply(c, 404, "Content-Type: text/plain\r\n", "Unable to decode identity.\n");
			return;
		}
		raw_identity[identity_len] = '\0';

		char *raw_assertion = mg_json_get_str(mg_str(raw_identity), "$.assertion");
		struct mg_str mg_assertion = mg_str(raw_assertion);
		if (!raw_assertion) {
			nn_trace("unable to get assertion from identity");
			mg_http_reply(c, 404, "Content-Type: text/plain\r\n", "Unable to get assertion from identity.\n");
			return;
		}

		char *raw_fingerprints = mg_json_get_str(mg_assertion, "$.fingerprints");
		if (!raw_fingerprints) {
			nn_trace("unable to get assertion->fingerprints from identity");
			mg_http_reply(c, 404, "Content-Type: text/plain\r\n", "Unable to get assertion->fingerprints from identity.\n");
			mg_free(raw_assertion);
			return;
		}

		int jwts_result;

		struct mg_str fp_mg = mg_str(raw_fingerprints);
		struct mg_str fp_header, fp_payload, fp_signature;
		if ((jwts_result = nn_extract_jws(fp_mg, &fp_header, &fp_payload, &fp_signature))) {
			nn_trace("invalid JWS (%d)", jwts_result);
			mg_http_reply(c, 404, "Content-Type: text/plain\r\n", "Invalid JWS - %d.\n", jwts_result);
			mg_free(raw_fingerprints);
			mg_free(raw_assertion);
			return;
		}

		char *raw_token = mg_json_get_str(mg_assertion, "$.token");
		if (!raw_token) {
			nn_trace("unable to get assertion->token from identity");
			mg_http_reply(c, 404, "Content-Type: text/plain\r\n", "Unable to get assertion->token from identity.\n");
			mg_free(raw_fingerprints);
			mg_free(raw_assertion);
			return;
		}

		struct mg_str tkn_mg = mg_str(raw_token);
		struct mg_str tkn_header, tkn_payload, tkn_signature;
		if ((jwts_result = nn_extract_jwt(tkn_mg, &tkn_header, &tkn_payload, &tkn_signature))) {
			nn_trace("invalid JWT (%d)", jwts_result);
			mg_http_reply(c, 404, "Content-Type: text/plain\r\n", "Invalid JWT - %d.\n", jwts_result);
			mg_free(raw_token);
			mg_free(raw_fingerprints);
			mg_free(raw_assertion);
			return;
		}

		int err;
		EVP_PKEY *cpk = NULL;
		if ((err = nn_validate_game_server_token(tkn_mg, tkn_header, tkn_payload, tkn_signature, &player_identity, &cpk))) {
			if (err == NN_TOKEN_UNKNOWN_KEY) {
				atomic_store(&nn->_keys_refresh_requested, true);
			}
			nn_trace("unable to validate GameServerToken (%d)", err);
			mg_http_reply(c, 404, "Content-Type: text/plain\r\n", "Unable to validate GameServerToken.\n");
			mg_free(raw_token);
			mg_free(raw_fingerprints);
			mg_free(raw_assertion);
			return;
		}

		mg_free(raw_token);
		raw_token = NULL;

		char json_fingerprint[2048];
		size_t n = 0;
		int fp_result = build_fingerprints_json(hm->body, json_fingerprint, sizeof(json_fingerprint), &n);
		if (fp_result) {
			nn_trace("unable to build fingerprints (%d)", fp_result);
			mg_http_reply(c, 400, "Content-Type: text/plain\r\n", "Invalid fingerprint.\n");
			EVP_PKEY_free(cpk);
			mg_free(raw_fingerprints);
			mg_free(raw_assertion);
			return;
		}

		int vr = nn_verify_fingerprints_jws(fp_header, fp_signature, json_fingerprint, n, cpk);
		EVP_PKEY_free(cpk);
		mg_free(raw_fingerprints);
		mg_free(raw_assertion);

		if (vr != 0) {
			nn_trace("invalid fingerprint signature (%d)", vr);
			mg_http_reply(c, 403, "Content-Type: text/plain\r\n", "Invalid fingerprint signature.\n");
			return;
		}
		identity_verified = true;

		if ((refusal = acl_check_player(nn, player_identity.xname, &acl_status))) {
			nn_trace("offer from %s (%s, xuid %s) refused (%d): %.*s", remote_ip, player_identity.xname, player_identity.xid, acl_status, (int)strcspn(refusal, "\n"), refusal);
			mg_http_reply(c, acl_status, "Content-Type: text/plain\r\n", "%s", refusal);
			c->is_draining = 1;
			return;
		}

accept_offer:;
		struct mg_str network_id = mg_str_n(hm->uri.buf + 9, hm->uri.len - 9);
		if (!valid_network_id(network_id)) {
			mg_http_reply(c, 400, "Content-Type: text/plain\r\n", "Invalid network id.\n");
			return;
		}

		char *offer = strip_identity(hm->body);
		NetherNetConnection *conn = (NetherNetConnection *)calloc(1, sizeof(NetherNetConnection));
		if (!offer || !conn) {
			free(offer);
			free(conn);
			mg_http_reply(c, 500, "Content-Type: text/plain\r\n", "Out of memory.\n");
			return;
		}
		conn->nn = nn;
		conn->identity = player_identity;
		snprintf(conn->network_id, sizeof(conn->network_id), "%.*s", (int)network_id.len, network_id.buf);
		conn->pc = NETHERNET_INVALID_RTC_VAR;
		atomic_store(&conn->reliable_dc, NETHERNET_INVALID_RTC_VAR);
		atomic_store(&conn->unreliable_dc, NETHERNET_INVALID_RTC_VAR);
		conn->http_conn_id = c->id;
		mg_snprintf(conn->remote_address, sizeof(conn->remote_address), "%M", mg_print_ip_port, &client);
		snprintf(conn->remote_ip, sizeof(conn->remote_ip), "%s", remote_ip);
		conn->created_ms = now_ms();
		conn->reasm_expect = -1;
		nn_mutex_init(&conn->reasm_mtx);

		rtcConfiguration config = {0};
		config.enableIceTcp = false;
		config.maxMessageSize = NN_MAX_MESSAGE_SIZE;
		config.iceServers = NULL;
		config.enableIceUdpMux = true;
		if (nn->ice_port > 0 && nn->ice_port <= 65535) {
			config.portRangeBegin = config.portRangeEnd = (uint16_t)nn->ice_port;
		}
		config.disableAutoNegotiation = true;
		config.mtu = nn->mtu > 0 ? nn->mtu : 0;
		conn->pc = rtcCreatePeerConnection(&config);
		if (conn->pc < 0) {
			free(offer);
			free_connection(conn);
			mg_http_reply(c, 500, "Content-Type: text/plain\r\n", "Unable to create peer connection.\n");
			return;
		}

		rtcSetUserPointer(conn->pc, conn);
		rtcSetStateChangeCallback(conn->pc, on_rtc_state_change);
		rtcSetIceStateChangeCallback(conn->pc, on_rtc_ice_state_change);
		rtcSetGatheringStateChangeCallback(conn->pc, on_rtc_gathering_change);
		rtcSetDataChannelCallback(conn->pc, on_rtc_data_channel);

		nn_mutex_lock(&nn->_conns_mtx);
		conn->id = ++nn->_next_connection_id;
		nn_mutex_unlock(&nn->_conns_mtx);

		if (rtcSetRemoteDescription(conn->pc, offer, "offer") < 0
			|| (identity_verified && !remote_fingerprints_signed(conn->pc, hm->body))
			|| rtcSetLocalDescription(conn->pc, "answer") < 0
		) {
			free(offer);
			free_connection(conn);
			mg_http_reply(c, 400, "Content-Type: text/plain\r\n", "Unable to accept the offer.\n");
			return;
		}
		free(offer);

		nn_mutex_lock(&nn->_conns_mtx);
		conn->next = nn->_conns;
		nn->_conns = conn;
		nn_mutex_unlock(&nn->_conns_mtx);

		nn_trace("accepted offer from %s (%s), waiting for ice gathering", player_identity.xname, player_identity.xid);
	}else {
		mg_http_reply(c, 404, "Content-Type: text/plain\r\n", "Not Found\n");
	}
}

static char *insert_identity(const char *sdp, const char *identity)
{
	const char *m = strstr(sdp, "\r\nm=");
	size_t at = m ? (size_t)(m - sdp) + 2 : strlen(sdp);
	size_t identity_len = strlen(identity), sdp_len = strlen(sdp);
	char *out = (char *)malloc(sdp_len + identity_len + 16);
	if (!out) {
		return NULL;
	}
	size_t k = at;
	memcpy(out, sdp, at);
	memcpy(out + k, "a=identity:", 11);
	k += 11;
	memcpy(out + k, identity, identity_len);
	k += identity_len;
	memcpy(out + k, "\r\n", 2);
	k += 2;
	memcpy(out + k, sdp + at, sdp_len - at);
	k += sdp_len - at;
	out[k] = '\0';
	return out;
}

static char *answer_with_identity(NetherNet *nn, const char *answer)
{
	char json_fingerprint[2048];
	size_t n = 0;
	if (build_fingerprints_json(mg_str(answer), json_fingerprint, sizeof(json_fingerprint), &n)) {
		return NULL;
	}
	char *identity = nn_build_server_identity((EVP_PKEY *)nn->_operator_key, json_fingerprint, n, nn->operator_domain, nn->operator_cpk_spki);
	if (!identity) {
		return NULL;
	}
	char *out = insert_identity(answer, identity);
	free(identity);
	return out;
}

static struct mg_connection *find_http_conn(NetherNet *nn, unsigned long id)
{
	for (struct mg_connection *c = nn->_mg_mgr->conns; c; c = c->next) {
		if (c->id == id) {
			return c;
		}
	}
	return NULL;
}

static void send_ready_answers(NetherNet *nn)
{
	nn_mutex_lock(&nn->_conns_mtx);
	for (NetherNetConnection *conn = nn->_conns; conn; conn = conn->next) {
		if (conn->outgoing || !atomic_load(&conn->gathered) || atomic_load(&conn->closed) || atomic_exchange(&conn->answered, true)) {
			continue;
		}
		struct mg_connection *c = find_http_conn(nn, conn->http_conn_id);
		if (!c) {
			close_connection(conn);
			continue;
		}

		char *answer = NULL;
		int size = rtcGetLocalDescription(conn->pc, NULL, 0);
		if (size > 0 && (answer = (char *)malloc((size_t)size)) && rtcGetLocalDescription(conn->pc, answer, size) >= 0) {
			if (nn_debug_enabled()) {
				size_t cursor = 0;
				struct mg_str cand;
				while (next_attribute(mg_str(answer), "a=candidate:", &cursor, &cand)) {
					nn_trace("conn %llu: local candidate: %.*s", (unsigned long long)conn->id, (int)cand.len, cand.buf);
				}
			}
			char *advertised = add_advertised_candidates(nn, answer);
			char *signed_answer = answer_with_identity(nn, advertised ? advertised : answer);
			free(advertised);
			if (signed_answer) {
				mg_http_reply(c, 200, "Content-Type: application/sdp\r\n", "%s", signed_answer);
				free(signed_answer);
				free(answer);
				continue;
			}
		}
		free(answer);
		mg_http_reply(c, 500, "Content-Type: text/plain\r\n", "Unable to create the answer.\n");
		close_connection(conn);
	}
	nn_mutex_unlock(&nn->_conns_mtx);
}

static NN_THREAD_RETURN http_worker(void *arg)
{
	NetherNet *ptr = (NetherNet *)arg;
	while (true) {
		nn_mutex_lock(&ptr->_mg_mgr_mtx);
		if (!ptr->_worker_running) {
			nn_mutex_unlock(&ptr->_mg_mgr_mtx);
			break;
		}
		mg_mgr_poll(ptr->_mg_mgr, 0);
		send_ready_answers(ptr);
		expire_http_connections(ptr);
		nn_mutex_unlock(&ptr->_mg_mgr_mtx);
		nn_thread_sleep_ms(1);
	}
	return 0;
}

static const char *const nn_issuers[MAX_ISSUERS_NUM] = {
	NN_MINECRAFT_ISSUER
};

static NN_THREAD_RETURN key_refresher(void *arg)
{
	NetherNet *nn = (NetherNet *)arg;
	uint64_t last_success = now_ms(), last_attempt = last_success;
	while (!atomic_load(&nn->_stopping)) {
		nn_thread_sleep_ms(100);
		uint64_t now = now_ms();
		if (!(now - last_success >= NN_KEYS_REFRESH_INTERVAL_MS || atomic_load(&nn->_keys_refresh_requested))
			|| now - last_attempt < NN_KEYS_REFRESH_MIN_GAP_MS
		) {
			continue;
		}
		last_attempt = now;
		atomic_store(&nn->_keys_refresh_requested, false);
		bool all_refreshed = true;
		for (size_t i = 0; i < MAX_ISSUERS_NUM; i++) {
			if (nn_refresh_issuer(nn, nn_issuers[i])) {
				nn_trace("refreshed the signing keys of %s", nn_issuers[i]);
			} else {
				nn_trace("refreshing the signing keys of %s failed, keeping the old ones", nn_issuers[i]);
				all_refreshed = false;
			}
		}
		if (all_refreshed) {
			last_success = now;
		}
	}
	return 0;
}

static void peer_init_unwind(NetherNet *nn)
{
	free(nn->_mg_mgr);
	nn->_mg_mgr = NULL;
	nn_ivec_destroy(&nn->_banned_names);
	nn_ivec_destroy(&nn->_banned_ips);
	nn_ivec_destroy(&nn->_whitelist);
	nn_mutex_destroy(&nn->_acl_mtx);
	nn_mutex_destroy(&nn->_events_mtx);
	nn_mutex_destroy(&nn->_conns_mtx);
	nn_mutex_destroy(&nn->_mg_mgr_mtx);
}

NetherNetResult nn_peer_init(NetherNet *nn)
{
	if (!nn) {
		return NN_NN_INVALID;
	}
	if (nn->_initialized) {
		return NN_ALREADY_INITIALIZED;
	}

	nn_mutex_init(&nn->_mg_mgr_mtx);
	nn_mutex_init(&nn->_conns_mtx);
	nn_mutex_init(&nn->_events_mtx);
	nn->_conns = NULL;
	nn->_next_connection_id = 0;
	nn->_events_head = nn->_events_tail = NULL;
	nn->_events_bytes = 0;
	atomic_store(&nn->_inbound_bytes, 0);
	memset(nn->_accept_buckets, 0, sizeof(nn->_accept_buckets));
	nn_mutex_init(&nn->_acl_mtx);
	nn_ivec_new(&nn->_banned_names, sizeof(AclName));
	nn_ivec_new(&nn->_banned_ips, sizeof(AclIp));
	nn_ivec_new(&nn->_whitelist, sizeof(AclName));
	nn->_name_seed = nn_ivec_rnd_seed();
	nn->_whitelist_enabled = nn->_reject_banned = nn->_reject_not_whitelisted = nn->_reject_when_full = false;
	nn->_players = nn->_max_players = 0;
	nn->_refresh_started = false;
	nn->_listening = false;
	atomic_store(&nn->_starting, false);
	atomic_store(&nn->_stopping, false);
	atomic_store(&nn->_keys_refresh_requested, false);

	nn->_mg_mgr = (struct mg_mgr *)malloc(sizeof(struct mg_mgr));
	if (!nn->_mg_mgr) {
		peer_init_unwind(nn);
		return NN_HTTP_THREAD_CREATION_FAIL;
	}
	static atomic_flag logs_configured = ATOMIC_FLAG_INIT;
	if (!atomic_flag_test_and_set(&logs_configured)) {
#ifdef _DEBUG
		mg_log_set(MG_LL_DEBUG);
		rtcInitLogger(RTC_LOG_DEBUG, NULL);
#else
		mg_log_set(MG_LL_NONE);
		mg_log_set_fn(discard_log, NULL);
		const char *debug = getenv("NN_DEBUG");
		if (debug && (!strcmp(debug, "2") || !strcmp(debug, "3"))) {
			rtcInitLogger(debug[0] == '3' ? RTC_LOG_VERBOSE : RTC_LOG_DEBUG, NULL);
		}
#endif
	}
	mg_mgr_init(nn->_mg_mgr);
	rtcPreload();
	nn->_worker_running = true;
	if (nn_thread_create(&nn->_worker_thread, http_worker, (void *)nn)) {
		nn->_worker_running = false;
		mg_mgr_free(nn->_mg_mgr);
		peer_init_unwind(nn);
		return NN_HTTP_THREAD_CREATION_FAIL;
	}

	nn->_initialized = true;
	return NN_SUCCESS;
}

static NetherNetResult startup_claimed(NetherNet *nn, const char *http_url)
{
	if (nn->_listening) {
		return NN_ALREADY_INITIALIZED;
	}

	EVP_PKEY_free((EVP_PKEY *)nn->_operator_key);
	nn->_operator_key = NULL;
	nn_mutex_lock(&nn->_mg_mgr_mtx);
	bool options_ok = load_network_options(nn);
	nn_mutex_unlock(&nn->_mg_mgr_mtx);
	if (!options_ok) {
		return NN_INVALID_ARGS;
	}
	nn->_operator_key = nn_load_operator_key(nn->operator_key_path ? nn->operator_key_path : "operator_key.pem");
	if (!nn->_operator_key) {
		return NN_OPERATOR_KEY_FAIL;
	}

	if (!ensure_ca_store(nn)) {
		return NN_CA_STORE_FAIL;
	}

	for (size_t i = 0; i < MAX_ISSUERS_NUM; i++) {
		if (!nn_trust_issuer(nn, nn_issuers[i])) {
			nn_trace("failed to trust the issuer: %s", nn_issuers[i]);
			return NN_TISS_FAILED;
		}
	}
	bool https = !strncmp(http_url, "https://", 8);
	if (https || nn->tls_cert_path || nn->tls_key_path) {
		if (!https || !nn->tls_cert_path || !nn->tls_key_path) {
			return NN_INVALID_ARGS;
		}
		struct mg_str cert = mg_file_read(&mg_fs_posix, nn->tls_cert_path);
		struct mg_str key = mg_file_read(&mg_fs_posix, nn->tls_key_path);
		if (!cert.buf || !key.buf) {
			mg_free((void *)cert.buf);
			mg_free((void *)key.buf);
			return NN_TLS_FAIL;
		}
		free(nn->_tls_cert);
		free(nn->_tls_key);
		nn->_tls_cert = (char *)malloc(cert.len + 1);
		nn->_tls_key = (char *)malloc(key.len + 1);
		if (nn->_tls_cert && nn->_tls_key) {
			memcpy(nn->_tls_cert, cert.buf, cert.len);
			nn->_tls_cert[cert.len] = '\0';
			memcpy(nn->_tls_key, key.buf, key.len);
			nn->_tls_key[key.len] = '\0';
		}
		mg_free((void *)cert.buf);
		mg_free((void *)key.buf);
		if (!nn->_tls_cert || !nn->_tls_key) {
			return NN_TLS_FAIL;
		}
	}

	if (!nn->_refresh_started) {
		if (nn_thread_create(&nn->_refresh_thread, key_refresher, (void *)nn)) {
			return NN_HTTP_THREAD_CREATION_FAIL;
		}
		nn->_refresh_started = true;
	}

	nn_mutex_lock(&nn->_mg_mgr_mtx);
	struct mg_connection *listener = mg_http_listen(nn->_mg_mgr, http_url, http_server_listener, nn);
	nn_mutex_unlock(&nn->_mg_mgr_mtx);
	if (!listener) {
		return NN_LISTEN_FAIL;
	}
	nn->_listening = true;
	return NN_SUCCESS;
}

NetherNetResult nn_startup(NetherNet *nn, const char *server_url)
{
	if (!nn) {
		return NN_NN_INVALID;
	}
	if (!nn->_initialized) {
		return NN_NOT_INITIALIZED;
	}
	if (!server_url) {
		return NN_INVALID_ARGS;
	}
	if (atomic_exchange(&nn->_starting, true)) {
		return NN_ALREADY_INITIALIZED;
	}
	NetherNetResult result = startup_claimed(nn, server_url);
	atomic_store(&nn->_starting, false);
	return result;
}

bool nn_set_server_information(NetherNet *nn, const char *json)
{
	if (!nn || !nn->_initialized || !json) {
		return false;
	}
	size_t len = strlen(json);
	char *copy = (char *)malloc(len + 1);
	if (!copy) {
		return false;
	}
	memcpy(copy, json, len + 1);
	nn_mutex_lock(&nn->_mg_mgr_mtx);
	char *old = nn->_server_information;
	nn->_server_information = copy;
	nn_mutex_unlock(&nn->_mg_mgr_mtx);
	free(old);
	return true;
}

bool nn_update_cycle(NetherNet *nn)
{
	if (!nn || !nn->_initialized) {
		return false;
	}

	NetherNetConnection *dead = NULL;
	uint64_t now = now_ms();
	nn_mutex_lock(&nn->_conns_mtx);
	NetherNetConnection **link = &nn->_conns;
	while (*link) {
		NetherNetConnection *conn = *link;
		if (!atomic_load(&conn->pinned) && !atomic_load(&conn->connected) && now > conn->created_ms && now - conn->created_ms > (uint64_t)NN_HANDSHAKE_TIMEOUT_SEC * 1000) {
			close_connection(conn);
		}
		if (atomic_load(&conn->closed) && !atomic_load(&conn->pinned)) {
			*link = conn->next;
			conn->next = dead;
			dead = conn;
		} else {
			link = &conn->next;
		}
	}
	nn_mutex_unlock(&nn->_conns_mtx);

	while (dead) {
		NetherNetConnection *next = dead->next;
		free_connection(dead);
		dead = next;
	}
	return true;
}

static NetherNetConnection *find_connection(NetherNet *nn, uint64_t connection_id)
{
	for (NetherNetConnection *conn = nn->_conns; conn; conn = conn->next) {
		if (conn->id == connection_id) {
			return conn;
		}
	}
	return NULL;
}

bool nn_poll_event(NetherNet *nn, NetherNetEvent *out)
{
	if (!nn || !out || !nn->_initialized) {
		return false;
	}
	nn_mutex_lock(&nn->_conns_mtx);
	nn_mutex_lock(&nn->_events_mtx);
	NetherNetEvent *ev = nn->_events_head;
	if (ev) {
		nn->_events_head = ev->_next;
		if (!nn->_events_head) {
			nn->_events_tail = NULL;
		}
		if (ev->type == NN_EVENT_DATA) {
			size_t cost = ev->len + sizeof(NetherNetEvent);
			nn->_events_bytes -= cost;
			NetherNetConnection *conn = find_connection(nn, ev->connection_id);
			if (conn) {
				conn->queued_bytes -= cost;
			}
		}
	}
	nn_mutex_unlock(&nn->_events_mtx);
	nn_mutex_unlock(&nn->_conns_mtx);
	if (!ev) {
		return false;
	}
	*out = *ev;
	out->_next = NULL;
	free(ev);
	return true;
}

void nn_free_event(NetherNetEvent *ev)
{
	if (ev) {
		free(ev->data);
		ev->data = NULL;
		ev->len = 0;
	}
}

NetherNetResult nn_send(NetherNet *nn, uint64_t connection_id, const void *data, size_t len, NetherNetChannel channel)
{
	if (!nn || !data || !len) {
		return NN_INVALID_ARGS;
	}

	NetherNetResult result = NN_SUCCESS;
	uint8_t *frame = NULL;
	nn_mutex_lock(&nn->_conns_mtx);
	NetherNetConnection *conn = find_connection(nn, connection_id);
	if (!conn || atomic_load(&conn->closed)) {
		result = NN_CONNECTION_NOT_FOUND;
		goto done;
	}
	if (!atomic_load(&conn->connected)) {
		result = NN_CONNECTION_NOT_READY;
		goto done;
	}

	int dc = channel == NN_CHANNEL_UNRELIABLE ? atomic_load(&conn->unreliable_dc) : atomic_load(&conn->reliable_dc);
	int remote_max = rtcGetRemoteMaxMessageSize(conn->pc);
	size_t max = remote_max > 1 && remote_max < NN_MAX_MESSAGE_SIZE ? (size_t)remote_max : NN_MAX_MESSAGE_SIZE;
	size_t chunk = max - 1;
	size_t count = (len + chunk - 1) / chunk;

	if ((channel == NN_CHANNEL_UNRELIABLE && count > 1) || count > 256) {
		result = NN_MESSAGE_TOO_LARGE;
		goto done;
	}

	int buffered = rtcGetBufferedAmount(dc);
	if (buffered < 0 || (size_t)buffered + len > NN_MAX_SEND_BUFFERED) {
		nn_trace("conn %llu: send buffer limit reached (%d bytes queued), closing", (unsigned long long)conn->id, buffered);
		close_connection(conn);
		result = NN_SEND_FAIL;
		goto done;
	}

	frame = (uint8_t *)malloc((len < chunk ? len : chunk) + 1);
	if (!frame) {
		result = NN_SEND_FAIL;
		goto done;
	}

	nn_trace("conn %llu: send %s len %zu in %zu segment(s), remote max %d", (unsigned long long)conn->id, channel == NN_CHANNEL_UNRELIABLE ? "unreliable" : "reliable", len, count, remote_max);
	for (size_t i = 0; i < count; ++i) {
		size_t off = i * chunk;
		size_t slice = len - off < chunk ? len - off : chunk;
		frame[0] = (uint8_t)(count - 1 - i);
		memcpy(frame + 1, (const uint8_t *)data + off, slice);
		if (rtcSendMessage(dc, (const char *)frame, (int)(slice + 1)) < 0) {
			nn_trace("conn %llu: send of segment %zu/%zu failed", (unsigned long long)conn->id, i + 1, count);
			result = NN_SEND_FAIL;
			break;
		}
	}

done:
	nn_mutex_unlock(&nn->_conns_mtx);
	free(frame);
	return result;
}

NetherNetResult nn_disconnect(NetherNet *nn, uint64_t connection_id)
{
	if (!nn) {
		return NN_NN_INVALID;
	}
	nn_mutex_lock(&nn->_conns_mtx);
	NetherNetConnection *conn = find_connection(nn, connection_id);
	if (conn) {
		close_connection(conn);
	}
	nn_mutex_unlock(&nn->_conns_mtx);
	return conn ? NN_SUCCESS : NN_CONNECTION_NOT_FOUND;
}

NetherNetResult nn_destroy(NetherNet *nn)
{
	if (!nn) {
		return NN_NN_INVALID;
	}
	if (!nn->_initialized) {
		return NN_NOT_INITIALIZED;
	}

	atomic_store(&nn->_stopping, true);
	if (nn->_refresh_started) {
		nn_thread_join(nn->_refresh_thread);
		nn->_refresh_started = false;
	}
	nn_mutex_lock(&nn->_mg_mgr_mtx);
	nn->_worker_running = false;
	nn_mutex_unlock(&nn->_mg_mgr_mtx);
	nn_thread_join(nn->_worker_thread);
	if (nn->_mg_mgr) {
		mg_mgr_free(nn->_mg_mgr);
		free(nn->_mg_mgr);
		nn->_mg_mgr = NULL;
	}

	NetherNetConnection *conn = nn->_conns;
	nn->_conns = NULL;
	while (conn) {
		NetherNetConnection *next = conn->next;
		free_connection(conn);
		conn = next;
	}

	NetherNetEvent *ev = nn->_events_head;
	nn->_events_head = nn->_events_tail = NULL;
	while (ev) {
		NetherNetEvent *next = ev->_next;
		free(ev->data);
		free(ev);
		ev = next;
	}

	free(nn->_server_information);
	nn->_server_information = NULL;
	free(nn->_tls_cert);
	free(nn->_tls_key);
	nn->_tls_cert = nn->_tls_key = NULL;

	EVP_PKEY_free((EVP_PKEY *)nn->_operator_key);
	nn->_operator_key = NULL;
	X509_STORE_free((X509_STORE *)nn->_ca_store);
	nn->_ca_store = NULL;
	free(nn->_advertise);
	nn->_advertise = NULL;
	nn->_advertise_count = 0;
	free(nn->_proxies);
	nn->_proxies = NULL;
	nn->_proxy_count = 0;

	nn_ivec_destroy(&nn->_banned_names);
	nn_ivec_destroy(&nn->_banned_ips);
	nn_ivec_destroy(&nn->_whitelist);
	nn_mutex_destroy(&nn->_acl_mtx);
	nn_mutex_destroy(&nn->_events_mtx);
	nn_mutex_destroy(&nn->_conns_mtx);
	nn_mutex_destroy(&nn->_mg_mgr_mtx);
	nn->_initialized = false;
	nn->_listening = false;
	return NN_DESTROY_SUCCESS;
}

char *nn_query(NetherNet *nn, const char *url)
{
	if (!nn || !nn->_initialized || !url) {
		return NULL;
	}
	char full[512];
	if ((size_t)snprintf(full, sizeof(full), "%s/v1/join", url) >= sizeof(full)) {
		return NULL;
	}
	return nn_http_get(nn, full);
}

static int remaining_ms(uint64_t deadline)
{
	uint64_t now = now_ms();
	return now >= deadline ? 0 : (int)(deadline - now);
}

static bool fingerprints_equal(const char *a, const char *b)
{
	size_t n = strlen(a);
	if (n != strlen(b)) {
		return false;
	}
	for (size_t i = 0; i < n; ++i) {
		char x = a[i], y = b[i];
		if (x >= 'a' && x <= 'z') {
			x -= 32;
		}
		if (y >= 'a' && y <= 'z') {
			y -= 32;
		}
		if (x != y) {
			return false;
		}
	}
	return true;
}

NetherNetResult nn_client_connect(NetherNet *nn, const NetherNetClientConfig *cfg, uint64_t *connection_id, char *fingerprint_out, size_t fingerprint_size)
{
	if (!nn) {
		return NN_NN_INVALID;
	}
	if (!nn->_initialized) {
		return NN_NOT_INITIALIZED;
	}
	if (!cfg || !cfg->server_url || !connection_id || (cfg->game_server_token && !cfg->client_key_pem)) {
		return NN_INVALID_ARGS;
	}
	if (fingerprint_out && fingerprint_size) {
		fingerprint_out[0] = '\0';
	}

	NetherNetResult result = NN_SUCCESS;
	uint64_t deadline = now_ms() + (uint64_t)(cfg->timeout_ms > 0 ? cfg->timeout_ms : 15000);
	EVP_PKEY *client_key = NULL;
	NetherNetConnection *conn = NULL;
	char *offer = NULL, *signed_offer = NULL, *identity = NULL, *answer = NULL, *stripped = NULL;

	if (cfg->game_server_token) {
		client_key = nn_load_private_key_pem(cfg->client_key_pem);
		if (!client_key) {
			return NN_CLIENT_KEY_FAIL;
		}
	}

	conn = (NetherNetConnection *)calloc(1, sizeof(NetherNetConnection));
	if (!conn) {
		EVP_PKEY_free(client_key);
		return NN_SEND_FAIL;
	}
	conn->nn = nn;
	conn->outgoing = true;
	if (cfg->network_id && valid_network_id(mg_str(cfg->network_id))) {
		snprintf(conn->network_id, sizeof(conn->network_id), "%s", cfg->network_id);
	} else {
		uint64_t r = 0;
		mg_random(&r, sizeof(r));
		snprintf(conn->network_id, sizeof(conn->network_id), "%llu", (unsigned long long)r);
	}
	conn->pc = NETHERNET_INVALID_RTC_VAR;
	atomic_store(&conn->reliable_dc, NETHERNET_INVALID_RTC_VAR);
	atomic_store(&conn->unreliable_dc, NETHERNET_INVALID_RTC_VAR);
	conn->created_ms = now_ms();
	conn->reasm_expect = -1;
	nn_mutex_init(&conn->reasm_mtx);

	rtcConfiguration config = {0};
	config.enableIceTcp = false;
	config.maxMessageSize = NN_MAX_MESSAGE_SIZE;
	config.iceServers = NULL;
	config.disableAutoNegotiation = true;
	config.mtu = nn->mtu > 0 ? nn->mtu : 0;
	conn->pc = rtcCreatePeerConnection(&config);
	if (conn->pc < 0) {
		free_connection(conn);
		EVP_PKEY_free(client_key);
		return NN_WEBRTC_FAIL;
	}
	rtcSetUserPointer(conn->pc, conn);
	rtcSetStateChangeCallback(conn->pc, on_rtc_state_change);
	rtcSetIceStateChangeCallback(conn->pc, on_rtc_ice_state_change);
	rtcSetGatheringStateChangeCallback(conn->pc, on_rtc_gathering_change);

	rtcDataChannelInit reliable = {0};
	rtcDataChannelInit unreliable = {0};
	unreliable.reliability.unordered = true;
	unreliable.reliability.unreliable = true;
	unreliable.reliability.maxRetransmits = 0;
	int rdc = rtcCreateDataChannelEx(conn->pc, NN_RELIABLE_CHANNEL_LABEL, &reliable);
	int udc = rtcCreateDataChannelEx(conn->pc, NN_UNRELIABLE_CHANNEL_LABEL, &unreliable);
	if (rdc < 0 || udc < 0) {
		if (rdc >= 0) rtcDeleteDataChannel(rdc);
		if (udc >= 0) rtcDeleteDataChannel(udc);
		free_connection(conn);
		EVP_PKEY_free(client_key);
		return NN_WEBRTC_FAIL;
	}
	atomic_store(&conn->reliable_dc, rdc);
	atomic_store(&conn->unreliable_dc, udc);
	int dcs[2] = { rdc, udc };
	for (int i = 0; i < 2; ++i) {
		rtcSetUserPointer(dcs[i], conn);
		rtcSetOpenCallback(dcs[i], on_dc_open);
		rtcSetClosedCallback(dcs[i], on_dc_closed);
		rtcSetMessageCallback(dcs[i], on_dc_message);
	}

	atomic_store(&conn->pinned, true);
	nn_mutex_lock(&nn->_conns_mtx);
	conn->id = ++nn->_next_connection_id;
	conn->next = nn->_conns;
	nn->_conns = conn;
	nn_mutex_unlock(&nn->_conns_mtx);

	if (rtcSetLocalDescription(conn->pc, "offer") < 0) {
		result = NN_WEBRTC_FAIL;
		goto fail;
	}
	while (!atomic_load(&conn->gathered)) {
		if (atomic_load(&conn->closed)) {
			result = NN_WEBRTC_FAIL;
			goto fail;
		}
		if (!remaining_ms(deadline)) {
			result = NN_TIMEOUT;
			goto fail;
		}
		nn_thread_sleep_ms(5);
	}

	int size = rtcGetLocalDescription(conn->pc, NULL, 0);
	if (size <= 0 || !(offer = (char *)malloc((size_t)size)) || rtcGetLocalDescription(conn->pc, offer, size) < 0) {
		result = NN_WEBRTC_FAIL;
		goto fail;
	}

	if (client_key) {
		char json_fingerprint[2048];
		size_t n = 0;
		if (build_fingerprints_json(mg_str(offer), json_fingerprint, sizeof(json_fingerprint), &n)) {
			result = NN_WEBRTC_FAIL;
			goto fail;
		}
		identity = nn_build_identity_envelope(client_key, json_fingerprint, n, cfg->game_server_token, cfg->idp_domain ? cfg->idp_domain : NN_MINECRAFT_ISSUER);
		if (!identity || !(signed_offer = insert_identity(offer, identity))) {
			result = NN_CLIENT_KEY_FAIL;
			goto fail;
		}
	}

	char url[512];
	if ((size_t)snprintf(url, sizeof(url), "%s/v1/join/%s", cfg->server_url, conn->network_id) >= sizeof(url)) {
		result = NN_INVALID_ARGS;
		goto fail;
	}
	const char *body = signed_offer ? signed_offer : offer;
	int status = 0;
	size_t answer_len = 0;
	if (!remaining_ms(deadline)) {
		result = NN_TIMEOUT;
		goto fail;
	}
	answer = http_request(nn, "POST", url, "application/sdp", body, strlen(body), &status, &answer_len, remaining_ms(deadline));
	if (!answer) {
		result = remaining_ms(deadline) ? NN_HTTP_FAIL : NN_TIMEOUT;
		goto fail;
	}
	if (status != 200) {
		nn_trace("server refused the offer (%d): %s", status, answer);
		result = NN_SERVER_REJECTED;
		goto fail;
	}

	size_t cursor = 0;
	struct mg_str server_identity;
	bool pinned = cfg->expected_fingerprint && *cfg->expected_fingerprint;
	bool identity_verified = false;
	if (next_attribute(mg_str_n(answer, answer_len), "a=identity:", &cursor, &server_identity)) {
		char json_fingerprint[2048];
		size_t n = 0;
		char fingerprint[96];
		if (build_fingerprints_json(mg_str_n(answer, answer_len), json_fingerprint, sizeof(json_fingerprint), &n)) {
			result = NN_SERVER_IDENTITY_INVALID;
			goto fail;
		}
		int vr = nn_verify_server_identity(server_identity.buf, server_identity.len, json_fingerprint, n, fingerprint, sizeof(fingerprint));
		if (vr) {
			nn_trace("invalid server identity (%d)", vr);
			result = NN_SERVER_IDENTITY_INVALID;
			goto fail;
		}
		if (pinned && !fingerprints_equal(fingerprint, cfg->expected_fingerprint)) {
			result = NN_SERVER_IDENTITY_MISMATCH;
			goto fail;
		}
		if (fingerprint_out && fingerprint_size) {
			snprintf(fingerprint_out, fingerprint_size, "%s", fingerprint);
		}
		identity_verified = true;
	} else if (!cfg->allow_missing_identity || pinned) {
		result = NN_SERVER_IDENTITY_INVALID;
		goto fail;
	}

	stripped = strip_identity(mg_str_n(answer, answer_len));
	if (!stripped
		|| rtcSetRemoteDescription(conn->pc, stripped, "answer") < 0
		|| (identity_verified && !remote_fingerprints_signed(conn->pc, mg_str_n(answer, answer_len)))
	) {
		result = NN_WEBRTC_FAIL;
		goto fail;
	}

	while (!atomic_load(&conn->connected)) {
		if (atomic_load(&conn->closed)) {
			result = NN_WEBRTC_FAIL;
			goto fail;
		}
		if (!remaining_ms(deadline)) {
			result = NN_TIMEOUT;
			goto fail;
		}
		nn_thread_sleep_ms(5);
	}

	char address[64];
	if (rtcGetRemoteAddress(conn->pc, address, sizeof(address)) > 0 && address[0]) {
		nn_mutex_lock(&nn->_events_mtx);
		snprintf(conn->remote_address, sizeof(conn->remote_address), "%s", address);
		for (NetherNetEvent *ev = nn->_events_head; ev; ev = ev->_next) {
			if (ev->connection_id == conn->id && !ev->remote_address[0]) {
				snprintf(ev->remote_address, sizeof(ev->remote_address), "%s", address);
			}
		}
		nn_mutex_unlock(&nn->_events_mtx);
	}

	*connection_id = conn->id;
	goto done;

fail:
	close_connection(conn);

done:
	EVP_PKEY_free(client_key);
	free(offer);
	free(signed_offer);
	free(identity);
	free(answer);
	free(stripped);
	atomic_store(&conn->pinned, false);
	return result;
}
