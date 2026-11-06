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

#include <nethernet/nn_peer.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static bool wait_event(NetherNet *nn, NetherNetEvent *ev, NetherNetEventType type, int timeout_ms)
{
	for (int i = 0; i < timeout_ms; i += 10) {
		nn_update_cycle(nn);
		while (nn_poll_event(nn, ev)) {
			if (ev->type == type) {
				return true;
			}
			nn_free_event(ev);
		}
		nn_thread_sleep_ms(10);
	}
	return false;
}

int main()
{
	NetherNet *server = (NetherNet *)calloc(1, sizeof(NetherNet));
	server->operator_key_path = "client_test_operator.pem";
	server->operator_domain = "loopback.test";
	server->allow_unauthenticated = true;
	if (nn_peer_init(server) != NN_SUCCESS || nn_startup(server, "http://127.0.0.1:19160") != NN_SUCCESS) {
		puts("unable to server startup");
		return 1;
	}
	nn_set_server_information(server, "{\"name\":\"Loopback\",\"protocol\":2177}");

	NetherNet *client = (NetherNet *)calloc(1, sizeof(NetherNet));
	if (nn_peer_init(client) != NN_SUCCESS) {
		puts("unable to client init");
		return 1;
	}

	char *info = nn_query(client, "http://127.0.0.1:19160");
	printf("query: %s\n", info ? info : "(null)");
	if (!info || !strstr(info, "Loopback")) {
		puts("unable to query");
		return 1;
	}
	free(info);

	NetherNetClientConfig cfg = {0};
	cfg.server_url = "http://127.0.0.1:19160";
	cfg.timeout_ms = 15000;
	uint64_t id = 0;
	char fingerprint[96] = {0};
	NetherNetResult r = nn_client_connect(client, &cfg, &id, fingerprint, sizeof(fingerprint));
	if (r != NN_SUCCESS) {
		printf("unable to connect - %d\n", r);
		return 1;
	}
	printf("client connected, id %llu, server key %s\n", (unsigned long long)id, fingerprint);

	cfg.expected_fingerprint = "00:11";
	uint64_t id2 = 0;
	r = nn_client_connect(client, &cfg, &id2, NULL, 0);
	printf("wrong pin -> %d (%s)\n", r, r == NN_SERVER_IDENTITY_MISMATCH ? "ok" : "FAIL");
	if (r != NN_SERVER_IDENTITY_MISMATCH) {
		return 1;
	}

	NetherNetEvent ev;
	if (!wait_event(server, &ev, NN_EVENT_CONNECTED, 10000)) {
		puts("unable to server never saw the connection");
		return 1;
	}
	uint64_t server_side = ev.connection_id;
	printf("server: connected %llu (network id %s, name \"%s\")\n", (unsigned long long)server_side, ev.network_id, ev.identity.xname);
	nn_free_event(&ev);

	size_t big_len = 600 * 1024;
	uint8_t *big = (uint8_t *)malloc(big_len);
	for (size_t i = 0; i < big_len; ++i) {
		big[i] = (uint8_t)(i * 31 + 7);
	}
	if (nn_send(client, id, "ping", 4, NN_CHANNEL_UNRELIABLE) != NN_SUCCESS || nn_send(client, id, big, big_len, NN_CHANNEL_RELIABLE) != NN_SUCCESS) {
		puts("unable to client send");
		return 1;
	}

	int got = 0;
	while (got < 2 && wait_event(server, &ev, NN_EVENT_DATA, 10000)) {
		if (ev.channel == NN_CHANNEL_UNRELIABLE && ev.len == 4 && !memcmp(ev.data, "ping", 4)) {
			puts("server: got unreliable ping");
			++got;
		} else if (ev.channel == NN_CHANNEL_RELIABLE && ev.len == big_len && !memcmp(ev.data, big, big_len)) {
			puts("server: got 600 KiB reliable payload intact");
			++got;
		}
		nn_free_event(&ev);
	}
	if (got != 2) {
		puts("unable to server data");
		return 1;
	}

	if (nn_send(server, server_side, "pong", 4, NN_CHANNEL_RELIABLE) != NN_SUCCESS || !wait_event(client, &ev, NN_EVENT_DATA, 10000) || ev.len != 4 || memcmp(ev.data, "pong", 4)) {
		puts("failed to send client data");
		return 1;
	}
	puts("client: got pong");
	nn_free_event(&ev);

	nn_disconnect(client, id);
	nn_update_cycle(client);
	if (!wait_event(server, &ev, NN_EVENT_DISCONNECTED, 15000)) {
		puts("server did not receive disconnect at the end");
		return 1;
	}
	puts("server: disconnected");
	nn_free_event(&ev);

	free(big);
	nn_destroy(client);
	nn_destroy(server);
	free(client);
	free(server);
	puts("PASS");
	return 0;
}
