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

int main()
{
	puts("Starting up NetherNet...");

	NetherNet *nn = (NetherNet *)calloc(1, sizeof(NetherNet));
	nn->server_information = "{\"name\":\"NetherNet Server\",\"protocol\":2177,\"version\":\"1.26.50\",\"level\":\"Bedrock level\",\"players\":0,\"maxPlayers\":10,\"gameType\":0}";
	nn->operator_key_path = "operator_key.pem";
	nn->operator_domain = "nethernet.local";
	if (nn_peer_init(nn) != NN_SUCCESS) {
		puts("Unable to initialize NetherNet.");
		return 1;
	}
	NetherNetResult result = nn_startup(nn, "http://0.0.0.0:19132");
	if (result != NN_SUCCESS) {
		printf("Unable to startup server - %d.\n", result);
		nn_destroy(nn);
		free(nn);
		return 1;
	}

	puts("NetherNet startup success.");

	while (true) {
		nn_update_cycle(nn);

		NetherNetEvent ev;
		while (nn_poll_event(nn, &ev)) {
			switch (ev.type) {
				case NN_EVENT_CONNECTED:
					printf("[%llu] connected: %s (%s)\n", (unsigned long long)ev.connection_id, ev.identity.xname, ev.identity.xid);
					break;
				case NN_EVENT_DATA:
					printf("[%llu] %zu bytes on the %s channel\n", (unsigned long long)ev.connection_id, ev.len, ev.channel == NN_CHANNEL_RELIABLE ? "reliable" : "unreliable");
					break;
				case NN_EVENT_DISCONNECTED:
					printf("[%llu] disconnected\n", (unsigned long long)ev.connection_id);
					break;
				default:
					break;
			}
			nn_free_event(&ev);
		}

		nn_thread_sleep_ms(50);
	}

	puts("NetherNet closed.");
	nn_destroy(nn);
	free(nn);
	return 0;
}
