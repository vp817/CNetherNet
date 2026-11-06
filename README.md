# CNetherNet

The reason behind CNetherNet is so that it can be used in other programming languages(or c itself) without needing to write it all again and again in every single programming language(unless that programming language does not support touching stuff outside of its language).

Mojang has added the **NetherNet** networking protocol to MCBE as of **v26.50** and has forced it in **v26.60**.

NetherNet is WebRTC data channels with HTTP signaling, CNetherNet does both sides of it: a **server** that players join and a **client** that joins other servers (like a proxy does).

## Usage

Check **tests/**

**server_test.c** is a server that players can join, **client_test.c** connects a client to a server in the same process and sends data both ways.

## Build tests

```
cmake -S . -DBUILD_NETHERNET_TESTS=TRUE -DCMAKE_BUILD_TYPE=Debug -B build
cmake --build build
```

On Windows if cmake can't find OpenSSL add `-DOPENSSL_ROOT_DIR="C:/Program Files/OpenSSL-Win64"` or the path of the openssl available in your machine.

## Usage

```
add_subdirectory(CNetherNet)
target_link_libraries(your_target PRIVATE nethernet)
```

then `#include <nethernet/nn_peer.h>`

## Server

1. calloc a NetherNet and fill in server_information (the json GET /v1/join answers with), operator_key_path and operator_domain
2. nn_peer_init(nn)
3. nn_startup(nn, "http://0.0.0.0:19132") (or https:// with tls_cert_path and tls_key_path set)
4. every tick call nn_update_cycle(nn) then nn_poll_event(nn, &ev) until it returns false, and nn_free_event(&ev) each one
5. nn_send(nn, id, data, len, channel) to send, nn_disconnect(nn, id) to kick
6. nn_destroy(nn) when done

The operator key is generated when it does not exist, **keep it the same file forever**, clients remember it.

## Events

**NN_EVENT_CONNECTED** - both data channels are open and the player identity (xid, xname) is verified

**NN_EVENT_DATA** - one full bedrock payload, the NetherNet framing is already removed

**NN_EVENT_DISCONNECTED** - the connection is gone

## Client

nn_query(nn, url) gets the GET /v1/join json of a server.

nn_client_connect(nn, &cfg, &id, fingerprint, sizeof(fingerprint)) connects and blocks until both channels are open, after that it is the same events and nn_send as a server connection.

## Access control

Bans, whitelist and full server checks can refuse a player at signaling, **before any WebRTC work**: nn_acl_set, nn_acl_set_whitelist_enabled, nn_acl_set_policy and nn_acl_set_capacity.

## Options

**allow_unauthenticated** - open/lan mode, offers without an identity are accepted

**ice_port** - one udp port for all the WebRTC traffic, so it can be opened in a firewall

**mtu** - lower it (1000, 900) if players on vpn or mobile data can't finish joining

**advertise_addresses** - public ips to offer when the server is behind nat, docker or a cloud vm

**trusted_proxies** and **real_ip_header** - when signaling sits behind a reverse proxy

**max_pending**, **max_pending_per_ip** and **max_connections_per_ip** - flood limits (0 = defaults)

## Debugging

Environment **NN_DEBUG=1** prints what is going on to stderr, NN_DEBUG=2 and NN_DEBUG=3 add the libdatachannel logs too.

## License

MIT, check LICENSE.
