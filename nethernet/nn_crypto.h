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

#include "nn_peer.h"
#include <mongoose.h>
#include <openssl/evp.h>

#define MAX_ISSUERS_NUM 1
#define NN_MINECRAFT_ISSUER "https://authorization.franchise.minecraft-services.net/"
#define NN_TOKEN_UNKNOWN_KEY 8
#define MAX_FINGERPRINTS_COUNT 8
#define MAX_FINGERPRINT_ALGO_LEN 16
#define MAX_FINGERPRINT_DIGEST_LEN 191

typedef struct
{
	char kid[64];
	EVP_PKEY *key;
} JwkEntry;

typedef struct
{
	char issuer[256];
	JwkEntry keys[16];
	int key_count;
} TrustedIssuer;

bool nn_trust_issuer(NetherNet *nn, const char *issuer);
bool nn_refresh_issuer(NetherNet *nn, const char *issuer);

EVP_PKEY *nn_find_key(const char *iss, const char *kid);
EVP_PKEY *nn_rsa_from_jwk(const char *raw_n, const char *raw_e);

int nn_extract_jwt(struct mg_str _mg_str, struct mg_str *header, struct mg_str *payload, struct mg_str *signature);
int nn_extract_jws(struct mg_str _mg_str, struct mg_str *header, struct mg_str *payload, struct mg_str *signature);

EVP_PKEY *nn_cpk_from_jwk(struct mg_str tkn_payload);

int nn_validate_game_server_token(struct mg_str tkn, struct mg_str tkn_header, struct mg_str tkn_payload, struct mg_str tkn_signature, PlayerIdentity *identity, EVP_PKEY **cpk_out);

int nn_verify_fingerprints_jws(struct mg_str hdr_b64, struct mg_str sig_b64, const char *payload, size_t payload_len, EVP_PKEY *cpk);

EVP_PKEY *nn_load_operator_key(const char *path);

char *nn_sign_es384_b64url(EVP_PKEY *key, const char *input, size_t input_len);

char *nn_build_identity_envelope(EVP_PKEY *key, const char *fingerprints_json, size_t fingerprints_json_len, const char *token, const char *domain);

char *nn_build_server_identity(EVP_PKEY *key, const char *fingerprints_json, size_t fingerprints_json_len, const char *domain, bool cpk_spki);

EVP_PKEY *nn_load_private_key_pem(const char *pem);

bool nn_public_keys_equal(EVP_PKEY *a, EVP_PKEY *b);

int nn_verify_es384(EVP_PKEY *key, const char *input, size_t input_len, struct mg_str sig_b64);

bool nn_key_fingerprint(EVP_PKEY *key, char *out, size_t out_size);

int nn_verify_server_identity(const char *identity_b64, size_t identity_b64_len, const char *fingerprints_json, size_t fingerprints_json_len, char *fingerprint_out, size_t fingerprint_size);
