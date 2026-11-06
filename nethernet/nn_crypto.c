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

#include "nn_crypto.h"
#include "nn_internal.h"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <math.h>
#include <stdio.h>
#include <time.h>
#include <stdatomic.h>
#if !defined(_WIN32) && !defined(__WIN32__) && !defined(_WIN64)
#include <fcntl.h>
#include <unistd.h>
#endif

static TrustedIssuer g_issuers[MAX_ISSUERS_NUM] = {0};
static int g_num_approved_issuers = 0;
static atomic_flag g_issuers_lock = ATOMIC_FLAG_INIT;

static void issuers_lock(void)
{
	while (atomic_flag_test_and_set_explicit(&g_issuers_lock, memory_order_acquire)) {
		nn_thread_sleep_ms(0);
	}
}

static void issuers_unlock(void)
{
	atomic_flag_clear_explicit(&g_issuers_lock, memory_order_release);
}

static bool exp_valid(double exp)
{
	return isfinite(exp) && exp + NN_TOKEN_CLOCK_LEEWAY_SEC > (double)time(NULL);
}

static TrustedIssuer *find_issuer_locked(const char *issuer)
{
	for (int i = 0; i < g_num_approved_issuers; ++i) {
		if (!strcmp(g_issuers[i].issuer, issuer)) {
			return g_issuers + i;
		}
	}
	return NULL;
}

static void free_keys(JwkEntry *keys, int count)
{
	for (int i = 0; i < count; ++i) {
		EVP_PKEY_free(keys[i].key);
		keys[i].key = NULL;
	}
}

static bool fetch_issuer_keys(NetherNet *nn, const char *issuer, JwkEntry *keys, int *key_count)
{
	char oid_cfg_url[300];
	snprintf(oid_cfg_url, sizeof(oid_cfg_url), "%s.well-known/openid-configuration", issuer);
	char *cfg = nn_http_get(nn, oid_cfg_url);
	if (!cfg) {
		nn_trace("trust issuer failure: was not able to get config");
		return false;
	}
	struct mg_str mg_cfg = mg_str(cfg);
	char *iss = mg_json_get_str(mg_cfg, "$.issuer");
	char *juri = mg_json_get_str(mg_cfg, "$.jwks_uri");
	free(cfg);
	if (!iss || !juri || strcmp(iss, issuer) != 0 || strncmp(juri, "https://", 8) != 0) {
		nn_trace("trust issuer failure: bad openid configuration");
		mg_free(iss);
		mg_free(juri);
		return false;
	}
	mg_free(iss);

	char *jwks = nn_http_get(nn, juri);
	mg_free(juri);
	if (!jwks) {
		nn_trace("trust issuer failure: unable to get jwks");
		return false;
	}

	JwkEntry fetched[16] = {0};
	int count = 0;
	for (int i = 0; count < 16; ++i) {
		char path[32];
		snprintf(path, sizeof(path), "$.keys[%d].kid", i);
		char *kid = mg_json_get_str(mg_str(jwks), path);
		if (!kid) {
			break;
		}
		snprintf(path, sizeof(path), "$.keys[%d].n", i);
		char *n = mg_json_get_str(mg_str(jwks), path);
		snprintf(path, sizeof(path), "$.keys[%d].e", i);
		char *e = mg_json_get_str(mg_str(jwks), path);
		EVP_PKEY *key = n && e ? nn_rsa_from_jwk(n, e) : NULL;
		if (key) {
			snprintf(fetched[count].kid, sizeof(fetched[count].kid), "%s", kid);
			fetched[count++].key = key;
		}
		mg_free(kid);
		mg_free(n);
		mg_free(e);
	}
	free(jwks);

	if (!count) {
		return false;
	}
	memcpy(keys, fetched, sizeof(fetched));
	*key_count = count;
	return true;
}

bool nn_trust_issuer(NetherNet *nn, const char *issuer)
{
	issuers_lock();
	bool known = find_issuer_locked(issuer) != NULL;
	issuers_unlock();
	if (known) {
		return true;
	}
	if (!nn) {
		return false;
	}

	JwkEntry keys[16] = {0};
	int key_count = 0;
	if (!fetch_issuer_keys(nn, issuer, keys, &key_count)) {
		return false;
	}

	issuers_lock();
	bool ok = true;
	if (!find_issuer_locked(issuer)) {
		if (g_num_approved_issuers < MAX_ISSUERS_NUM) {
			TrustedIssuer *ptr = g_issuers + g_num_approved_issuers++;
			snprintf(ptr->issuer, sizeof(ptr->issuer), "%s", issuer);
			memcpy(ptr->keys, keys, sizeof(keys));
			ptr->key_count = key_count;
			key_count = 0;
		} else {
			ok = false;
		}
	}
	issuers_unlock();
	free_keys(keys, key_count);
	return ok;
}

bool nn_refresh_issuer(NetherNet *nn, const char *issuer)
{
	JwkEntry keys[16] = {0};
	int key_count = 0;
	if (!nn || !fetch_issuer_keys(nn, issuer, keys, &key_count)) {
		return false;
	}

	JwkEntry old[16] = {0};
	int old_count = 0;
	issuers_lock();
	TrustedIssuer *ptr = find_issuer_locked(issuer);
	if (ptr) {
		memcpy(old, ptr->keys, sizeof(old));
		old_count = ptr->key_count;
		memcpy(ptr->keys, keys, sizeof(keys));
		ptr->key_count = key_count;
		key_count = 0;
	}
	issuers_unlock();
	free_keys(old, old_count);
	free_keys(keys, key_count);
	return ptr != NULL;
}

EVP_PKEY *nn_find_key(const char *iss, const char *kid)
{
	EVP_PKEY *key = NULL;
	issuers_lock();
	TrustedIssuer *ptr = find_issuer_locked(iss);
	for (int k = 0; ptr && k < ptr->key_count && !key; ++k) {
		if (!strcmp(ptr->keys[k].kid, kid) && EVP_PKEY_up_ref(ptr->keys[k].key) == 1) {
			key = ptr->keys[k].key;
		}
	}
	issuers_unlock();
	return key;
}

EVP_PKEY *nn_rsa_from_jwk(const char *raw_n, const char *raw_e)
{
	unsigned char n[1024], e[16];
	size_t nl = mg_base64url_decode(raw_n, strlen(raw_n), (char *)n, sizeof(n));
	size_t el = mg_base64url_decode(raw_e, strlen(raw_e), (char *)e, sizeof(e));
	if (!nl || !el) {
		return NULL;
	}

	BIGNUM *bn = BN_bin2bn(n, (int)nl, NULL), *be = BN_bin2bn(e, (int)el, NULL);
	OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	OSSL_PARAM *params = NULL;
	EVP_PKEY *pkey = NULL;

	if (bn && be && bld && ctx
		&& OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn)
		&& OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, be)
		&& (params = OSSL_PARAM_BLD_to_param(bld))
		&& EVP_PKEY_fromdata_init(ctx) == 1
	) {
		EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
	}

	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	EVP_PKEY_CTX_free(ctx);
	BN_free(bn);
	BN_free(be);
	return pkey;
}

int nn_extract_jwt_raw(struct mg_str _mg_str, struct mg_str *header, struct mg_str *payload, struct mg_str *signature)
{
	if (!mg_span(_mg_str, header, &_mg_str, '.')) {
		return 1;
	}
	if (!mg_span(_mg_str, payload, signature, '.')) {
		return 2;
	}
	return 0;
}

int nn_extract_jwt(struct mg_str _mg_str, struct mg_str *header, struct mg_str *payload, struct mg_str *signature)
{
	int error = nn_extract_jwt_raw(_mg_str, header, payload, signature);
	if (error) {
		return error;
	}
	if (!header->len || !payload->len || !signature->len) {
		return 3;
	}
	return error;
}

int nn_extract_jws(struct mg_str _mg_str, struct mg_str *header, struct mg_str *payload, struct mg_str *signature)
{
	int error = nn_extract_jwt_raw(_mg_str, header, payload, signature);
	if (error) {
		return error;
	}
	if (!header->len || payload->len || !signature->len) {
		return 3;
	}
	return error;
}

EVP_PKEY *nn_cpk_from_jwk(struct mg_str tkn_payload)
{
	EVP_PKEY *cpk = NULL;
	EVP_PKEY_CTX *vctx = NULL;
	unsigned char der[256];

	char *b64 = mg_json_get_str(tkn_payload, "$.cpk");
	if (!b64) {
		return NULL;
	}

	size_t der_len = mg_base64_decode(b64, strlen(b64), (char *)der, sizeof(der));
	mg_free(b64);
	if (!der_len) {
		return NULL;
	}

	const unsigned char *p = der;
	cpk = d2i_PUBKEY(NULL, &p, (long)der_len);
	if (!cpk) {
		return NULL;
	}

	char group[64] = {0};
	vctx = EVP_PKEY_CTX_new_from_pkey(NULL, cpk, NULL);
	if (!vctx
		|| EVP_PKEY_get_base_id(cpk) != EVP_PKEY_EC
		|| !EVP_PKEY_get_group_name(cpk, group, sizeof(group), NULL)
		|| strcmp(group, "secp384r1") || EVP_PKEY_public_check(vctx) != 1
	) {
		EVP_PKEY_free(cpk);
		cpk = NULL;
	}

	EVP_PKEY_CTX_free(vctx);
	return cpk;
}

int nn_validate_game_server_token(struct mg_str tkn, struct mg_str tkn_header, struct mg_str tkn_payload, struct mg_str tkn_signature, PlayerIdentity *identity, EVP_PKEY **cpk_out)
{
	*cpk_out = NULL;
	int error;
	char hdr_buf[512], pld_buf[2048], sig_buf[512];
	char *xid = NULL, *xname = NULL;
	struct mg_str decoded_hdr = { hdr_buf, sizeof(hdr_buf) };
	struct mg_str decoded_pld = { pld_buf, sizeof(pld_buf) };
	struct mg_str decoded_sig = { sig_buf, sizeof(sig_buf) };
	size_t decoded_sig_len;
	EVP_MD_CTX *md = NULL;
	EVP_PKEY *cpk = NULL;
	EVP_PKEY *key = NULL;

	size_t decoded_hdr_len = mg_base64url_decode(tkn_header.buf, tkn_header.len, decoded_hdr.buf, decoded_hdr.len);
	if (!decoded_hdr_len) {
		return 1;
	}
	decoded_hdr.len = decoded_hdr_len;

	size_t decoded_pld_len = mg_base64url_decode(tkn_payload.buf, tkn_payload.len, decoded_pld.buf, decoded_pld.len);
	if (!decoded_pld_len) {
		return 2;
	}
	decoded_pld.len = decoded_pld_len;
	if (!(decoded_sig_len = mg_base64url_decode(tkn_signature.buf, tkn_signature.len, decoded_sig.buf, decoded_sig.len))) {
		return 3;
	}

	char *alg = mg_json_get_str(decoded_hdr, "$.alg");
	char *kid = mg_json_get_str(decoded_hdr, "$.kid");
	char *iss = mg_json_get_str(decoded_pld, "$.iss");
	char *aud = mg_json_get_str(decoded_pld, "$.aud");
	double exp = 0;
	if (!alg || !kid || !iss || !aud) {
		error = 4;
		goto done;
	}
	if (strcmp(alg, "RS256")) {
		error = 5;
		goto done;
	}
	if (!mg_json_get_num(decoded_pld, "$.exp", &exp) || !exp_valid(exp)) {
		error = 6;
		goto done;
	}
	if (strcmp(aud, "api://auth-minecraft-services/multiplayer")) {
		error = 7;
		goto done;
	}

	key = nn_find_key(iss, kid);
	if (!key) {
		error = NN_TOKEN_UNKNOWN_KEY;
		goto done;
	}

	size_t signed_len = tkn_header.len + 1 + tkn_payload.len;
	md = EVP_MD_CTX_new();
	if (!md || EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, key) != 1) {
		error = 9;
		goto done;
	}

	if (EVP_DigestVerify(md, (const unsigned char *)decoded_sig.buf, decoded_sig_len, (unsigned char *)tkn.buf, signed_len) != 1) {
		error = 10;
		goto done;
	}

	cpk = nn_cpk_from_jwk(decoded_pld);
	if (!cpk) {
		error = 11;
		goto done;
	}

	xid = mg_json_get_str(decoded_pld, "$.xid");
	xname = mg_json_get_str(decoded_pld, "$.xname");
	if (!xid || !xname || strlen(xid) >= sizeof(identity->xid) || strlen(xname) >= sizeof(identity->xname)) {
		error = 12;
		goto done;
	}
	snprintf(identity->xid, sizeof(identity->xid), "%s", xid);
	snprintf(identity->xname, sizeof(identity->xname), "%s", xname);

	*cpk_out = cpk;
	cpk = NULL;

	error = 0;

done:
	EVP_MD_CTX_free(md);
	EVP_PKEY_free(key);
	mg_free(alg);
	mg_free(kid);
	mg_free(iss);
	mg_free(aud);
	EVP_PKEY_free(cpk);
	mg_free(xid);
	mg_free(xname);
	return error;
}

int nn_verify_fingerprints_jws(struct mg_str hdr_b64, struct mg_str sig_b64, const char *payload, size_t payload_len, EVP_PKEY *cpk)
{
	int error = 0, der_len = 0;
	char hdr_json[256] = {0}, *alg = NULL, *input = NULL;
	unsigned char raw[128] = {0}, *der = NULL, *p = NULL;
	ECDSA_SIG *es = NULL;
	BIGNUM *r = NULL, *s = NULL;
	EVP_MD_CTX *md = NULL;
	size_t hdr_len = 0, enc_cap = 0, enc_len = 0, input_len = 0;

	if (hdr_b64.len == 0 || hdr_b64.len > sizeof(hdr_json) || sig_b64.len != 128 || !cpk) {
		return 1;
	}

	hdr_len = mg_base64url_decode(hdr_b64.buf, hdr_b64.len, hdr_json, sizeof(hdr_json));
	if (hdr_len == 0) {
		return 2;
	}
	alg = mg_json_get_str(mg_str_n(hdr_json, hdr_len), "$.alg");
	if (!alg || strcmp(alg, "ES384") != 0) {
		error = 3;
		goto done;
	}

	enc_cap = ((payload_len / 3) + (payload_len % 3 ? 1 : 0)) * 4 + 1;
	input = (char *) malloc(hdr_b64.len + 1 + enc_cap);
	if (!input) {
		error = 4;
		goto done;
	}
	memcpy(input, hdr_b64.buf, hdr_b64.len);
	input[hdr_b64.len] = '.';
	enc_len = mg_base64url_encode((const unsigned char *) payload, payload_len, input + hdr_b64.len + 1, enc_cap);
	if (enc_len == 0) {
		error = 5;
		goto done;
	}

	input_len = hdr_b64.len + 1 + enc_len;
	if (mg_base64url_decode(sig_b64.buf, sig_b64.len, (char *) raw, sizeof(raw)) != 96) {
		error = 6;
		goto done;
	}

	es = ECDSA_SIG_new();
	r = BN_bin2bn(raw, 48, NULL);
	s = BN_bin2bn(raw + 48, 48, NULL);
	if (!es || !r || !s || ECDSA_SIG_set0(es, r, s) != 1) {
		error = 7;
		goto done;
	}
	r = s = NULL;

	der_len = i2d_ECDSA_SIG(es, NULL);
	if (der_len <= 0) {
		error = 8;
		goto done;
	}

	der = (unsigned char *)malloc((size_t) der_len);
	if (!der) {
		error = 9;
		goto done;
	}
	p = der;
	if (i2d_ECDSA_SIG(es, &p) != der_len) {
		error = 10;
		goto done;
	}

	md = EVP_MD_CTX_new();
	if (!md || EVP_DigestVerifyInit(md, NULL, EVP_sha384(), NULL, cpk) != 1) {
		error = 11;
		goto done;
	}

	if (EVP_DigestVerify(md, der, (size_t) der_len, (const unsigned char *) input, input_len) != 1) {
		error = 12;
		goto done;
	}

done:
	EVP_MD_CTX_free(md);
	free(der);
	free(input);
	BN_free(r);
	BN_free(s);
	ECDSA_SIG_free(es);
	mg_free(alg);
	return error;
}

EVP_PKEY *nn_load_operator_key(const char *path)
{
	if (!path || !*path) {
		return NULL;
	}

	EVP_PKEY *key = NULL;
	FILE *f = fopen(path, "rb");
	if (f) {
		fclose(f);
		BIO *in = BIO_new_file(path, "rb");
		key = in ? PEM_read_bio_PrivateKey(in, NULL, NULL, NULL) : NULL;
		BIO_free(in);
		if (!key) {
			nn_trace("operator key %s exists but could not be parsed", path);
			return NULL;
		}
		char group[64] = {0};
		if (EVP_PKEY_get_base_id(key) != EVP_PKEY_EC || !EVP_PKEY_get_group_name(key, group, sizeof(group), NULL) || strcmp(group, "secp384r1")) {
			nn_trace("operator key %s is not an EC P-384 key", path);
			EVP_PKEY_free(key);
			return NULL;
		}
		return key;
	}

	key = EVP_EC_gen("P-384");
	if (!key) {
		return NULL;
	}
#if defined(_WIN32) || defined(__WIN32__) || defined(_WIN64)
	BIO *out = BIO_new_file(path, "wb");
#else
	BIO *out = NULL;
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
	FILE *fp = fd >= 0 ? fdopen(fd, "wb") : NULL;
	if (fp) {
		out = BIO_new_fp(fp, BIO_CLOSE);
		if (!out) {
			fclose(fp);
		}
	} else if (fd >= 0) {
		close(fd);
	}
#endif
	if (!out) {
		EVP_PKEY_free(key);
		return NULL;
	}
	if (PEM_write_bio_PrivateKey(out, key, NULL, NULL, 0, NULL, NULL) != 1) {
		BIO_free(out);
		remove(path);
		EVP_PKEY_free(key);
		return NULL;
	}
	BIO_free(out);
	nn_trace("generated a new operator key: %s", path);
	return key;
}

char *nn_sign_es384_b64url(EVP_PKEY *key, const char *input, size_t input_len)
{
	EVP_MD_CTX *md = NULL;
	ECDSA_SIG *es = NULL;
	unsigned char *der = NULL, raw[96] = {0};
	const unsigned char *p = NULL;
	size_t der_len = 0;
	char *out = NULL;

	md = EVP_MD_CTX_new();
	if (!md || EVP_DigestSignInit(md, NULL, EVP_sha384(), NULL, key) != 1) {
		goto done;
	}
	if (EVP_DigestSign(md, NULL, &der_len, (const unsigned char *)input, input_len) != 1) {
		goto done;
	}
	der = (unsigned char *)malloc(der_len);
	if (!der || EVP_DigestSign(md, der, &der_len, (const unsigned char *)input, input_len) != 1) {
		goto done;
	}

	p = der;
	es = d2i_ECDSA_SIG(NULL, &p, (long)der_len);
	if (!es) {
		goto done;
	}
	const BIGNUM *r = NULL, *s = NULL;
	ECDSA_SIG_get0(es, &r, &s);
	if (BN_bn2binpad(r, raw, 48) != 48 || BN_bn2binpad(s, raw + 48, 48) != 48) {
		goto done;
	}

	out = (char *)malloc(129);
	if (out && !mg_base64url_encode(raw, sizeof(raw), out, 129)) {
		free(out);
		out = NULL;
	}

done:
	ECDSA_SIG_free(es);
	free(der);
	EVP_MD_CTX_free(md);
	return out;
}

static char *b64url_alloc(const char *data, size_t len)
{
	size_t cap = ((len + 2) / 3) * 4 + 1;
	char *out = (char *)malloc(cap);
	if (!out) {
		return NULL;
	}
	if (!mg_base64url_encode((const unsigned char *)data, len, out, cap) && len) {
		free(out);
		return NULL;
	}
	return out;
}

static char *join_dot(const char *a, const char *dots, const char *b)
{
	size_t la = strlen(a), ld = strlen(dots), lb = strlen(b);
	char *out = (char *)malloc(la + ld + lb + 1);
	if (!out) {
		return NULL;
	}
	memcpy(out, a, la);
	memcpy(out + la, dots, ld);
	memcpy(out + la + ld, b, lb);
	out[la + ld + lb] = '\0';
	return out;
}

static bool operator_cpk_json(EVP_PKEY *key, bool cpk_spki, char *out, size_t out_size)
{
	if (cpk_spki) {
		unsigned char *der = NULL;
		int der_len = i2d_PUBKEY(key, &der);
		if (der_len <= 0) {
			return false;
		}
		char b64[256] = {0};
		size_t n = mg_base64_encode(der, (size_t)der_len, b64, sizeof(b64));
		OPENSSL_free(der);
		if (!n) {
			return false;
		}
		return mg_snprintf(out, out_size, "\"%s\"", b64) < out_size;
	}

	unsigned char x[48] = {0}, y[48] = {0};
	BIGNUM *bx = NULL, *by = NULL;
	bool ok = EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &bx) == 1
		&& EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &by) == 1
		&& BN_bn2binpad(bx, x, 48) == 48
		&& BN_bn2binpad(by, y, 48) == 48;
	BN_free(bx);
	BN_free(by);
	if (!ok) {
		return false;
	}

	char x64[72] = {0}, y64[72] = {0};
	if (!mg_base64url_encode(x, 48, x64, sizeof(x64)) || !mg_base64url_encode(y, 48, y64, sizeof(y64))) {
		return false;
	}
	return mg_snprintf(out, out_size, "{\"crv\":\"P-384\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}", x64, y64) < out_size;
}

char *nn_build_identity_envelope(EVP_PKEY *key, const char *fingerprints_json, size_t fingerprints_json_len, const char *token, const char *domain)
{
	char *hdr_jws = NULL, *fp_b64 = NULL, *signing = NULL, *sig = NULL, *jws = NULL;
	char *assertion = NULL, *envelope = NULL, *out = NULL;

	if (!key || !fingerprints_json || !fingerprints_json_len || !token || !domain) {
		return NULL;
	}

	const char jws_header[] = "{\"alg\":\"ES384\"}";
	hdr_jws = b64url_alloc(jws_header, sizeof(jws_header) - 1);
	fp_b64 = b64url_alloc(fingerprints_json, fingerprints_json_len);
	if (!hdr_jws || !fp_b64) {
		goto done;
	}

	signing = join_dot(hdr_jws, ".", fp_b64);
	if (!signing || !(sig = nn_sign_es384_b64url(key, signing, strlen(signing)))) {
		goto done;
	}
	jws = join_dot(hdr_jws, "..", sig);
	if (!jws) {
		goto done;
	}

	size_t assertion_len = strlen(jws) + strlen(token) + 64;
	assertion = (char *)malloc(assertion_len);
	if (!assertion) {
		goto done;
	}
	mg_snprintf(assertion, assertion_len, "{\\\"fingerprints\\\":\\\"%s\\\",\\\"token\\\":\\\"%s\\\"}", jws, token);

	size_t envelope_cap = strlen(assertion) + strlen(domain) + 96;
	envelope = (char *)malloc(envelope_cap);
	if (!envelope) {
		goto done;
	}
	size_t envelope_len = mg_snprintf(envelope, envelope_cap, "{\"assertion\":\"%s\",\"idp\":{\"domain\":\"%s\",\"protocol\":\"default\"}}", assertion, domain);
	if (envelope_len >= envelope_cap) {
		goto done;
	}

	size_t out_cap = ((envelope_len + 2) / 3) * 4 + 1;
	out = (char *)malloc(out_cap);
	if (out && !mg_base64_encode((const unsigned char *)envelope, envelope_len, out, out_cap)) {
		free(out);
		out = NULL;
	}

done:
	free(hdr_jws);
	free(fp_b64);
	free(signing);
	free(sig);
	free(jws);
	free(assertion);
	free(envelope);
	return out;
}

char *nn_build_server_identity(EVP_PKEY *key, const char *fingerprints_json, size_t fingerprints_json_len, const char *domain, bool cpk_spki)
{
	char cpk[512] = {0}, payload[768] = {0};
	char *hdr_jwt = NULL, *pld_b64 = NULL, *signing = NULL, *sig = NULL, *jwt = NULL, *out = NULL;

	if (!key || !fingerprints_json || !fingerprints_json_len) {
		return NULL;
	}
	if (!domain || !*domain) {
		domain = "nethernet.invalid";
	}

	if (!operator_cpk_json(key, cpk_spki, cpk, sizeof(cpk))) {
		goto done;
	}
	long long iat = (long long)time(NULL);
	size_t pld_len = mg_snprintf(payload, sizeof(payload), "{\"cpk\":%s,\"exp\":%lld,\"iat\":%lld}", cpk, iat + NN_OPERATOR_TOKEN_TTL_SEC, iat);
	if (pld_len >= sizeof(payload)) {
		goto done;
	}

	const char jwt_header[] = "{\"alg\":\"ES384\",\"typ\":\"JWT\"}";
	hdr_jwt = b64url_alloc(jwt_header, sizeof(jwt_header) - 1);
	pld_b64 = b64url_alloc(payload, pld_len);
	if (!hdr_jwt || !pld_b64) {
		goto done;
	}
	signing = join_dot(hdr_jwt, ".", pld_b64);
	if (!signing || !(sig = nn_sign_es384_b64url(key, signing, strlen(signing)))) {
		goto done;
	}
	jwt = join_dot(signing, ".", sig);
	if (jwt) {
		out = nn_build_identity_envelope(key, fingerprints_json, fingerprints_json_len, jwt, domain);
	}

done:
	free(hdr_jwt);
	free(pld_b64);
	free(signing);
	free(sig);
	free(jwt);
	return out;
}

EVP_PKEY *nn_load_private_key_pem(const char *pem)
{
	if (!pem) {
		return NULL;
	}
	BIO *in = BIO_new_mem_buf(pem, -1);
	EVP_PKEY *key = in ? PEM_read_bio_PrivateKey(in, NULL, NULL, NULL) : NULL;
	BIO_free(in);
	char group[64] = {0};
	if (key && (EVP_PKEY_get_base_id(key) != EVP_PKEY_EC || !EVP_PKEY_get_group_name(key, group, sizeof(group), NULL) || strcmp(group, "secp384r1"))) {
		EVP_PKEY_free(key);
		key = NULL;
	}
	return key;
}

bool nn_public_keys_equal(EVP_PKEY *a, EVP_PKEY *b)
{
	return a && b && EVP_PKEY_eq(a, b) == 1;
}

int nn_verify_es384(EVP_PKEY *key, const char *input, size_t input_len, struct mg_str sig_b64)
{
	unsigned char raw[128] = {0}, *der = NULL, *p = NULL;
	ECDSA_SIG *es = NULL;
	BIGNUM *r = NULL, *s = NULL;
	EVP_MD_CTX *md = NULL;
	int error = 0, der_len = 0;

	if (!key || sig_b64.len != 128 || mg_base64url_decode(sig_b64.buf, sig_b64.len, (char *)raw, sizeof(raw)) != 96) {
		return 1;
	}
	es = ECDSA_SIG_new();
	r = BN_bin2bn(raw, 48, NULL);
	s = BN_bin2bn(raw + 48, 48, NULL);
	if (!es || !r || !s || ECDSA_SIG_set0(es, r, s) != 1) {
		error = 2;
		goto done;
	}
	r = s = NULL;
	der_len = i2d_ECDSA_SIG(es, NULL);
	if (der_len <= 0 || !(der = (unsigned char *)malloc((size_t)der_len))) {
		error = 3;
		goto done;
	}
	p = der;
	i2d_ECDSA_SIG(es, &p);
	md = EVP_MD_CTX_new();
	if (!md || EVP_DigestVerifyInit(md, NULL, EVP_sha384(), NULL, key) != 1 || EVP_DigestVerify(md, der, (size_t)der_len, (const unsigned char *)input, input_len) != 1) {
		error = 4;
	}

done:
	EVP_MD_CTX_free(md);
	free(der);
	BN_free(r);
	BN_free(s);
	ECDSA_SIG_free(es);
	return error;
}

static EVP_PKEY *cpk_from_any(struct mg_str payload)
{
	int len = 0;
	int off = mg_json_get(payload, "$.cpk", &len);
	if (off < 0) {
		return NULL;
	}
	if (payload.buf[off] == '"') {
		return nn_cpk_from_jwk(payload);
	}
	if (payload.buf[off] != '{') {
		return NULL;
	}

	char *kty = mg_json_get_str(payload, "$.cpk.kty");
	char *crv = mg_json_get_str(payload, "$.cpk.crv");
	char *x = mg_json_get_str(payload, "$.cpk.x");
	char *y = mg_json_get_str(payload, "$.cpk.y");
	EVP_PKEY *key = NULL;
	unsigned char point[97] = {0}, xb[64] = {0}, yb[64] = {0};
	if (kty && crv && x && y && !strcmp(kty, "EC") && !strcmp(crv, "P-384")
		&& mg_base64url_decode(x, strlen(x), (char *)xb, sizeof(xb)) == 48
		&& mg_base64url_decode(y, strlen(y), (char *)yb, sizeof(yb)) == 48) {
		point[0] = 0x04;
		memcpy(point + 1, xb, 48);
		memcpy(point + 49, yb, 48);
		OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
		OSSL_PARAM *params = NULL;
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
		if (bld && ctx
			&& OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "secp384r1", 0)
			&& OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, point, sizeof(point))
			&& (params = OSSL_PARAM_BLD_to_param(bld))
			&& EVP_PKEY_fromdata_init(ctx) == 1
		) {
			EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params);
		}
		OSSL_PARAM_free(params);
		OSSL_PARAM_BLD_free(bld);
		EVP_PKEY_CTX_free(ctx);
	}
	mg_free(kty);
	mg_free(crv);
	mg_free(x);
	mg_free(y);
	return key;
}

bool nn_key_fingerprint(EVP_PKEY *key, char *out, size_t out_size)
{
	unsigned char *der = NULL, digest[32];
	unsigned int digest_len = 0;
	int der_len = i2d_PUBKEY(key, &der);
	if (der_len <= 0 || out_size < 96) {
		OPENSSL_free(der);
		return false;
	}
	bool ok = EVP_Digest(der, (size_t)der_len, digest, &digest_len, EVP_sha256(), NULL) == 1 && digest_len == 32;
	OPENSSL_free(der);
	if (!ok) {
		return false;
	}
	for (int i = 0; i < 32; ++i) {
		snprintf(out + i * 3, 4, i < 31 ? "%02X:" : "%02X", digest[i]);
	}
	return true;
}

int nn_verify_server_identity(const char *identity_b64, size_t identity_b64_len, const char *fingerprints_json, size_t fingerprints_json_len, char *fingerprint_out, size_t fingerprint_size)
{
	int error = 0;
	char *envelope = NULL, *assertion = NULL, *token = NULL, *fingerprints = NULL, *alg = NULL;
	char hdr_buf[256] = {0}, pld_buf[2048] = {0};
	EVP_PKEY *cpk = NULL;

	envelope = (char *)malloc(identity_b64_len + 1);
	if (!envelope) {
		return 1;
	}
	size_t envelope_len = mg_base64_decode(identity_b64, identity_b64_len, envelope, identity_b64_len + 1);
	if (!envelope_len) {
		error = 2;
		goto done;
	}
	assertion = mg_json_get_str(mg_str_n(envelope, envelope_len), "$.assertion");
	if (!assertion) {
		error = 3;
		goto done;
	}
	token = mg_json_get_str(mg_str(assertion), "$.token");
	fingerprints = mg_json_get_str(mg_str(assertion), "$.fingerprints");
	if (!token || !fingerprints) {
		error = 4;
		goto done;
	}

	struct mg_str t_hdr = {0}, t_pld = {0}, t_sig = {0};
	if (nn_extract_jwt(mg_str(token), &t_hdr, &t_pld, &t_sig)) {
		error = 5;
		goto done;
	}
	size_t hdr_len = mg_base64url_decode(t_hdr.buf, t_hdr.len, hdr_buf, sizeof(hdr_buf));
	size_t pld_len = mg_base64url_decode(t_pld.buf, t_pld.len, pld_buf, sizeof(pld_buf));
	if (!hdr_len || !pld_len) {
		error = 6;
		goto done;
	}
	alg = mg_json_get_str(mg_str_n(hdr_buf, hdr_len), "$.alg");
	if (!alg || strcmp(alg, "ES384")) {
		error = 7;
		goto done;
	}

	struct mg_str payload = mg_str_n(pld_buf, pld_len);
	cpk = cpk_from_any(payload);
	if (!cpk) {
		error = 8;
		goto done;
	}
	if (nn_verify_es384(cpk, token, t_hdr.len + 1 + t_pld.len, t_sig)) {
		error = 9;
		goto done;
	}
	double exp = 0;
	if (!mg_json_get_num(payload, "$.exp", &exp) || !exp_valid(exp)) {
		error = 10;
		goto done;
	}

	struct mg_str f_hdr = {0}, f_pld = {0}, f_sig = {0};
	if (nn_extract_jws(mg_str(fingerprints), &f_hdr, &f_pld, &f_sig)) {
		error = 11;
		goto done;
	}
	if (nn_verify_fingerprints_jws(f_hdr, f_sig, fingerprints_json, fingerprints_json_len, cpk)) {
		error = 12;
		goto done;
	}

	if (fingerprint_out && !nn_key_fingerprint(cpk, fingerprint_out, fingerprint_size)) {
		error = 13;
	}
done:
	EVP_PKEY_free(cpk);
	mg_free(alg);
	mg_free(token);
	mg_free(fingerprints);
	mg_free(assertion);
	free(envelope);
	return error;
}
