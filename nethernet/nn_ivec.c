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

#include "nn_ivec.h"
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32) || defined(__WIN32__) || defined(_WIN64)
#include <windows.h>
#include <bcrypt.h>
#else
#include <stdio.h>
#endif

#define IVEC_EMPTY -1
#define IVEC_TOMB -2
#define IVEC_ENTRY(iv, i) ((iv)->data + (size_t)(i) * (iv)->elem_size)

uint64_t nn_ivec_rnd_seed(void)
{
	uint64_t s = 0;
#if defined(_WIN32) || defined(__WIN32__) || defined(_WIN64)
	if (BCryptGenRandom(NULL, (PUCHAR)&s, sizeof(s), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
		s = 0x9e3779b97f4a7c15ULL;
	}
#else
	FILE *f = fopen("/dev/urandom", "rb");
	if (!f || fread(&s, sizeof(s), 1, f) != 1) {
		s = 0x9e3779b97f4a7c15ULL;
	}
	if (f) {
		fclose(f);
	}
#endif
	return s;
}

static uint64_t iv_mix64(uint64_t x)
{
	x ^= x >> 30;
	x *= 0xbf58476d1ce4e5b9ULL;
	x ^= x >> 27;
	x *= 0x94d049bb133111ebULL;
	return x ^ (x >> 31);
}

static uint64_t iv_hash(const void *key, uint64_t seed)
{
	uint64_t x;
	memcpy(&x, key, sizeof(x));
	return iv_mix64(x ^ seed);
}

static bool iv_eq(const void *a, const void *b)
{
	return memcmp(a, b, sizeof(uint64_t)) == 0;
}

int nn_ivec_new_seeded(IVec *iv, size_t elem_size, uint64_t seed)
{
	if (!iv || elem_size < sizeof(uint64_t)) {
		return 1;
	}
	memset(iv, 0, sizeof(*iv));
	iv->elem_size = elem_size;
	iv->seed = seed;
	return 0;
}

int nn_ivec_new(IVec *iv, size_t elem_size)
{
	return nn_ivec_new_seeded(iv, elem_size, nn_ivec_rnd_seed());
}

static size_t iv_probe(const IVec *iv, const void *key, uint64_t h, bool *found)
{
	size_t mask = iv->slot_capacity - 1, tomb = SIZE_MAX;
	for (size_t i = h & mask; ; i = (i + 1) & mask) {
		int32_t s = iv->slots[i];
		if (s == IVEC_EMPTY) {
			*found = false;
			return tomb != SIZE_MAX ? tomb : i;
		}
		if (s == IVEC_TOMB) {
			if (tomb == SIZE_MAX) {
				tomb = i;
			}
			continue;
		}
		if (iv->hashes[s] == h && iv_eq(IVEC_ENTRY(iv, s), key)) {
			*found = true;
			return i;
		}
	}
}

static int iv_rebuild(IVec *iv, size_t new_capacity)
{
	if (new_capacity > SIZE_MAX / sizeof(int32_t)) {
		return -1;
	}
	int32_t *slots = (int32_t *)malloc(new_capacity * sizeof(*slots));
	if (!slots) {
		return -1;
	}
	memset(slots, 0xFF, new_capacity * sizeof(*slots));
	size_t mask = new_capacity - 1;
	for (size_t i = 0; i < iv->len; ++i) {
		size_t j = iv->hashes[i] & mask;
		while (slots[j] != IVEC_EMPTY) {
			j = (j + 1) & mask;
		}
		slots[j] = (int32_t)i;
	}
	free(iv->slots);
	iv->slots = slots;
	iv->slot_capacity = new_capacity;
	iv->tomb = 0;
	return 0;
}

static int iv_grow_entries(IVec *iv)
{
	if (iv->capacity > INT32_MAX / 2) {
		return -1;
	}
	size_t new_capacity = iv->capacity ? iv->capacity * 2 : 8;
	if (new_capacity > SIZE_MAX / iv->elem_size) {
		return -1;
	}
	if (new_capacity > SIZE_MAX / sizeof(uint64_t)) {
		return -1;
	}
	char *data = (char *)realloc(iv->data, new_capacity * iv->elem_size);
	if (!data) {
		return -1;
	}
	iv->data = data;
	uint64_t *hashes = (uint64_t *)realloc(iv->hashes, new_capacity * sizeof(*hashes));
	if (!hashes) {
		return -1;
	}
	iv->hashes = hashes;
	iv->capacity = new_capacity;
	return 0;
}

void *nn_ivec_find(const IVec *iv, const void *key)
{
	if (!iv || !key || !iv->slot_capacity) {
		return NULL;
	}
	bool found;
	size_t s = iv_probe(iv, key, iv_hash(key, iv->seed), &found);
	return found ? IVEC_ENTRY(iv, iv->slots[s]) : NULL;
}

int nn_ivec_put(IVec *iv, const void *elem)
{
	if (!iv || !elem || !iv->elem_size) {
		return 1;
	}
	uint64_t h = iv_hash(elem, iv->seed);

	if (iv->slot_capacity) {
		bool found;
		size_t s = iv_probe(iv, elem, h, &found);
		if (found) {
			memcpy(IVEC_ENTRY(iv, iv->slots[s]), elem, iv->elem_size);
			return 0;
		}
	}

	if (iv->len == iv->capacity && iv_grow_entries(iv) != 0) {
		return -1;
	}

	if (iv->slot_capacity == 0 || iv->len + iv->tomb + 1 > iv->slot_capacity / 10 * 7 + iv->slot_capacity % 10 * 7 / 10) {
		if (iv->len + 1 > iv->slot_capacity / 2 && iv->slot_capacity > SIZE_MAX / sizeof(int32_t) / 2) {
			return -1;
		}
		size_t new_capacity = iv->slot_capacity == 0 ? 16 : iv->len + 1 > iv->slot_capacity / 2 ? iv->slot_capacity * 2 : iv->slot_capacity;
		if (iv_rebuild(iv, new_capacity) != 0) {
			return -1;
		}
	}

	bool found;
	size_t s = iv_probe(iv, elem, h, &found);
	if (iv->slots[s] == IVEC_TOMB) {
		--iv->tomb;
	}
	iv->slots[s] = (int32_t)iv->len;
	memcpy(IVEC_ENTRY(iv, iv->len), elem, iv->elem_size);
	iv->hashes[iv->len] = h;
	++iv->len;
	return 0;
}

bool nn_ivec_remove(IVec *iv, const void *key)
{
	if (!iv || !key || !iv->slot_capacity) {
		return false;
	}
	bool found;
	size_t s = iv_probe(iv, key, iv_hash(key, iv->seed), &found);
	if (!found) {
		return false;
	}

	size_t mask = iv->slot_capacity - 1;
	size_t i = (size_t)iv->slots[s], last = iv->len - 1;

	if (iv->slots[(s + 1) & mask] == IVEC_EMPTY) {
		iv->slots[s] = IVEC_EMPTY;
	} else {
		iv->slots[s] = IVEC_TOMB;
		++iv->tomb;
	}

	if (i != last) {
		size_t j = iv->hashes[last] & mask;
		while (iv->slots[j] != (int32_t)last) {
			j = (j + 1) & mask;
		}
		iv->slots[j] = (int32_t)i;
		memcpy(IVEC_ENTRY(iv, i), IVEC_ENTRY(iv, last), iv->elem_size);
		iv->hashes[i] = iv->hashes[last];
	}
	--iv->len;
	return true;
}

void *nn_ivec_at(const IVec *iv, size_t i)
{
	if (!iv || i >= iv->len) {
		return NULL;
	}
	return IVEC_ENTRY(iv, i);
}

void nn_ivec_destroy(IVec *iv)
{
	if (!iv) {
		return;
	}
	free(iv->data);
	free(iv->hashes);
	free(iv->slots);
	memset(iv, 0, sizeof(*iv));
}
