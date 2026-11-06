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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct
{
	char *data;
	uint64_t *hashes;
	int32_t *slots;
	size_t slot_capacity;
	size_t len;
	size_t capacity;
	size_t tomb;
	size_t elem_size;
	uint64_t seed;
} IVec;

uint64_t nn_ivec_rnd_seed(void);

int nn_ivec_new(IVec *iv, size_t elem_size);
int nn_ivec_new_seeded(IVec *iv, size_t elem_size, uint64_t seed);

int nn_ivec_put(IVec *iv, const void *elem);

void *nn_ivec_find(const IVec *iv, const void *key);
bool nn_ivec_remove(IVec *iv, const void *key);
void *nn_ivec_at(const IVec *iv, size_t i);

void nn_ivec_destroy(IVec *iv);

#ifdef __cplusplus
}
#endif
