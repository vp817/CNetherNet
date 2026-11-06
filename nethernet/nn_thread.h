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

#if defined(_WIN32) || defined(__WIN32__) || defined(_WIN64)
#include <windows.h>

#define NN_THREAD_RETURN DWORD WINAPI

typedef HANDLE nn_thread_t;
typedef CRITICAL_SECTION nn_mutex_t;
typedef DWORD (WINAPI *nn_thread_func_t)(LPVOID);

#define nn_thread_sleep_ms(ms) Sleep(ms)
#else
#include <pthread.h>
#include <unistd.h>

#define NN_THREAD_RETURN void *

typedef pthread_t nn_thread_t;
typedef pthread_mutex_t nn_mutex_t;
typedef void *(*nn_thread_func_t)(void *);

#define nn_thread_sleep_ms(ms) usleep((ms) * 1000)
#endif

#ifdef __cplusplus
extern "C"
{
#endif

int nn_thread_create(nn_thread_t *thread, nn_thread_func_t func, void *arg);
int nn_thread_join(nn_thread_t thread);
int nn_thread_detach(nn_thread_t thread);

int nn_mutex_init(nn_mutex_t *mtx);

int nn_mutex_lock(nn_mutex_t *mtx);
int nn_mutex_unlock(nn_mutex_t *mtx);

int nn_mutex_destroy(nn_mutex_t *mtx);

#ifdef __cplusplus
}
#endif
