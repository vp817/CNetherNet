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

#include "nn_thread.h"

int nn_thread_create(nn_thread_t *thread, nn_thread_func_t func, void *arg)
{
#if defined(_WIN32) || defined(__WIN32__) || defined(_WIN64)
	*thread = CreateThread(NULL, 0, func, arg, 0, NULL);
	return *thread != NULL ? 0 : 1;
#else
	return pthread_create(thread, NULL, func, arg) == 0 ? 0 : 1;
#endif
}

int nn_thread_join(nn_thread_t thread)
{
#if defined(_WIN32) || defined(__WIN32__) || defined(_WIN64)
	if (!thread) {
		return 1;
	}
	WaitForSingleObject(thread, INFINITE);
	return CloseHandle(thread) ? 0 : 1;
#else
	return pthread_join(thread, NULL) == 0 ? 0 : 1;
#endif
}

int nn_thread_detach(nn_thread_t thread)
{
#if defined(_WIN32) || defined(__WIN32__) || defined(_WIN64)
	if (!thread) {
		return 1;
	}
	return CloseHandle(thread) ? 0 : 1;
#else
	return pthread_detach(thread) == 0 ? 0 : 1;
#endif
}

int nn_mutex_init(nn_mutex_t *mtx)
{
#if defined(_WIN32) || defined(__WIN32__) || defined(_WIN64)
	InitializeCriticalSection(mtx);
	return 0;
#else
	return pthread_mutex_init(mtx, NULL) == 0 ? 0 : 1;
#endif
}

int nn_mutex_lock(nn_mutex_t *mtx)
{
#if defined(_WIN32) || defined(__WIN32__) || defined(_WIN64)
	EnterCriticalSection(mtx);
	return 0;
#else
	return pthread_mutex_lock(mtx) == 0 ? 0 : 1;
#endif
}

int nn_mutex_unlock(nn_mutex_t *mtx)
{
#if defined(_WIN32) || defined(__WIN32__) || defined(_WIN64)
	LeaveCriticalSection(mtx);
	return 0;
#else
	return pthread_mutex_unlock(mtx) == 0 ? 0 : 1;
#endif
}

int nn_mutex_destroy(nn_mutex_t *mtx)
{
#if defined(_WIN32) || defined(__WIN32__) || defined(_WIN64)
	DeleteCriticalSection(mtx);
	return 0;
#else
	return pthread_mutex_destroy(mtx) == 0 ? 0 : 1;
#endif
}
