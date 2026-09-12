/**
 * @file w32chan.c
 * windows TS virtual channel pipe bridge
 */
/*
 * This file is part of rdp2tcp
 *
 * Copyright (C) 2010-2011, Nicolas Collignon
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifdef _WIN32

#include "r2tcli.h"
#include "w32chan.h"

#include <stdlib.h>
#include <string.h>

/** size of one pipe I/O chunk */
#define CHAN_IO_SIZE   (1024*64)
/** outbound queue watermark: past this the main loop stops feeding us */
#define CHAN_WR_HIMARK (1024*256)

/** growable byte FIFO shared between the main loop and one I/O thread */
typedef struct _chanbuf {
	CRITICAL_SECTION lock; /**< guards every field below */
	HANDLE evt;            /**< manual-reset readiness event */
	char *data;            /**< buffered bytes */
	unsigned int size;     /**< allocated size */
	unsigned int used;     /**< buffered size */
	int err;               /**< 1 once the pipe is unusable */
} chanbuf_t;

static struct {
	HANDLE rd_pipe;   /**< stdin: channel -> us */
	HANDLE wr_pipe;   /**< stdout: us -> channel */
	HANDLE rd_thread;
	HANDLE wr_thread;
	HANDLE wr_wake;   /**< auto-reset, kicks the writer thread */
	chanbuf_t rd;
	chanbuf_t wr;
	volatile LONG quit;
} vcp;

/**
 * append bytes to a FIFO, growing it as needed
 * @note caller must hold the FIFO lock
 * @return 0 on success
 */
static int chanbuf_append(chanbuf_t *cb, const void *buf, unsigned int len)
{
	char *ptr;
	unsigned int want;

	if (cb->used + len > cb->size) {
		want = cb->size ? cb->size : CHAN_IO_SIZE;
		while (want < cb->used + len)
			want *= 2;
		ptr = realloc(cb->data, want);
		if (!ptr)
			return -1;
		cb->data = ptr;
		cb->size = want;
	}

	memcpy(cb->data + cb->used, buf, len);
	cb->used += len;

	return 0;
}

/**
 * drop the first len bytes of a FIFO
 * @note caller must hold the FIFO lock
 */
static void chanbuf_drop(chanbuf_t *cb, unsigned int len)
{
	assert(len <= cb->used);

	cb->used -= len;
	if (cb->used)
		memmove(cb->data, cb->data + len, cb->used);
}

/** flag a FIFO as dead and wake whoever waits on it */
static void chanbuf_fail(chanbuf_t *cb)
{
	EnterCriticalSection(&cb->lock);
	cb->err = 1;
	SetEvent(cb->evt);
	LeaveCriticalSection(&cb->lock);
}

static int chanbuf_init(chanbuf_t *cb, BOOL signalled)
{
	memset(cb, 0, sizeof(*cb));

	cb->evt = CreateEvent(NULL, TRUE, signalled, NULL);
	if (!cb->evt)
		return -1;

	InitializeCriticalSection(&cb->lock);

	return 0;
}

static void chanbuf_kill(chanbuf_t *cb)
{
	if (cb->evt) {
		CloseHandle(cb->evt);
		cb->evt = NULL;
	}
	DeleteCriticalSection(&cb->lock);
	free(cb->data);
	cb->data = NULL;
	cb->size = cb->used = 0;
}

/**
 * drain the inbound pipe into the read FIFO until it closes
 */
static DWORD WINAPI reader_thread(LPVOID unused)
{
	char tmp[CHAN_IO_SIZE];
	DWORD r;
	int failed;

	(void) unused;

	for (;;) {
		if (!ReadFile(vcp.rd_pipe, tmp, sizeof(tmp), &r, NULL) || !r)
			break;

		EnterCriticalSection(&vcp.rd.lock);
		failed = chanbuf_append(&vcp.rd, tmp, (unsigned int)r);
		SetEvent(vcp.rd.evt);
		LeaveCriticalSection(&vcp.rd.lock);

		if (failed)
			break;
	}

	chanbuf_fail(&vcp.rd);

	return 0;
}

/**
 * push the write FIFO out to the channel pipe
 */
static DWORD WINAPI writer_thread(LPVOID unused)
{
	char tmp[CHAN_IO_SIZE];
	unsigned int n, off;
	DWORD w;

	(void) unused;

	for (;;) {
		EnterCriticalSection(&vcp.wr.lock);
		n = vcp.wr.used;
		if (n > sizeof(tmp))
			n = sizeof(tmp);
		if (n) {
			memcpy(tmp, vcp.wr.data, n);
			chanbuf_drop(&vcp.wr, n);
			if (vcp.wr.used < CHAN_WR_HIMARK)
				SetEvent(vcp.wr.evt);
		}
		LeaveCriticalSection(&vcp.wr.lock);

		if (!n) {
			if (vcp.quit)
				break;
			WaitForSingleObject(vcp.wr_wake, INFINITE);
			continue;
		}

		for (off = 0; off < n; off += (unsigned int)w) {
			if (!WriteFile(vcp.wr_pipe, tmp+off, n-off, &w, NULL) || !w) {
				chanbuf_fail(&vcp.wr);
				return 0;
			}
		}
	}

	return 0;
}

int w32chan_init(void)
{
	vcp.rd_pipe = GetStdHandle(STD_INPUT_HANDLE);
	vcp.wr_pipe = GetStdHandle(STD_OUTPUT_HANDLE);

	if ((vcp.rd_pipe == INVALID_HANDLE_VALUE)
			|| (vcp.wr_pipe == INVALID_HANDLE_VALUE))
		return error("no TS virtual channel on stdin/stdout");

	/* the writer FIFO starts empty, hence writable */
	if (chanbuf_init(&vcp.rd, FALSE) || chanbuf_init(&vcp.wr, TRUE))
		return error("failed to create channel events");

	vcp.wr_wake = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!vcp.wr_wake)
		return error("failed to create channel writer event");

	vcp.rd_thread = CreateThread(NULL, 0, reader_thread, NULL, 0, NULL);
	vcp.wr_thread = CreateThread(NULL, 0, writer_thread, NULL, 0, NULL);

	if (!vcp.rd_thread || !vcp.wr_thread)
		return error("failed to create channel threads");

	return 0;
}

void w32chan_kill(void)
{
	InterlockedExchange(&vcp.quit, 1);

	if (vcp.wr_wake)
		SetEvent(vcp.wr_wake);

	/* the reader thread sits in a blocking ReadFile(); closing the pipe is
	 * what releases it. Give both a moment, then stop waiting -- we are on
	 * the way out and the process is about to exit anyway. */
	if (vcp.wr_thread) {
		WaitForSingleObject(vcp.wr_thread, 2000);
		CloseHandle(vcp.wr_thread);
		vcp.wr_thread = NULL;
	}

	if (vcp.rd_thread) {
		CloseHandle(vcp.rd_thread);
		vcp.rd_thread = NULL;
	}

	if (vcp.wr_wake) {
		CloseHandle(vcp.wr_wake);
		vcp.wr_wake = NULL;
	}

	chanbuf_kill(&vcp.rd);
	chanbuf_kill(&vcp.wr);
}

HANDLE w32chan_read_evt(void)
{
	return vcp.rd.evt;
}

HANDLE w32chan_write_evt(void)
{
	return vcp.wr.evt;
}

int w32chan_read(void *buf, unsigned int len)
{
	char *ptr = (char *)buf;
	unsigned int got = 0, n;
	int dead;

	while (got < len) {

		EnterCriticalSection(&vcp.rd.lock);

		n = vcp.rd.used;
		if (n > len - got)
			n = len - got;

		if (n) {
			memcpy(ptr + got, vcp.rd.data, n);
			chanbuf_drop(&vcp.rd, n);
			got += n;
		}

		/* only stop signalling once the FIFO is drained *and* still alive */
		if (!vcp.rd.used && !vcp.rd.err)
			ResetEvent(vcp.rd.evt);

		dead = (!n && vcp.rd.err);

		LeaveCriticalSection(&vcp.rd.lock);

		if (dead)
			return -1;

		if (!n)
			WaitForSingleObject(vcp.rd.evt, INFINITE);
	}

	return (int)len;
}

int w32chan_write(const void *buf, unsigned int len)
{
	int ret = 0;

	EnterCriticalSection(&vcp.wr.lock);

	if (vcp.wr.err || chanbuf_append(&vcp.wr, buf, len)) {
		ret = -1;
	} else if (vcp.wr.used >= CHAN_WR_HIMARK) {
		ResetEvent(vcp.wr.evt);
	}

	LeaveCriticalSection(&vcp.wr.lock);

	if (!ret)
		SetEvent(vcp.wr_wake);

	return ret;
}

int w32chan_can_write(void)
{
	int ok;

	EnterCriticalSection(&vcp.wr.lock);
	ok = (!vcp.wr.err && (vcp.wr.used < CHAN_WR_HIMARK));
	LeaveCriticalSection(&vcp.wr.lock);

	return ok;
}

#endif // _WIN32
