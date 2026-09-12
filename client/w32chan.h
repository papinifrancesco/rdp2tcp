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
#ifndef __R2T_W32CHAN_H__
#define __R2T_W32CHAN_H__

#ifdef _WIN32

#include <windows.h>

/**
 * The RDP client spawns rdp2tcp.exe with CreateProcess() and hands it the
 * TS virtual channel over *anonymous* pipes bound to stdin/stdout (see
 * FreeRDP channels/rdp2tcp/client, which uses CreatePipe()).
 *
 * Anonymous pipes support neither overlapped I/O nor WaitForMultipleObjects,
 * so the blocking pipe I/O is pushed onto a reader and a writer thread and
 * the main loop waits on events they signal. That keeps the event loop
 * structurally identical to the server's (see server/events.c).
 */

int w32chan_init(void);
void w32chan_kill(void);

/** signalled while inbound channel bytes are buffered, or on EOF/error */
HANDLE w32chan_read_evt(void);
/** signalled while the outbound queue has room, or on error */
HANDLE w32chan_write_evt(void);

/**
 * read exactly len bytes from the channel, blocking until they arrive
 * @return len on success, -1 on EOF or error
 * @note this mirrors the blocking read() loop the POSIX client performs on
 *       its stdin: the reader thread only makes the wait possible, it does
 *       not change the framing semantics
 */
int w32chan_read(void *buf, unsigned int len);

/**
 * queue len bytes for the channel, never blocking
 * @return 0 on success, -1 if the pipe is gone or memory ran out
 */
int w32chan_write(const void *buf, unsigned int len);

/** 0 when the outbound queue hit its watermark and the caller must wait */
int w32chan_can_write(void);

#endif // _WIN32
#endif
