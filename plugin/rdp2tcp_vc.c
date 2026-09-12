/**
 * @file rdp2tcp_vc.c
 * static virtual channel plugin for the microsoft RDP client (mstsc.exe)
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

/*
 * rdp2tcp's server side opens a *static* virtual channel
 * (WTSVirtualChannelOpen, see server/channel.c), so the client side is the
 * legacy VirtualChannelEntry plugin ABI rather than a dynamic (IWTSPlugin)
 * one. mstsc loads this DLL from
 *
 *   HKCU\Software\Microsoft\Terminal Server Client\Default\AddIns\rdp2tcp
 *       Name = <full path to rdp2tcp_vc.dll>
 *
 * The plugin itself holds no rdp2tcp protocol knowledge. It does exactly
 * what FreeRDP's own rdp2tcp channel does: spawn rdp2tcp.exe as a child
 * with anonymous pipes on its stdin/stdout, and shuttle bytes between those
 * pipes and the virtual channel. That keeps one implementation of the
 * tunnelling logic (the client exe) shared by both RDP clients.
 *
 * Framing, which client/w32chan.c depends on:
 *   channel -> child : [UINT32 host-order totalLength][ channel payload ]
 *                      the length is written once, on CHANNEL_FLAG_FIRST
 *   child -> channel : whatever the child writes, verbatim
 */

#include <windows.h>
#include <cchannel.h>
#include <stdio.h>
#include <string.h>

#define R2T_CHANNEL_NAME "rdp2tcp"
#define R2T_HELPER_EXE   "rdp2tcp.exe"
#define R2T_IO_SIZE      (16*1024)

static struct {
	CHANNEL_ENTRY_POINTS ep;
	LPVOID initHandle;
	DWORD  openHandle;

	HANDLE child_stdin_w;  /**< channel -> child */
	HANDLE child_stdout_r; /**< child -> channel */
	PROCESS_INFORMATION pi;

	HANDLE copy_thread;
	HANDLE write_complete;

	volatile LONG running;
} vc;

/** diagnostics: visible in DebugView, mstsc gives us no console */
static void vclog(const char *fmt, ...)
{
	char buf[512];
	va_list ap;

	va_start(ap, fmt);
	_vsnprintf(buf, sizeof(buf)-1, fmt, ap);
	buf[sizeof(buf)-1] = 0;
	va_end(ap);

	OutputDebugStringA("[rdp2tcp] ");
	OutputDebugStringA(buf);
	OutputDebugStringA("\n");
}

/**
 * work out which rdp2tcp.exe to run: $RDP2TCP_EXE if set, else the one
 * sitting next to this DLL
 */
static int helper_cmdline(char *out, unsigned int outsz)
{
	char dll[MAX_PATH], *sep;
	HMODULE self = NULL;
	DWORD n;

	n = GetEnvironmentVariableA("RDP2TCP_EXE", out, outsz);
	if (n && (n < outsz)) {
		vclog("helper from RDP2TCP_EXE: %s", out);
		return 0;
	}

	if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
									|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
									(LPCSTR)(void *)&helper_cmdline, &self))
		return -1;

	n = GetModuleFileNameA(self, dll, sizeof(dll));
	if (!n || (n >= sizeof(dll)))
		return -1;

	sep = strrchr(dll, '\\');
	if (!sep)
		return -1;
	*(sep+1) = 0;

	if (_snprintf(out, outsz, "\"%s%s\"", dll, R2T_HELPER_EXE) < 0)
		return -1;

	vclog("helper next to the DLL: %s", out);

	return 0;
}

/** pump the child's stdout into the virtual channel */
static DWORD WINAPI copy_thread(LPVOID unused)
{
	DWORD r;
	char *buf;
	UINT rc;

	(void) unused;

	while (vc.running) {

		/* pVirtualChannelWrite is asynchronous: the buffer has to stay put
		 * until CHANNEL_EVENT_WRITE_COMPLETE hands it back as pUserData */
		buf = (char *) malloc(R2T_IO_SIZE);
		if (!buf) {
			vclog("out of memory in the copy thread");
			break;
		}

		if (!ReadFile(vc.child_stdout_r, buf, R2T_IO_SIZE, &r, NULL) || !r) {
			free(buf);
			vclog("child stdout closed (%lu)", GetLastError());
			break;
		}

		ResetEvent(vc.write_complete);

		rc = vc.ep.pVirtualChannelWrite(vc.openHandle, buf, r, buf);
		if (rc != CHANNEL_RC_OK) {
			free(buf);
			vclog("pVirtualChannelWrite failed: %u", rc);
			break;
		}

		/* one write in flight at a time keeps ordering and bounds memory */
		WaitForSingleObject(vc.write_complete, INFINITE);
	}

	return 0;
}

/** spawn rdp2tcp.exe with pipes on its stdin/stdout */
static int start_helper(void)
{
	SECURITY_ATTRIBUTES sa;
	STARTUPINFOA si;
	HANDLE in_r = NULL, out_w = NULL, nul;
	char cmdline[MAX_PATH+64];

	if (helper_cmdline(cmdline, sizeof(cmdline))) {
		vclog("cannot locate " R2T_HELPER_EXE);
		return -1;
	}

	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;

	if (!CreatePipe(&vc.child_stdout_r, &out_w, &sa, 0)) {
		vclog("stdout CreatePipe failed: %lu", GetLastError());
		return -1;
	}
	SetHandleInformation(vc.child_stdout_r, HANDLE_FLAG_INHERIT, 0);

	if (!CreatePipe(&in_r, &vc.child_stdin_w, &sa, 0)) {
		vclog("stdin CreatePipe failed: %lu", GetLastError());
		return -1;
	}
	SetHandleInformation(vc.child_stdin_w, HANDLE_FLAG_INHERIT, 0);

	/* STARTF_USESTDHANDLES wants three real handles, and mstsc has no
	 * console to inherit one from, so the helper's diagnostics go to NUL */
	nul = CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE,
							&sa, OPEN_EXISTING, 0, NULL);

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput  = in_r;
	si.hStdOutput = out_w;
	si.hStdError  = nul;

	/* CREATE_NO_WINDOW: rdp2tcp.exe is a console program and mstsc is not,
	 * so without this the operator gets a stray console window */
	if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW,
							  NULL, NULL, &si, &vc.pi)) {
		vclog("CreateProcess(%s) failed: %lu", cmdline, GetLastError());
		CloseHandle(in_r);
		CloseHandle(out_w);
		if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
		return -1;
	}

	/* the child owns its ends now */
	CloseHandle(in_r);
	CloseHandle(out_w);
	if (nul != INVALID_HANDLE_VALUE)
		CloseHandle(nul);

	vclog("started %s (pid %lu)", cmdline, vc.pi.dwProcessId);

	return 0;
}

static void stop_helper(void)
{
	InterlockedExchange(&vc.running, 0);

	/* Release the copy thread. It is either blocked in ReadFile or waiting
	 * for a write to complete. Closing the handle is NOT enough for the
	 * first case -- a synchronous ReadFile already in progress is not
	 * reliably aborted by CloseHandle, and the thread would hang forever --
	 * so cancel the pending I/O explicitly first, then wake the waiter. */
	if (vc.child_stdout_r)
		CancelIoEx(vc.child_stdout_r, NULL);

	if (vc.write_complete)
		SetEvent(vc.write_complete);

	if (vc.copy_thread) {
		if (WaitForSingleObject(vc.copy_thread, 2000) != WAIT_OBJECT_0)
			vclog("copy thread did not stop");
		CloseHandle(vc.copy_thread);
		vc.copy_thread = NULL;
	}

	/* only now that nobody reads from it */
	if (vc.child_stdout_r) {
		CloseHandle(vc.child_stdout_r);
		vc.child_stdout_r = NULL;
	}

	/* closing its stdin is what tells rdp2tcp.exe to exit */
	if (vc.child_stdin_w) {
		CloseHandle(vc.child_stdin_w);
		vc.child_stdin_w = NULL;
	}

	if (vc.pi.hProcess) {
		if (WaitForSingleObject(vc.pi.hProcess, 3000) != WAIT_OBJECT_0) {
			vclog("helper did not exit, terminating it");
			TerminateProcess(vc.pi.hProcess, 1);
		}
		CloseHandle(vc.pi.hProcess);
		CloseHandle(vc.pi.hThread);
		memset(&vc.pi, 0, sizeof(vc.pi));
	}

	if (vc.write_complete) {
		CloseHandle(vc.write_complete);
		vc.write_complete = NULL;
	}

	vclog("helper stopped");
}

/** virtual channel -> child stdin */
static void data_received(LPVOID pData, UINT32 dataLength,
								  UINT32 totalLength, UINT32 dataFlags)
{
	DWORD w;

	if (dataFlags & (CHANNEL_FLAG_SUSPEND | CHANNEL_FLAG_RESUME))
		return;

	if (!vc.child_stdin_w)
		return;

	/* the RDP stack splits large messages into CHANNEL_CHUNK_LENGTH pieces;
	 * the child wants the total once, up front */
	if (dataFlags & CHANNEL_FLAG_FIRST) {
		if (!WriteFile(vc.child_stdin_w, &totalLength, sizeof(totalLength),
							&w, NULL)) {
			vclog("failed writing the length prefix: %lu", GetLastError());
			return;
		}
	}

	if (!WriteFile(vc.child_stdin_w, pData, dataLength, &w, NULL))
		vclog("failed writing channel data: %lu", GetLastError());
}

static VOID VCAPITYPE open_event(DWORD openHandle, UINT event, LPVOID pData,
											UINT32 dataLength, UINT32 totalLength,
											UINT32 dataFlags)
{
	(void) openHandle;

	switch (event) {

		case CHANNEL_EVENT_DATA_RECEIVED:
			data_received(pData, dataLength, totalLength, dataFlags);
			break;

		case CHANNEL_EVENT_WRITE_COMPLETE:
		case CHANNEL_EVENT_WRITE_CANCELLED:
			/* pData is the pUserData handed to pVirtualChannelWrite */
			free(pData);
			SetEvent(vc.write_complete);
			break;
	}
}

static VOID VCAPITYPE init_event(LPVOID pInitHandle, UINT event,
											LPVOID pData, UINT dataLength)
{
	UINT rc;

	(void) pData;
	(void) dataLength;

	switch (event) {

		case CHANNEL_EVENT_CONNECTED:
			rc = vc.ep.pVirtualChannelOpen(pInitHandle, &vc.openHandle,
													 R2T_CHANNEL_NAME, open_event);
			if (rc != CHANNEL_RC_OK) {
				vclog("pVirtualChannelOpen failed: %u", rc);
				return;
			}

			vc.write_complete = CreateEvent(NULL, TRUE, FALSE, NULL);
			if (!vc.write_complete) {
				vclog("CreateEvent failed: %lu", GetLastError());
				return;
			}

			InterlockedExchange(&vc.running, 1);

			if (start_helper()) {
				stop_helper();
				return;
			}

			vc.copy_thread = CreateThread(NULL, 0, copy_thread, NULL, 0, NULL);
			if (!vc.copy_thread) {
				vclog("CreateThread failed: %lu", GetLastError());
				stop_helper();
			}
			break;

		case CHANNEL_EVENT_DISCONNECTED:
		case CHANNEL_EVENT_TERMINATED:
			stop_helper();
			if (vc.openHandle) {
				vc.ep.pVirtualChannelClose(vc.openHandle);
				vc.openHandle = 0;
			}
			break;
	}
}

/**
 * mstsc entry point, looked up by name in the registered DLL
 */
VCEXPORT WINBOOL VCAPITYPE VirtualChannelEntry(PCHANNEL_ENTRY_POINTS pEntryPoints)
{
	CHANNEL_DEF cd;
	UINT rc;

	if (!pEntryPoints || (pEntryPoints->cbSize < sizeof(vc.ep)))
		return FALSE;

	memcpy(&vc.ep, pEntryPoints, sizeof(vc.ep));

	memset(&cd, 0, sizeof(cd));
	/* "rdp2tcp" is exactly CHANNEL_NAME_LEN, so name[] holds it plus the
	 * terminator with nothing to spare -- copy the NUL explicitly */
	memcpy(cd.name, R2T_CHANNEL_NAME, sizeof(R2T_CHANNEL_NAME));
	cd.options = CHANNEL_OPTION_INITIALIZED | CHANNEL_OPTION_ENCRYPT_RDP;

	rc = vc.ep.pVirtualChannelInit(&vc.initHandle, &cd, 1,
											 VIRTUAL_CHANNEL_VERSION_WIN2000,
											 init_event);
	if (rc != CHANNEL_RC_OK) {
		vclog("pVirtualChannelInit failed: %u", rc);
		return FALSE;
	}

	vclog("channel \"" R2T_CHANNEL_NAME "\" registered");

	return TRUE;
}
