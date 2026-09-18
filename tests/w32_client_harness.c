/*
 * This file is part of rdp2tcp
 *
 * Exercises the native windows client (client/rdp2tcp.exe) the way an RDP
 * client drives it, without needing an RDP session.
 *
 * It reproduces exactly what FreeRDP's rdp2tcp channel does:
 *   - CreatePipe() anonymous pipes for the child's stdin/stdout
 *   - CreateProcessA() the helper
 *   - channel -> child: [UINT32 host-order totalLength][ server frame ],
 *     where the server frame is [UINT32 big-endian len][cmd][id][data]
 *   - child -> channel: whatever the child writes to stdout, verbatim
 *
 * It then plays the server side of a full tunnel: connect request, connect
 * answer, and payload in both directions.
 *
 *   usage: w32_client_harness <path to rdp2tcp.exe>
 */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define R2TCMD_CONN  0x00
#define R2TCMD_CLOSE 0x01
#define R2TCMD_DATA  0x02
#define R2TCMD_PING 0x03
#define TUNAF_IPV4  0x01

#define CTRL_PORT   8477
#define TUN_PORT    15900

static HANDLE child_in_w, child_out_r;
static PROCESS_INFORMATION pi;
static int failures = 0;

static void ok(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	printf("[ok] ");
	vprintf(fmt, ap);
	printf("\n");
	va_end(ap);
}

static void fail(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	printf("[FAIL] ");
	vprintf(fmt, ap);
	printf("\n");
	va_end(ap);
	++failures;
}

static int spawn(const char *exe)
{
	SECURITY_ATTRIBUTES sa;
	STARTUPINFOA si;
	HANDLE in_r, out_w;
	char cmdline[512];

	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;

	if (!CreatePipe(&child_out_r, &out_w, &sa, 0)) return -1;
	SetHandleInformation(child_out_r, HANDLE_FLAG_INHERIT, 0);
	if (!CreatePipe(&in_r, &child_in_w, &sa, 0)) return -1;
	SetHandleInformation(child_in_w, HANDLE_FLAG_INHERIT, 0);

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput  = in_r;
	si.hStdOutput = out_w;
	si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);

	_snprintf(cmdline, sizeof(cmdline), "%s", exe);

	if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, 0, NULL, NULL,
							  &si, &pi)) {
		fail("CreateProcess: %lu", GetLastError());
		return -1;
	}

	CloseHandle(in_r);
	CloseHandle(out_w);
	return 0;
}

/** send one rdp2tcp message the way the RDP client would deliver it */
static int send_msg(unsigned char cmd, unsigned char id,
						  const void *data, unsigned int data_len)
{
	unsigned char frame[2048];
	unsigned int inner, total;
	DWORD w;

	inner = data_len + 2;    /* cmd + id + payload */
	total = inner + 4;       /* plus the protocol's big-endian length */

	if (total + 4 > sizeof(frame)) return -1;

	memcpy(frame, &total, 4);                 /* host order, as FreeRDP does */
	frame[4] = (unsigned char)(inner >> 24);  /* big endian, as the server does */
	frame[5] = (unsigned char)(inner >> 16);
	frame[6] = (unsigned char)(inner >> 8);
	frame[7] = (unsigned char)inner;
	frame[8] = cmd;
	frame[9] = id;
	if (data_len)
		memcpy(frame+10, data, data_len);

	return (WriteFile(child_in_w, frame, total + 4, &w, NULL) ? 0 : -1);
}

/**
 * read one [big-endian length][payload] frame the client wrote to its stdout
 * @return payload length, or -1 on timeout
 */
static int read_frame(unsigned char *out, int outsz, int timeout_ms)
{
	DWORD avail = 0, got = 0;
	unsigned char hdr[4];
	unsigned int len;
	int waited = 0;

	while (waited < timeout_ms) {
		if (PeekNamedPipe(child_out_r, NULL, 0, NULL, &avail, NULL) && (avail >= 4))
			break;
		Sleep(25);
		waited += 25;
	}

	if (avail < 4) return -1;

	if (!ReadFile(child_out_r, hdr, 4, &got, NULL) || (got != 4)) return -1;

	len = ((unsigned int)hdr[0] << 24) | ((unsigned int)hdr[1] << 16)
		 | ((unsigned int)hdr[2] << 8)  | (unsigned int)hdr[3];

	if ((int)len > outsz) return -1;

	if (!ReadFile(child_out_r, out, len, &got, NULL) || (got != len)) return -1;

	return (int)len;
}

static SOCKET tcp_connect(unsigned short port)
{
	SOCKET s;
	struct sockaddr_in sa;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET) return INVALID_SOCKET;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = inet_addr("127.0.0.1");

	if (connect(s, (struct sockaddr *)&sa, sizeof(sa))) {
		closesocket(s);
		return INVALID_SOCKET;
	}

	{ DWORD tmo = 2000;
	  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tmo, sizeof(tmo)); }

	return s;
}

static int controller_cmd(const char *line, char *out, int outsz)
{
	SOCKET s;
	int n;

	s = tcp_connect(CTRL_PORT);
	if (s == INVALID_SOCKET) return -1;

	send(s, line, (int)strlen(line), 0);
	n = recv(s, out, outsz-1, 0);
	closesocket(s);

	if (n <= 0) return -1;
	out[n] = 0;
	return n;
}

int main(int argc, char **argv)
{
	WSADATA wsa;
	char reply[4096];
	unsigned char frame[2048];
	unsigned char connans[8];
	const char *to_client = "hello-from-server";
	const char *to_server = "hello-from-client";
	SOCKET t;
	unsigned char tid;
	int n;

	if (argc < 2) { printf("usage: %s <rdp2tcp.exe>\n", argv[0]); return 2; }

	setvbuf(stdout, NULL, _IONBF, 0);
	WSAStartup(MAKEWORD(2,2), &wsa);

	if (spawn(argv[1])) return 1;
	ok("spawned %s (pid %lu)", argv[1], pi.dwProcessId);
	Sleep(800);

	/* --- 1. a ping should flip the channel to connected ------------- */
	if (send_msg(R2TCMD_PING, 0, NULL, 0)) { fail("writing the ping"); return 1; }
	Sleep(600);
	ok("sent PING down the channel");

	/* --- 2. the controller should answer ---------------------------- */
	if (controller_cmd("l\n", reply, sizeof(reply)) > 0)
		ok("controller answered 'l': %.*s", (int)strcspn(reply, "\r\n"), reply);
	else
		fail("controller did not answer 'l'");

	/* --- 3. register a forward tunnel ------------------------------- */
	if (controller_cmd("t 127.0.0.1 15900 10.0.0.1 5900\n", reply, sizeof(reply)) > 0)
		ok("tunnel registered");
	else
		fail("tunnel add rejected");

	/* --- 4. connecting it must emit R2TCMD_CONN up the channel ------ */
	t = tcp_connect(TUN_PORT);
	if (t == INVALID_SOCKET) { fail("connect to the tunnel port"); return 1; }

	n = read_frame(frame, sizeof(frame), 3000);
	if ((n < 8) || (frame[0] != R2TCMD_CONN)) {
		fail("expected R2TCMD_CONN, got %d bytes", n);
		return 1;
	}
	tid = frame[1];
	ok("client requested a tunnel: R2TCMD_CONN id=0x%02x port=%u host=\"%s\"",
		tid, (frame[2] << 8) | frame[3], (char *)(frame + 5));

	/* --- 5. answer as the server would: connected, IPv4 ------------- */
	connans[0] = 0x00;        /* err = success */
	connans[1] = TUNAF_IPV4;
	connans[2] = 0x17;        /* port 5900, big endian */
	connans[3] = 0x0c;
	connans[4] = 10;          /* 10.0.0.1 */
	connans[5] = 0;
	connans[6] = 0;
	connans[7] = 1;
	if (send_msg(R2TCMD_CONN, tid, connans, sizeof(connans)))
		fail("writing the connect answer");
	Sleep(500);
	ok("sent the connect answer, tunnel 0x%02x is up", tid);

	/* --- 6. payload server -> client ------------------------------- */
	if (send_msg(R2TCMD_DATA, tid, to_client, (unsigned int)strlen(to_client)))
		fail("writing the inbound data frame");

	n = recv(t, reply, sizeof(reply)-1, 0);
	if (n > 0) {
		reply[n] = 0;
		if (!strcmp(reply, to_client))
			ok("payload reached the tunnel socket: \"%s\"", reply);
		else
			fail("tunnel socket got \"%s\", expected \"%s\"", reply, to_client);
	} else {
		fail("nothing arrived on the tunnel socket (%d)", WSAGetLastError());
	}

	/* --- 7. payload client -> server ------------------------------- */
	send(t, to_server, (int)strlen(to_server), 0);

	n = read_frame(frame, sizeof(frame), 3000);
	if ((n >= 2) && (frame[0] == R2TCMD_DATA) && (frame[1] == tid)
			&& !memcmp(frame+2, to_server, strlen(to_server))) {
		ok("payload came back up as R2TCMD_DATA: \"%.*s\"",
			n-2, (char *)(frame+2));
	} else {
		fail("expected R2TCMD_DATA back up the channel, got %d bytes", n);
	}

	closesocket(t);

	/* --- 7b. peer closes before the tunnel is up --------------------
	 * Regression for a leak found in the first live mstsc test: FD_CLOSE
	 * is one-shot, and if it arrives while the tunnel is still waiting
	 * for the connect answer, an edge-triggered loop loses it and the
	 * tunnel (and the remote process) live forever. */
	{
		SOCKET t2 = tcp_connect(TUN_PORT);
		unsigned char tid2;
		int saw_close = 0, tries;

		if (t2 == INVALID_SOCKET) { fail("second tunnel connect"); goto shutdown; }

		/* the first tunnel's R2TCMD_CLOSE may still be in flight: skip past
		 * it to the CONN for this one */
		for (tries = 0; tries < 3; ++tries) {
			n = read_frame(frame, sizeof(frame), 3000);
			if ((n >= 8) && (frame[0] == R2TCMD_CONN)) break;
		}
		if (tries == 3) { fail("second R2TCMD_CONN"); goto shutdown; }
		tid2 = frame[1];

		/* data + EOF while the server has not answered yet */
		send(t2, "early", 5, 0);
		shutdown(t2, SD_SEND);
		Sleep(300);

		/* now the server answers: the tunnel comes up with a dead peer */
		if (send_msg(R2TCMD_CONN, tid2, connans, sizeof(connans)))
			fail("writing the second connect answer");

		for (tries = 0; tries < 3 && !saw_close; ++tries) {
			n = read_frame(frame, sizeof(frame), 3000);
			if (n < 0) break;
			if ((frame[0] == R2TCMD_CLOSE) && (frame[1] == tid2))
				saw_close = 1;
		}

		if (saw_close)
			ok("EOF received before the connect answer still closes tunnel 0x%02x", tid2);
		else
			fail("tunnel 0x%02x leaked: peer EOF before the connect answer was lost", tid2);

		closesocket(t2);
	}

	/* --- 7c. reverse tunnel whose local connect-out is refused --------
	 * Regression for a leak found live: every I/O-error close path in
	 * main.c went through netsock_close() directly, which never told the
	 * server -- only the explicit tunnel_close(ns,1) API did. A reverse
	 * tunnel's local connect failing (the operator's own target refusing,
	 * exactly what a throttled local proxy does) took that path, so the
	 * server's tunnel_t lived forever, holding its id, until 255 of them
	 * had piled up over one real session. */
	{
		unsigned char tid3, rid3, connans_ok[8];
		unsigned char rconn[16];
		int tries, saw_close = 0;

		if (controller_cmd(
				"r 127.0.0.1 59999 127.0.0.1 9999\n", reply, sizeof(reply)) <= 0)
			fail("reverse tunnel add rejected");

		/* client requests the bind */
		n = read_frame(frame, sizeof(frame), 3000);
		if ((n < 2) || (frame[0] != 0x04 /* R2TCMD_BIND */)) {
			fail("expected R2TCMD_BIND, got %d bytes", n);
			goto shutdown;
		}
		tid3 = frame[1];

		/* answer as the server would: bound, IPv4, port/addr are
		 * cosmetic here since nothing real is listening */
		connans_ok[0] = 0x00; connans_ok[1] = TUNAF_IPV4;
		connans_ok[2] = 0x27; connans_ok[3] = 0x0f;   /* port 9999 */
		connans_ok[4] = 127; connans_ok[5] = 0;
		connans_ok[6] = 0;   connans_ok[7] = 1;
		if (send_msg(0x04 /* R2TCMD_BIND */, tid3, connans_ok, sizeof(connans_ok)))
			fail("writing the bind answer");
		Sleep(300);
		ok("reverse tunnel 0x%02x bound", tid3);

		/* simulate a peer connecting to our (bound) listener: rid is a
		 * fresh id for this one accepted connection. addr/port here are
		 * purely informational (the remote peer's address) -- the client
		 * connects out to the lhost:lport from the "r" command above,
		 * 127.0.0.1:1, which nothing answers on loopback */
		rid3 = (tid3 == 0x00) ? 0x01 : 0x00;
		rconn[0] = rid3; rconn[1] = TUNAF_IPV4;
		rconn[2] = 0x30; rconn[3] = 0x39;             /* port 12345, cosmetic */
		rconn[4] = 127; rconn[5] = 0; rconn[6] = 0; rconn[7] = 1;
		if (send_msg(0x05 /* R2TCMD_RCONN */, tid3, rconn, 8))
			fail("writing the RCONN frame");

		for (tries = 0; tries < 30 && !saw_close; ++tries) {
			/* keep the channel's own liveness timeout (30s+4s) from
			 * expiring during this long a wait -- a spurious client-side
			 * "disconnected" would tear the tunnel down via
			 * tunnels_kill_clients() and confound the real scenario */
			if ((tries % 6) == 0)
				send_msg(R2TCMD_PING, 0, NULL, 0);

			n = read_frame(frame, sizeof(frame), 3000);
			if (n < 0) {
				/* read_frame() returns -1 for a plain timeout too, not
				 * only a dead pipe -- only give up early if the process
				 * genuinely exited, otherwise keep polling */
				if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0)
					break;
				continue;
			}
			if ((frame[0] == R2TCMD_CLOSE) && (frame[1] == rid3))
				saw_close = 1;
		}

		if (saw_close)
			ok("refused local connect-out still closes tunnel 0x%02x", rid3);
		else
			fail("tunnel 0x%02x leaked: refused connect-out was never reported", rid3);

		controller_cmd("- 127.0.0.1 59999\n", reply, sizeof(reply));
	}

shutdown:
	/* --- 8. the RDP client going away ------------------------------ */
	CloseHandle(child_in_w);
	CloseHandle(child_out_r);

	if (WaitForSingleObject(pi.hProcess, 3000) == WAIT_OBJECT_0) {
		DWORD code = 1;
		GetExitCodeProcess(pi.hProcess, &code);
		if (!code)
			ok("client exited cleanly when the channel closed");
		else
			fail("client exited with code %lu", code);
	} else {
		fail("client still running 3s after the channel closed");
		TerminateProcess(pi.hProcess, 1);
	}

	printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
			 failures, failures == 1 ? "" : "s");

	return failures ? 1 : 0;
}
