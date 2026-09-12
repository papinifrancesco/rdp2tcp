/*
 * This file is part of rdp2tcp
 *
 * Stands in for mstsc.exe: loads plugin/rdp2tcp_vc.dll and drives the static
 * virtual channel plugin ABI exactly as the real client would, so the plugin
 * and the client helper can be tested together without an RDP session.
 *
 * Covers registration, open, chunked data delivery, asynchronous write
 * completion, a full tunnel payload round trip, disconnect, reconnect and
 * terminate.
 *
 *   usage: w32_mstsc_mock <path to rdp2tcp_vc.dll>
 */
#include <winsock2.h>
#include <windows.h>
#include <cchannel.h>
#include <stdio.h>
#include <string.h>

#define R2TCMD_CONN 0x00
#define R2TCMD_DATA 0x02
#define R2TCMD_PING 0x03
#define TUNAF_IPV4  0x01

#define CTRL_PORT   8477
#define TUN_PORT    15901

static PCHANNEL_INIT_EVENT_FN plugin_init_event;
static PCHANNEL_OPEN_EVENT_FN plugin_open_event;
static LPVOID init_handle = (LPVOID) 0xABCD0001;
static DWORD  open_handle = 0x1234;
static int    failures = 0;

/* bytes the plugin pushed up the channel, i.e. the helper's stdout */
static CRITICAL_SECTION up_lock;
static unsigned char up_buf[65536];
static unsigned int  up_len;

static void ok(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	printf("[ok] "); vprintf(fmt, ap); printf("\n");
	va_end(ap);
}

static void fail(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	printf("[FAIL] "); vprintf(fmt, ap); printf("\n");
	va_end(ap);
	++failures;
}

/* ---- the four entry points mstsc would provide --------------------- */

static UINT VCAPITYPE mock_init(LPVOID *ppInitHandle, PCHANNEL_DEF pChannel,
										  INT channelCount, ULONG versionRequested,
										  PCHANNEL_INIT_EVENT_FN proc)
{
	if (channelCount != 1) return CHANNEL_RC_TOO_MANY_CHANNELS;

	ok("registered channel \"%.*s\" options=0x%08lx version=%lu",
		CHANNEL_NAME_LEN, pChannel[0].name,
		(unsigned long)pChannel[0].options, (unsigned long)versionRequested);

	plugin_init_event = proc;
	*ppInitHandle = init_handle;
	return CHANNEL_RC_OK;
}

static UINT VCAPITYPE mock_open(LPVOID pInitHandle, LPDWORD pOpenHandle,
										  PCHAR pChannelName,
										  PCHANNEL_OPEN_EVENT_FN proc)
{
	(void) pInitHandle;
	ok("plugin opened channel \"%s\"", pChannelName);
	plugin_open_event = proc;
	*pOpenHandle = open_handle;
	return CHANNEL_RC_OK;
}

static UINT VCAPITYPE mock_close(DWORD openHandle)
{
	(void) openHandle;
	return CHANNEL_RC_OK;
}

static UINT VCAPITYPE mock_write(DWORD openHandle, LPVOID pData,
											ULONG dataLength, LPVOID pUserData)
{
	(void) openHandle;

	EnterCriticalSection(&up_lock);
	if (up_len + dataLength <= sizeof(up_buf)) {
		memcpy(up_buf + up_len, pData, dataLength);
		up_len += dataLength;
	}
	LeaveCriticalSection(&up_lock);

	/* hand the buffer back exactly as the RDP stack does */
	plugin_open_event(open_handle, CHANNEL_EVENT_WRITE_COMPLETE,
							pUserData, 0, 0, 0);

	return CHANNEL_RC_OK;
}

/* ---- helpers ------------------------------------------------------- */

/** pop one [big-endian length][payload] frame the helper produced */
static int wait_frame(unsigned char *out, int outsz, int timeout_ms)
{
	int waited = 0;
	unsigned int len = 0;
	int got = -1;

	while (waited < timeout_ms) {

		EnterCriticalSection(&up_lock);
		if (up_len >= 4) {
			len = ((unsigned int)up_buf[0] << 24) | ((unsigned int)up_buf[1] << 16)
				 | ((unsigned int)up_buf[2] << 8)  | (unsigned int)up_buf[3];

			if ((up_len >= len + 4) && ((int)len <= outsz)) {
				memcpy(out, up_buf + 4, len);
				up_len -= (len + 4);
				if (up_len)
					memmove(up_buf, up_buf + len + 4, up_len);
				got = (int)len;
			}
		}
		LeaveCriticalSection(&up_lock);

		if (got >= 0) return got;

		Sleep(25);
		waited += 25;
	}

	return -1;
}

/**
 * deliver a virtual channel message, split the way the RDP stack splits
 * anything longer than CHANNEL_CHUNK_LENGTH
 */
static void deliver_chunked(const void *payload, UINT32 len)
{
	const unsigned char *p = (const unsigned char *)payload;
	UINT32 off = 0;

	while (off < len) {
		UINT32 n = len - off;
		UINT32 flags = 0;

		if (n > CHANNEL_CHUNK_LENGTH)
			n = CHANNEL_CHUNK_LENGTH;

		if (off == 0)          flags |= CHANNEL_FLAG_FIRST;
		if (off + n >= len)    flags |= CHANNEL_FLAG_LAST;

		plugin_open_event(open_handle, CHANNEL_EVENT_DATA_RECEIVED,
								(LPVOID)(p + off), n, len, flags);
		off += n;
	}
}

/** build [BE len][cmd][id][data] and hand it over, chunked like mstsc */
static void send_msg(unsigned char cmd, unsigned char id,
							const void *data, unsigned int data_len)
{
	static unsigned char buf[8192];
	unsigned int inner = data_len + 2;

	if (inner + 4 > sizeof(buf)) return;

	buf[0] = (unsigned char)(inner >> 24);
	buf[1] = (unsigned char)(inner >> 16);
	buf[2] = (unsigned char)(inner >> 8);
	buf[3] = (unsigned char)inner;
	buf[4] = cmd;
	buf[5] = id;
	if (data_len)
		memcpy(buf + 6, data, data_len);

	deliver_chunked(buf, inner + 4);
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

	{ DWORD tmo = 3000;
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
	HMODULE dll;
	PVIRTUALCHANNELENTRY entry;
	CHANNEL_ENTRY_POINTS ep;
	WSADATA wsa;
	char reply[4096];
	unsigned char frame[8192];
	unsigned char connans[8];
	static char big[3000];
	const char *small = "hello-from-server";
	const char *up = "hello-from-client";
	SOCKET t;
	unsigned char tid;
	int n, i, total;

	if (argc < 2) { printf("usage: %s <rdp2tcp_vc.dll>\n", argv[0]); return 2; }

	setvbuf(stdout, NULL, _IONBF, 0);
	InitializeCriticalSection(&up_lock);
	WSAStartup(MAKEWORD(2,2), &wsa);

	dll = LoadLibraryA(argv[1]);
	if (!dll) { fail("LoadLibrary: %lu", GetLastError()); return 1; }
	ok("loaded %s", argv[1]);

	entry = (PVIRTUALCHANNELENTRY) GetProcAddress(dll, "VirtualChannelEntry");
	if (!entry) { fail("no VirtualChannelEntry export"); return 1; }

	memset(&ep, 0, sizeof(ep));
	ep.cbSize = sizeof(ep);
	ep.protocolVersion = VIRTUAL_CHANNEL_VERSION_WIN2000;
	ep.pVirtualChannelInit  = mock_init;
	ep.pVirtualChannelOpen  = mock_open;
	ep.pVirtualChannelClose = mock_close;
	ep.pVirtualChannelWrite = mock_write;

	if (!entry(&ep)) { fail("VirtualChannelEntry returned FALSE"); return 1; }
	if (!plugin_init_event) { fail("plugin never called pVirtualChannelInit"); return 1; }

	/* --- session up: the plugin should spawn the helper ------------- */
	plugin_init_event(init_handle, CHANNEL_EVENT_CONNECTED, NULL, 0);
	Sleep(1200);

	if (!plugin_open_event) { fail("plugin never opened the channel"); return 1; }

	if (controller_cmd("l\n", reply, sizeof(reply)) > 0)
		ok("helper is up, controller answered");
	else
		{ fail("helper controller did not answer"); return 1; }

	/* --- ping -------------------------------------------------------- */
	send_msg(R2TCMD_PING, 0, NULL, 0);
	Sleep(500);
	ok("delivered PING through the channel");

	/* --- tunnel up --------------------------------------------------- */
	if (controller_cmd("t 127.0.0.1 15901 10.0.0.1 5900\n", reply, sizeof(reply)) <= 0)
		{ fail("tunnel add rejected"); return 1; }

	t = tcp_connect(TUN_PORT);
	if (t == INVALID_SOCKET) { fail("connect to the tunnel port"); return 1; }

	n = wait_frame(frame, sizeof(frame), 3000);
	if ((n < 8) || (frame[0] != R2TCMD_CONN)) {
		fail("expected R2TCMD_CONN up the channel, got %d bytes", n);
		return 1;
	}
	tid = frame[1];
	ok("R2TCMD_CONN came up through pVirtualChannelWrite (id=0x%02x)", tid);

	connans[0] = 0x00; connans[1] = TUNAF_IPV4;
	connans[2] = 0x17; connans[3] = 0x0c;         /* port 5900 */
	connans[4] = 10; connans[5] = 0; connans[6] = 0; connans[7] = 1;
	send_msg(R2TCMD_CONN, tid, connans, sizeof(connans));
	Sleep(500);
	ok("tunnel 0x%02x connected", tid);

	/* --- small payload down ----------------------------------------- */
	send_msg(R2TCMD_DATA, tid, small, (unsigned int)strlen(small));
	n = recv(t, reply, sizeof(reply)-1, 0);
	if ((n > 0) && !strncmp(reply, small, strlen(small)))
		ok("small payload reached the tunnel socket");
	else
		fail("small payload did not arrive (%d)", n);

	/* --- large payload down, split across channel chunks ------------- */
	for (i = 0; i < (int)sizeof(big); ++i)
		big[i] = (char)('A' + (i % 26));

	send_msg(R2TCMD_DATA, tid, big, sizeof(big));

	total = 0;
	while (total < (int)sizeof(big)) {
		n = recv(t, reply, sizeof(reply), 0);
		if (n <= 0) break;
		if (memcmp(reply, big + total, n)) { fail("chunked payload corrupted at %d", total); break; }
		total += n;
	}
	if (total == (int)sizeof(big))
		ok("%d-byte payload survived CHANNEL_CHUNK_LENGTH splitting", total);
	else
		fail("only %d of %d chunked bytes arrived", total, (int)sizeof(big));

	/* --- payload up -------------------------------------------------- */
	send(t, up, (int)strlen(up), 0);
	n = wait_frame(frame, sizeof(frame), 3000);
	if ((n >= 2) && (frame[0] == R2TCMD_DATA) && (frame[1] == tid)
			&& !memcmp(frame+2, up, strlen(up)))
		ok("payload came back up as R2TCMD_DATA");
	else
		fail("expected R2TCMD_DATA up the channel, got %d bytes", n);

	closesocket(t);

	/* --- disconnect -------------------------------------------------- */
	plugin_init_event(init_handle, CHANNEL_EVENT_DISCONNECTED, NULL, 0);
	Sleep(800);

	if (controller_cmd("l\n", reply, sizeof(reply)) > 0)
		fail("helper still running after disconnect");
	else
		ok("helper torn down on disconnect");

	/* --- reconnect: the plugin state must be reusable ---------------- */
	plugin_init_event(init_handle, CHANNEL_EVENT_CONNECTED, NULL, 0);
	Sleep(1200);

	if (controller_cmd("l\n", reply, sizeof(reply)) > 0)
		ok("helper came back up on reconnect");
	else
		fail("helper did not restart on reconnect");

	plugin_init_event(init_handle, CHANNEL_EVENT_DISCONNECTED, NULL, 0);
	Sleep(500);
	plugin_init_event(init_handle, CHANNEL_EVENT_TERMINATED, NULL, 0);
	ok("plugin survived TERMINATED");

	printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
			 failures, failures == 1 ? "" : "s");

	return failures ? 1 : 0;
}
