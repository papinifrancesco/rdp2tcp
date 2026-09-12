/**
 * @file main.c
 * main loop
 * @mainpage rdp2tcp
 * @section sec_ts TS virtual channel
 * @li channel.c
 * @section sec_tun rdp2tcp tunnels
 * @li tunnel.c
 * @li commands.c
 * @li socks5.c
 * @li controller.c
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
#include "r2tcli.h"
#include "w32chan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifndef _WIN32
#include <signal.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#endif

/**
 * default rdp2tcp controller TCP port
 */
#define R2T_PORT   8477

extern struct list_head all_sockets;
static int killme = 0;

void bye(void)
{
	netsock_t *ns, *bak;

	list_for_each_safe(ns, bak, &all_sockets)
		netsock_close(ns);

	channel_kill();
	net_exit();
	exit(0);
}

#ifndef _WIN32
static void handle_cleanup(int sig)
{
	if (sig == SIGPIPE)
		info(0, "rdesktop pipe is broken");
	bye();
}
#else
/**
 * windows has no SIGINT: the console control handler is the equivalent, and
 * SIGPIPE has no analogue either -- a dead channel pipe surfaces as a failed
 * read or write, which channel_read_event() already reports.
 */
static BOOL WINAPI handle_console_ctrl(DWORD type)
{
	switch (type) {
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT:
		case CTRL_CLOSE_EVENT:
		case CTRL_LOGOFF_EVENT:
		case CTRL_SHUTDOWN_EVENT:
			bye();
			return TRUE;
	}

	return FALSE;
}
#endif

static void setup(int argc, char **argv)
{
	const char *host;
	int port;

	print_init();

	if (argc > 3)
		exit(0);

	if (argc == 3) {
		port = atoi(argv[2]);
		if ((port <= 0) || (port > 0xffff)) {
			error("invalid controller port %i", port);
			exit(0);
		}
		host = argv[1];
	} else if (argc == 2) {
		port = R2T_PORT;
		host = argv[1];
	} else {
		port = R2T_PORT;
		host = "127.0.0.1";
	}

	/* no-op on POSIX, WSAStartup() on windows -- must precede any socket */
	net_init();

	if (controller_start(host, port))
		exit(0);

	channel_init();
}

/**
 * react to a virtual channel connect/disconnect
 * @param[in,out] last_state previously observed channel state
 * @return the current channel state
 */
static int sync_channel_state(int *last_state)
{
	int state;

	state = channel_is_connected();

	if (state != *last_state) {

		if (!state) // connected --> disconnected
			tunnels_kill_clients();
		else // disconnected --> connected
			tunnels_restart();

		*last_state = state;
	}

	return state;
}

/**
 * dispatch a ready network socket
 * @param[in] ns the socket
 * @param[in] can_read 1 if the socket is readable
 * @param[in] can_write 1 if the socket is writable
 * @return -1 if the socket must be closed
 */
static int netsock_dispatch(netsock_t *ns, int can_read, int can_write)
{
	int ret = 0;

	if (netsock_is_server(ns)) {

		if (can_read) {
			if (ns->type == NETSOCK_TUNSRV)
				tunnel_accept_event(ns);
			else if (ns->type == NETSOCK_S5SRV)
				socks5_accept_event(ns);
			else
				controller_accept_event(ns);
		}

		return 0;
	}

	if (can_write)
		ret = tunnel_write_event(ns);

	if ((ret >= 0) && can_read) {

		if (ns->type == NETSOCK_S5CLI)
			ret = socks5_read_event(ns);
		else if (ns->type == NETSOCK_CTRLCLI)
			ret = controller_read_event(ns);
		else
			ret = channel_forward_recv(ns);
	}

	return ret;
}

#ifdef _WIN32

/**
 * build the winsock event filter matching what the main loop wants to know
 * about a socket
 */
static long netsock_evt_mask(netsock_t *ns)
{
	long mask = FD_CLOSE;

	if (netsock_want_read(ns))
		mask |= FD_READ | FD_ACCEPT;

	if (netsock_want_write(ns))
		mask |= FD_WRITE | FD_CONNECT;

	return mask;
}

/**
 * windows main loop
 *
 * Structurally the same as the server's (see server/events.c): everything
 * waitable is a HANDLE and WaitForMultipleObjects() replaces select().
 * Sockets contribute the WSAEVENT that common/nethelper.c already keeps in
 * sock_t; the virtual channel contributes the two events signalled by the
 * pipe bridge threads in w32chan.c.
 */
static void mainloop(void)
{
	HANDLE handles[MAXIMUM_WAIT_OBJECTS];
	netsock_t *ns, *bak;
	WSANETWORKEVENTS nev;
	DWORD ret;
	unsigned int n;
	int last_state, state, rd, wr, warned = 0;

	last_state = 0;

	while (!killme) {

		state = sync_channel_state(&last_state);

		n = 0;
		handles[n++] = channel_read_evt();

		if (state && channel_want_write())
			handles[n++] = channel_write_evt();

		list_for_each(ns, &all_sockets) {

			assert(valid_netsock(ns));

			if ((ns->state == NETSTATE_CANCELLED) || netsock_is_sockless(ns))
				continue;

			if (n >= MAXIMUM_WAIT_OBJECTS) {
				if (!warned) {
					warned = 1;
					error("more than %i concurrent sockets, some will stall",
							MAXIMUM_WAIT_OBJECTS);
				}
				break;
			}

			WSAEventSelect(ns->sock.fd, ns->sock.evt, netsock_evt_mask(ns));
			handles[n++] = (HANDLE) ns->sock.evt;
		}

		ret = WaitForMultipleObjects(n, handles, FALSE,
											  state ? 1000 : INFINITE);

		if (ret == WAIT_FAILED) {
			error("WaitForMultipleObjects error (%s)",
					net_syserror(GetLastError()));
			break;
		}

		if (ret == WAIT_TIMEOUT)
			continue;

		if (state && channel_want_write() && w32chan_can_write())
			channel_write_event();

		/* the read event stays signalled while the bridge holds buffered
		 * bytes, so one message per pass is enough -- we are woken again
		 * immediately if more remain */
		if (WaitForSingleObject(channel_read_evt(), 0) == WAIT_OBJECT_0) {
			if (channel_read_event() < 0)
				break;
		}

		list_for_each_safe(ns, bak, &all_sockets) {

			assert(valid_netsock(ns));

			if (ns->state == NETSTATE_CANCELLED) {
				debug(0, "closing cancelled connection");
				netsock_close(ns);
				continue;
			}

			if (netsock_is_sockless(ns))
				continue;

			if (WSAEnumNetworkEvents(ns->sock.fd, ns->sock.evt, &nev))
				continue;

			rd = (nev.lNetworkEvents & (FD_READ|FD_ACCEPT|FD_CLOSE)) != 0;
			wr = (nev.lNetworkEvents & (FD_WRITE|FD_CONNECT)) != 0;

			if ((rd || wr) && (netsock_dispatch(ns, rd, wr) < 0))
				netsock_close(ns);
		}
	}
}

#else

/**
 * POSIX main loop
 */
static void mainloop(void)
{
	int ret, fd, max_fd, last_state, state;
	netsock_t *ns, *bak;
	fd_set rfd, wfd, *pwfd;
	struct timeval tv, *ptv;

	last_state = 0;

	while (!killme) {

		FD_ZERO(&rfd);
		FD_SET(RDP_FD_IN, &rfd);
		max_fd = RDP_FD_IN;

		FD_ZERO(&wfd);
		pwfd = NULL;
		ptv = NULL;

		state = sync_channel_state(&last_state);

		if (state) {
			// channel is connected
			if (channel_want_write()) {
				FD_SET(RDP_FD_OUT, &wfd);
				max_fd = RDP_FD_OUT;
				pwfd = &wfd;
			}
			tv.tv_sec  = 1;
			tv.tv_usec = 0;
			ptv = &tv;
		}

		list_for_each(ns, &all_sockets) {

			assert(valid_netsock(ns));

			if (ns->state != NETSTATE_CANCELLED) {
				fd = ns->sock;

				if (netsock_want_read(ns)) {
					FD_SET(fd, &rfd);
					if (fd > max_fd) max_fd = fd;
				}

				if (netsock_want_write(ns)) {
					FD_SET(fd, &wfd);
					pwfd = &wfd;
					if (fd > max_fd) max_fd = fd;
				}
			}
		}

		ret = select(max_fd+1, &rfd, pwfd, NULL, ptv);
		if (ret == -1) {
			error("select error (%s)", strerror(errno));
			break;
		}

		if (ret == 0) {
			// channel ping timeout
			continue;
		}

		if (FD_ISSET(RDP_FD_OUT, &wfd))
			channel_write_event();

		if (FD_ISSET(RDP_FD_IN, &rfd)) {
			if (channel_read_event() < 0)
				break;
		}

		list_for_each_safe(ns, bak, &all_sockets) {

			assert(valid_netsock(ns));

			if (ns->state == NETSTATE_CANCELLED) {
				debug(0, "closing cancelled connection");
				netsock_close(ns);
				continue;
			}

			if (netsock_is_sockless(ns))
				continue;

			fd = ns->sock;

			if (netsock_dispatch(ns, FD_ISSET(fd, &rfd),
										FD_ISSET(fd, &wfd)) < 0)
				netsock_close(ns);
		}
	}
}

#endif

int main(int argc, char **argv)
{
	setup(argc, argv);

#ifndef _WIN32
	signal(SIGUSR1, handle_cleanup);
	signal(SIGINT, handle_cleanup);
	signal(SIGPIPE, handle_cleanup);
#else
	SetConsoleCtrlHandler(handle_console_ctrl, TRUE);
#endif

	mainloop();

	bye();
	return 0;
}
