/**
 * @file print.c
 * debug/info/warn/error messages helpers
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
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "debug.h"
#include "print.h"

#define PRINT_INFO 0
#define PRINT_WARN 1
#define PRINT_ERR  2
#define PRINT_DBG  3
#define PRINT_MAX  4

int info_level = 3;
static FILE *print_fps[PRINT_MAX];

/**
 * optional duplicate of every info/warn/error/debug line, timestamped, to a
 * plain file -- set RDP2TCP_LOGFILE to a path before launching the client
 * or the server. Console output (print_fps[]) is unaffected either way.
 * Exists for the server, which has no equivalent of the client's plugin
 * redirecting its stderr: whatever console window it was launched from is
 * the only record, gone the moment that window scrolls or closes. A file
 * survives, and the timestamp is what makes a freeze like "it worked for a
 * while, then stopped" provable after the fact instead of guessed at.
 */
static FILE *log_fp = NULL;

/* common code {{{  */

/** write one already-formatted line to the log file, if one is open */
static void log_line(const char *prefix, const char *fmt, va_list va)
{
	time_t now;
	struct tm *lt;
	char ts[16];

	if (!log_fp)
		return;

	time(&now);
	lt = localtime(&now);
	if (lt)
		strftime(ts, sizeof(ts), "%H:%M:%S", lt);
	else
		snprintf(ts, sizeof(ts), "??:??:??");

	fprintf(log_fp, "%s ", ts);
	if (prefix)
		fputs(prefix, log_fp);
	vfprintf(log_fp, fmt, va);
	fputc('\n', log_fp);
	fflush(log_fp); /* a freeze leaves nothing buffered unwritten */
}

static void do_print(
					unsigned int fid,
					const char *prefix,
					const char *fmt,
					va_list va)
{
	FILE *fp;
	va_list vc;

	assert(print_fps[fid] && fmt);

	if (log_fp) {
		va_copy(vc, va);
		log_line(prefix, fmt, vc);
		va_end(vc);
	}

	fp = print_fps[fid];
	if (prefix)
		fputs(prefix, fp);
	vfprintf(fp, fmt, va);
	fputc('\n', fp);
}
/* }}} */
/* debug {{{ */
int debug_level = -1;
int tracing_flags = 0;

void __debug(int level, const char *fmt, ...)
{
	va_list va;

	if (level <= debug_level) {
		va_start(va, fmt);
		do_print(PRINT_DBG, "debug: ", fmt, va);
		va_end(va);
	}
}

void __trace(
			const char *file,
			int line,
			const char *func,
			const char *fmt,
			...)
{
	va_list va;

	fprintf(stderr, " %s(", func);
	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	va_end(va);
	fputs(")\n", stderr);
}

/* }}} */
/* info/warn/error API {{{ */
void print_init(void)
{
	const char *path;

#ifdef DEBUG
	char *val;

	val = getenv("DEBUG");
	if (val)
		debug_level = atoi(val);
	val = getenv("TRACE");
	if (val)
		tracing_flags = (int)strtoul(val, NULL, 16);
	print_fps[3] = stderr;
#endif
	print_fps[0] = stderr;
	print_fps[1] = stderr;
	print_fps[2] = stderr;

	path = getenv("RDP2TCP_LOGFILE");
	if (path && *path) {
		log_fp = fopen(path, "a");
		if (!log_fp)
			fprintf(stderr, "warning: failed to open RDP2TCP_LOGFILE '%s'\n", path);
	}
}

/**
 * @brief print information on stdout
 * @param[in] level information verbosity level
 * @param[in] fmt format string
 * @see warn error
 */
void info(int level, const char *fmt, ...)
{
	va_list va;

	assert(fmt);

	if (level <= info_level) {
		va_start(va, fmt);
		do_print(PRINT_INFO, NULL, fmt, va);
		va_end(va);
	}
}

/**
 * @brief print a warning on stderr
 * @param[in] fmt format string
 * @return always -1
 * @see info, error
 */
int warn(const char *fmt, ...)
{
	va_list va;

	assert(fmt);

	va_start(va, fmt);
	do_print(PRINT_WARN, "warn: ", fmt, va);
	va_end(va);

	return -1;
}
/**
 * @brief print an error on stderr
 * @param[in] fmt format string
 * @return always -1
 * @see info, warn
 */
int error(const char *fmt, ...)
{
	va_list va;

	assert(fmt);

	va_start(va, fmt);
	do_print(PRINT_ERR, "error: ", fmt, va);
	va_end(va);

	return -1;
}
/* }}} */

/**
 * print I/O transfer length
 */
void print_xfer(const char *name, char rw, unsigned int size)
{
	info(1, (rw=='r'?"%-6s          < %-8u":"%-6s %8u >"), name, size);
}

#ifdef DEBUG
void fprint_hex(void *data, unsigned int len, FILE *fp)
{
	unsigned int i;
	for (i=0; i<len; ++i)
		fprintf(fp, "%02x", *(((unsigned char *)data)+i));
}
#endif

// vim: ts=3 sw=3 fdm=marker
