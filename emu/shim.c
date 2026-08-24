/*
 * zteshim — the six symbols zte_icg_agg needs that are not in libc.
 *
 * The real binary is dynamically linked against fifteen libraries, most of them
 * ZTE proprietary, but it only actually *imports* six non-libc symbols. Five of
 * those are logging and one pair is a uci get/set. So instead of assembling a
 * full OpenWrt userland we stand in for the lot with this, and every other
 * DT_NEEDED entry is satisfied by a symlink to this same file: the musl loader
 * resolves by filename, and it does not care that libsqlite3.so.0 happens to
 * contain a logging shim it never calls.
 *
 * Signatures were read off the call sites in the binary, not guessed:
 *
 *   dzlog(file, filelen, func, funclen, line, level, fmt, ...)
 *       zlog's real prototype. Verified against dozens of call sites: x0/x1 are
 *       a __FILE__ and its strlen, x2/x3 a __func__ and its strlen, x4 the
 *       line, w5 a level, x6 the format, varargs from x7 on.
 *   libzte_router_uci_get(key, buf, buflen)     at 0x11670
 *   libzte_router_uci_set(key, value)           at 0x116f8
 *   zte_key_syslog_append(a, b, file, line, fmt, ...)   at 0x14694
 */
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UCI_STORE_ENV "ZTESHIM_UCI"
#define UCI_STORE_DEFAULT "/etc/zteshim/uci.conf"

static const char *uci_store(void)
{
	const char *p = getenv(UCI_STORE_ENV);
	return (p && *p) ? p : UCI_STORE_DEFAULT;
}

/* zlog levels, so output looks like the device's own /logfs log. */
static const char *level_name(int level)
{
	switch (level) {
	case 20:  return "DEBUG";
	case 40:  return "INFO";
	case 60:  return "NOTICE";
	case 80:  return "WARN";
	case 100: return "ERROR";
	case 120: return "FATAL";
	default:  break;
	}
	/* The binary passes 0x28/0x3c/0x64/0x78 constants; print the number when
	 * it is not one we recognise rather than pretending. */
	return "LOG";
}

int dzlog_init(const char *confpath, const char *category)
{
	fprintf(stderr, "[shim] dzlog_init(conf=%s, category=%s)\n",
		confpath ? confpath : "(null)", category ? category : "(null)");
	setvbuf(stderr, NULL, _IOLBF, 0);
	return 0;
}

void dzlog(const char *file, size_t filelen, const char *func, size_t funclen,
	   long line, int level, const char *fmt, ...)
{
	char msg[4096];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof msg, fmt, ap);
	va_end(ap);

	/* file/func are not NUL-terminated in every call, hence the lengths. */
	fprintf(stderr, "[%s] %.*s:%ld %.*s() %s\n",
		level_name(level),
		(int)filelen, file ? file : "?", line,
		(int)funclen, func ? func : "?", msg);
}

int zlog_fini(void)
{
	fflush(stderr);
	return 0;
}

void zte_key_syslog_append(int a, int b, const char *file, int line,
			   const char *fmt, ...)
{
	char msg[2048];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof msg, fmt, ap);
	va_end(ap);
	fprintf(stderr, "[KEYLOG] %s:%d (%d,%d) %s\n",
		file ? file : "?", line, a, b, msg);
}

/*
 * uci, backed by a flat key=value file so it can be changed without rebuilding.
 * Returns 0 on success; the binary treats non-zero as "not set".
 */
int libzte_router_uci_get(const char *key, char *buf, size_t buflen)
{
	FILE *f;
	char line[1024];
	size_t klen;
	int rc = -1;

	if (!key || !buf || buflen == 0)
		return -1;
	buf[0] = '\0';
	klen = strlen(key);

	f = fopen(uci_store(), "r");
	if (!f) {
		fprintf(stderr, "[shim] uci_get(%s): no store at %s\n", key, uci_store());
		return -1;
	}
	while (fgets(line, sizeof line, f)) {
		char *nl = strpbrk(line, "\r\n");
		if (nl)
			*nl = '\0';
		if (line[0] == '#' || line[0] == '\0')
			continue;
		if (strncmp(line, key, klen) == 0 && line[klen] == '=') {
			snprintf(buf, buflen, "%s", line + klen + 1);
			rc = 0;
			break;
		}
	}
	fclose(f);
	fprintf(stderr, "[shim] uci_get(%s) -> %s%s\n", key,
		rc == 0 ? buf : "", rc == 0 ? "" : "(unset)");
	return rc;
}

int libzte_router_uci_set(const char *key, const char *value)
{
	/*
	 * Append rather than rewrite: uci_get takes the first match, so the
	 * store keeps its configured value and we still get a record of what
	 * the binary tried to set. That is exactly what we want to observe —
	 * icg_agg_status going to 1 is how the device says the handshake
	 * succeeded.
	 */
	FILE *f = fopen(uci_store(), "a");
	fprintf(stderr, "[shim] uci_set(%s = %s)\n", key ? key : "?",
		value ? value : "?");
	if (!f)
		return -1;
	fprintf(f, "# set-by-agg %s=%s\n", key ? key : "?", value ? value : "?");
	fclose(f);
	return 0;
}
