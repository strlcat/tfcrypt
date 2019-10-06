/*
 * tfcrypt -- high security Threefish encryption tool.
 *
 * tfcrypt is copyrighted:
 * Copyright (C) 2012-2019 Andrey Rys. All rights reserved.
 *
 * tfcrypt is licensed to you under the terms of std. MIT/X11 license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "tfcrypt.h"

size_t blk_len_adj(tfc_fsize filelen, tfc_fsize read_already, size_t blklen)
{
	if (filelen == NOFSIZE) return blklen;
	return ((filelen - read_already) >= blklen) ? blklen : (filelen - read_already);
}

tfc_yesno xor_shrink(void *dst, size_t szdst, const void *src, size_t szsrc)
{
	unsigned char *udst = dst;
	const unsigned char *usrc = src;
	size_t x, y;

	if ((szsrc % szdst) != 0) return NO;
	if (szdst >= szsrc) {
		if (szdst == szsrc) {
			memmove(dst, src, szsrc);
			return YES;
		}
		return NO;
	}

	memset(dst, 0, szdst);
	for (x = 0; x < (szsrc / szdst); x++) {
		for (y = 0; y < szdst; y++) udst[y] ^= usrc[(x*szdst)+y];
	}

	return YES;
}

tfc_yesno str_empty(const char *str)
{
	if (!*str) return YES;
	return NO;
}

void xclose(int fd)
{
	if (fd < 3) return;
	if (close(fd) == -1) xerror(YES, NO, NO, "close(%d)", fd);
}

const char *tfc_modename(int mode)
{
	switch (mode) {
		case TFC_MODE_CTR: return "CTR";
		case TFC_MODE_STREAM: return "STREAM";
		case TFC_MODE_XTS: return "XTS";
		case TFC_MODE_ECB: return "ECB";
		case TFC_MODE_CBC: return "CBC";
		case TFC_MODE_OCB: return "OCB";
	}

	return NULL;
}

void tfc_getcurtime(tfc_useconds *tx)
{
	struct timeval t;
	memset(&t, 0, sizeof(t));

	gettimeofday(&t, NULL);
	*tx = t.tv_sec * 1000000 + t.tv_usec;

	memset(&t, 0, sizeof(t));
}

char *tfc_format_time(tfc_useconds t)
{
	tfc_useconds secs, dsecs;
	unsigned days, hours, minutes, seconds;
	static char r[128];

	secs = (tfc_useconds)TFC_UTODSECS(t);
	dsecs = (tfc_useconds)(t - (secs * 1000000));

	days = secs / 86400;
	hours = (secs / 3600) % 24;
	minutes = (secs / 60) % 60;
	seconds = secs % 60;

	if (days > 0) sprintf(r, "%ud,%02u:%02u:%02u.%03u", days, hours, minutes, seconds, (unsigned)(dsecs / 1000));
	else if (hours > 0) sprintf(r, "%02u:%02u:%02u.%03u", hours, minutes, seconds, (unsigned)(dsecs / 1000));
	else if (minutes > 0) sprintf(r, "%02u:%02u.%03u", minutes, seconds, (unsigned)(dsecs / 1000));
	else sprintf(r, "%02u.%03u", seconds, (unsigned)(dsecs / 1000));

	return r;
}

tfc_fsize tfc_fdsize(int fd)
{
	off_t l, cur;

	cur = lseek(fd, 0L, SEEK_CUR);
	l = lseek(fd, 0L, SEEK_SET);
	if (l == -1) return NOFSIZE;
	l = lseek(fd, 0L, SEEK_END);
	if (l == -1) return NOFSIZE;
	lseek(fd, cur, SEEK_SET);

	return (tfc_fsize)l;
}

tfc_fsize tfc_fdgetpos(int fd)
{
	off_t t;

	t = lseek(fd, 0L, SEEK_CUR);
	if (t == -1) return NOFSIZE;
	return (tfc_fsize)t;
}

tfc_fsize tfc_fnamesize(char *fname, tfc_yesno noexit)
{
	int fnmfd;
	tfc_fsize ret;
	char *s, T[2];

	if (!fname) return 0;

	s = strchr(fname, ':');
	if (s && s[1] && (s[1] == '+' || s[1] == '-' || s[1] == '*' || s[1] == '/')) {
		memcpy(T, s, 2);
		memset(s, 0, 2);
	}

	fnmfd = open(fname, O_RDONLY);
	if (s) memcpy(s, T, 2);
	if (fnmfd == -1) {
		xerror(noexit, NO, YES, "%s", fname);
		return NOFSIZE;
	}
	ret = tfc_fdsize(fnmfd);
	if (ret == NOFSIZE) {
		xerror(noexit, NO, YES, "%s: not a seekable file", fname);
		return ret;
	}
	xclose(fnmfd);

	return ret;
}

tfc_fsize tfc_modifysize(tfc_fsize szmodify, const char *szspec)
{
	tfc_fsize t;
	const char *s;
	char *stoi, c;

	if (szmodify == NOFSIZE) return NOFSIZE;
	if (!szspec) return szmodify;
	s = szspec;

	if (*s != ':') return szmodify;
	s++;
	if (!(*s == '+' || *s == '-' || *s == '*' || *s == '/')) return szmodify;
	c = *s;
	s++;
	if (strchr(s, '/') || strchr(s, '.')) return szmodify;

	t = tfc_humanfsize(s, &stoi);
	if (!str_empty(stoi)) return szmodify;

	switch (c) {
		case '+': szmodify += t; break;
		case '-': szmodify -= t; break;
		case '*': szmodify *= t; break;
		case '/': szmodify /= t; break;
		default: break;
	}

	return szmodify;
}

void fcopy_matime(int fd, const struct stat *st)
{
	struct timeval times[2];

	times[1].tv_sec = times[0].tv_sec = st->st_mtime;
	times[1].tv_usec = times[0].tv_usec = 0;
	if (futimes(fd, times) == -1) xerror(YES, NO, YES, "futimes(%d)", fd);
}

static void char_to_nul(char *s, size_t l, int c)
{
	while (*s && l) { if (*s == c) { *s = 0; break; } s++; l--; }
}

tfc_yesno xfgets(char *s, size_t n, FILE *f)
{
	memset(s, 0, n);

	if (fgets(s, (int)n, f) == s) {
		char_to_nul(s, n, '\n');
		return YES;
	}

	return NO;
}

tfc_yesno isbase64(const char *s)
{
	while (*s) {
		if (*s >= 'g' && *s <= 'z') return YES;
		if (*s >= 'G' && *s <= 'Z') return YES;
		if (*s == '+' || *s == '/' || *s == '=') return YES;
		s++;
	}
	return NO;
}

static int chrbin(char x)
{
	if (x >= '0' && x <= '9')
		return x - '0';
	if (x >= 'A' && x <= 'F')
		return x - 'A' + 10;
	if (x >= 'a' && x <= 'f')
		return x - 'a' + 10;
	return 0;
}

void hex2bin(void *d, const char *s)
{
	const char *S = s;
	char *D = d;
	int x = 0;

	while (*s) {
		if ((s-S) % 2) {
			x = (x << 4) ^ chrbin(*s);
			*D = x; D++;
		}
		else x = chrbin(*s);
		s++;
	}
}
