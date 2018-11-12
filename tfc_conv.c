/*
 * tfcrypt -- high security Threefish encryption tool.
 *
 * tfcrypt is copyrighted:
 * Copyright (C) 2012-2018 Andrey Rys. All rights reserved.
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

static const char *tfc_size_scale[] = {"B", "K", "M", "G", "T", "P"};

void tfc_data_to_words64(void *data, size_t szdata)
{
#ifndef TF_NO_ENDIAN
	size_t idx;
	uint64_t *d = data;
	uint64_t t;

	for (idx = 0; idx < (szdata/sizeof(uint64_t)); idx++) {
#ifdef TF_BIG_ENDIAN
		t = htobe64(d[idx]);
#else
		t = htole64(d[idx]);
#endif
		d[idx] = t;
	}
#endif
}

static tfc_yesno tfc_is_number(const char *s)
{
	char *p;
	if (!s || str_empty(s)) return NO;
	strtol(s, &p, 10);
	return str_empty(p) ? YES : NO;
}

tfc_fsize tfc_humanfsize(const char *s, char **stoi)
{
	char pfx[2], T[2], N[48], *ss;
	int base = 10;
	size_t l;
	tfc_fsize gbgib = 0, ret = 0;

	if (!s) return 0;

	memset(N, 0, sizeof(N));
	memset(pfx, 0, sizeof(pfx));
	memset(T, 0, sizeof(T));

	if (!strncmp(s, "0x", 2)) {
		s += 2;
		base = 16;
	}
	else if (s[0] == '0') base = 0;

	l = strnlen(s, sizeof(N)-1);
	memcpy(N, s, l);

	ss = strchr(N, ':');
	if (ss && ss[1] && (ss[1] == '+' || ss[1] == '-' || ss[1] == '*' || ss[1] == '/')) {
		ss[0] = 0;
		l = strnlen(N, sizeof(N)-1);
	}

	if (base == 16) goto _nopfx;

	pfx[0] = N[l-1];
	if (tfc_is_number(pfx) == NO) N[l-1] = 0;

_nopfx:
	*stoi = NULL;
	if (tfc_is_number(pfx) || pfx[0] == 'B' || pfx[0] == 'c') ret = strtoull(N, stoi, base);
	else if (pfx[0] == 'W') ret = strtoull(N, stoi, base)*2;
	else if (pfx[0] == 'I') ret = strtoull(N, stoi, base)*4;
	else if (pfx[0] == 'L') ret = strtoull(N, stoi, base)*8;
	else if (pfx[0] == 'e') ret = strtoull(N, stoi, base)*TF_BLOCK_SIZE;
	else if (pfx[0] == 'y') ret = strtoull(N, stoi, base)*TF_FROM_BITS(TFC_KEY_BITS);
	else if (pfx[0] == 'x') ret = strtoull(N, stoi, base)*TF_FROM_BITS(TFC_KEY_BITS)*2;
	else if (pfx[0] == 'E') ret = strtoull(N, stoi, base)*blksize;
	else if (pfx[0] == 'b' || pfx[0] == 's') ret = strtoull(N, stoi, base)*512;
	else if (pfx[0] == 'p' || pfx[0] == 'S') ret = strtoull(N, stoi, base)*4096;
	else if (pfx[0] == 'k' || pfx[0] == 'K') {
		gbgib = do_stats_in_gibs == YES ? 1000 : 1024;
	}
	else if (pfx[0] == 'm' || pfx[0] == 'M') {
		gbgib = do_stats_in_gibs == YES ? 1000 * 1000 : 1024 * 1024;
	}
	else if (pfx[0] == 'g' || pfx[0] == 'G') {
		gbgib = do_stats_in_gibs == YES ? 1000 * 1000 * 1000 : 1024 * 1024 * 1024;
	}
	else if (pfx[0] == 'T') {
		gbgib = do_stats_in_gibs == YES ? 1000000000000ULL : 1099511627776ULL;
	}
	else if (pfx[0] == 'P') {
		gbgib = do_stats_in_gibs == YES ? 1000000000000000ULL : 1125899906842624ULL;
	}
	else ret = strtoull(N, stoi, base);
	if (gbgib) ret = strtoull(N, stoi, base) * gbgib;

	return ret;
}

const char *tfc_getscale(int scale)
{
	return scale >= TFC_ARRAY_SIZE(tfc_size_scale) ?
		tfc_size_scale[TFC_ARRAY_SIZE(tfc_size_scale)-1] : tfc_size_scale[scale];
}

void tfc_describescale(tfc_fsize num, double *w, int *scale)
{
	tfc_fsize gbgib = (do_stats_in_gibs == YES) ? 1000 : 1024;

	if (num <= gbgib) {
		*w = num;
		*scale = 0;
	}
	else if ((num > gbgib)
		&& (num <= gbgib * gbgib)) {
		*w = (double)num / gbgib;
		*scale = 1;
	}
	else if ((num > gbgib * gbgib)
		&& (num <= gbgib * gbgib * gbgib)) {
		*w = (double)num / (gbgib * gbgib);
		*scale = 2;
	}
	else if ((num > gbgib * gbgib * gbgib)
		&& (num <= gbgib * gbgib * gbgib * gbgib)) {
		*w = (double)num / (gbgib * gbgib * gbgib);
		*scale = 3;
	}
	else if ((num > gbgib * gbgib * gbgib * gbgib)
		&& num <= gbgib * gbgib * gbgib * gbgib * gbgib) {
		*w = (double)num/ (gbgib * gbgib * gbgib * gbgib);
		*scale = 4;
	}
	else {
		*w = (double)num / (gbgib * gbgib * gbgib * gbgib * gbgib);
		*scale = 5;
	}
}
