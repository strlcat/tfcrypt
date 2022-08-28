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

void read_defaults(const char *path, tfc_yesno noerr)
{
	static char ln[4096];
	char *s, *d, *t, *stoi;
	FILE *f;
	tfc_yesno valid = NO;

	f = fopen(path, "r");
	if (!f) {
		if (noerr == YES) return;
		xerror(NO, NO, YES, "%s", path);
	}

	while (1) {
		memset(ln, 0, sizeof(ln));
		if (xfgets(ln, sizeof(ln), f) != YES) break;

		if (valid == NO) {
			if (!strcmp(ln, "# tfcrypt.defs")) valid = YES;
			continue;
		}

		if (str_empty(ln) || ln[0] == '#') continue;

		s = ln;
		d = strchr(s, '=');
		if (!d) continue;
		*d = 0; d++;

		/* yay! GOTO hell! You'll "like" it! */
_spc1:		t = strchr(s, ' ');
		if (!t) goto _spc2;
		*t = 0; goto _spc1;
_spc2:		t = strchr(d, ' ');
		if (!t) goto _nspc;
		*t = 0; d = t+1; goto _spc2;
_nspc:
		if (!strcmp(s, "nr_turns")) {
			nr_turns = strtoul(d, &stoi, 10);
			if (!str_empty(stoi)) xerror(NO, YES, YES, "[%s] nr_turns=%s: invalid number of turns", path, d);
		}
		else if (!strcmp(s, "ctr_mode")) {
			if (!strcasecmp(d, "ctr"))
				ctr_mode = TFC_MODE_CTR;
			else if (!strcasecmp(d, "stream"))
				ctr_mode = TFC_MODE_STREAM;
			else if (!strcasecmp(d, "cbc"))
				ctr_mode = TFC_MODE_CBC;
			else if (!strcasecmp(d, "pcbc"))
				ctr_mode = TFC_MODE_PCBC;
			else if (!strcasecmp(d, "ecb"))
				ctr_mode = TFC_MODE_ECB;
			else if (!strcasecmp(d, "xts"))
				ctr_mode = TFC_MODE_XTS;
			else xerror(NO, YES, YES, "[%s] ctr_mode=%s: invalid mode of operation", path, d);
		}
		else if (!strcmp(s, "tfc_salt")) {
			memset(tfc_salt, 0, TFC_MAX_SALT);
			tfc_saltsz = base64_decode((char *)tfc_salt, TFC_MAX_SALT, d, strlen(d));
		}
		else if (!strcmp(s, "macbits")) {
			macbits = strtoul(d, &stoi, 10);
			if (macbits == 0 || !str_empty(stoi) || macbits < 8
			|| macbits > TF_MAX_BITS || macbits % 8)
				xerror(NO, YES, YES, "[%s] macbits=%s: invalid MAC bits setting", path, d);
		}
		else if (!strcmp(s, "do_full_key")) {
			if (!strcasecmp(d, "yes")) do_full_key = YES;
			else if (!strcasecmp(d, "no")) do_full_key = NO;
		}
		else xerror(NO, YES, YES, "[%s] %s: unknown keyword", path, s);
	}

	memset(ln, 0, sizeof(ln));
	fclose(f);
}

void hash_defaults(char *uhash, size_t szuhash)
{
	struct skein sk;
	char shash[56];
	const char *mode;
	tfc_byte hash[TF_FROM_BITS(256)];

	skein_init(&sk, 256);

	skein_update(&sk, tfc_salt, tfc_saltsz);

	memset(shash, 0, sizeof(shash));
	sprintf(shash, "%zu", nr_turns);
	skein_update(&sk, shash, strlen(shash));

	mode = tfc_modename(ctr_mode);
	skein_update(&sk, mode, strlen(mode));

	memset(shash, 0, sizeof(shash));
	sprintf(shash, "%zu", macbits);
	skein_update(&sk, shash, strlen(shash));

	skein_update(&sk, do_full_key ? "1" : "0", 1);

	skein_final(hash, &sk);
	memset(shash, 0, sizeof(shash));
	base64_encode(shash, (const char *)hash, sizeof(hash));
	memset(hash, 0, sizeof(hash));

	xstrlcpy(uhash, shash, szuhash);
}
