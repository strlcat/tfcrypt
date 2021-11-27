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

enum { TFB64_STOP1 = 1, TFB64_STOPF };

void do_edbase64(char **fargv)
{
	struct base64_decodestate dstate;
	struct base64_encodestate estate;
	size_t lread = 0;

	sfd = 0; dfd = 1;

	if (fargv[0]) {
		if (!strcmp(fargv[0], "-")) sfd = 0;
		else {
			sfd = open(fargv[0], O_RDONLY | O_LARGEFILE);
			if (do_preserve_time) if (fstat(sfd, &s_stat) == -1)
				xerror(YES, NO, YES, "stat(%s)", fargv[0]);
		}
		if (sfd == -1) xerror(NO, NO, YES, "%s", fargv[0]);
	}

	if (fargv[0] && fargv[1]) {
		if (!strcmp(fargv[1], "-")) dfd = 1;
		else dfd = open(fargv[1], O_WRONLY | O_CREAT | O_LARGEFILE | write_flags, 0666);
		if (dfd == -1) xerror(NO, NO, YES, "%s", fargv[1]);
	}

	if (do_edcrypt == TFC_DO_ENCRYPT) {
		memset(&estate, 0, sizeof(struct base64_encodestate));
		base64_init_encodestate(&estate);
	}
	else if (do_edcrypt == TFC_DO_DECRYPT) {
		memset(&dstate, 0, sizeof(struct base64_decodestate));
		base64_init_decodestate(&dstate);
	}

	errno = 0;
	do_stop = NO;
	while (1) {
		if (do_stop) break;
		pblk = srcblk;
		lblock = lrem = do_edcrypt == TFC_DO_DECRYPT ? TFC_B64_DWIDTH : TFC_B64_EWIDTH;
		ldone = 0;
		if (error_action == TFC_ERRACT_SYNC) rdpos = tfc_fdgetpos(sfd);
_again:		lio = xread(sfd, pblk, lrem);
		if (lio == 0) do_stop = TFB64_STOP1;
		if (lio != NOSIZE) ldone += lio;
		else {
			if (errno != EIO && catch_all_errors != YES)
				xerror(NO, NO, NO, "%s", fargv[0]);
			switch (error_action) {
				case TFC_ERRACT_CONT: xerror(YES, NO, NO, "%s", fargv[0]); goto _again; break;
				case TFC_ERRACT_SYNC:
				case TFC_ERRACT_LSYNC:
					xerror(YES, NO, NO, "%s", fargv[0]);
					lio = ldone = lrem = lblock;
					memset(srcblk, 0, lio);
					if (rdpos == NOFSIZE) lseek(sfd, lio, SEEK_CUR);
					else lseek(sfd, rdpos + lio, SEEK_SET);
					break;
				default: xerror(NO, NO, NO, "%s", fargv[0]); break;
			}
		}
		if (lio && lio < lrem) {
			pblk += lio;
			lrem -= lio;
			goto _again;
		}

		if (do_edcrypt == TFC_DO_ENCRYPT) {
			estate.count = 0;
			base64_encode_block((const char *)srcblk, ldone, (char *)dstblk, &estate);
			lread = ldone;
			ldone = estate.count;
		}
		else if (do_edcrypt == TFC_DO_DECRYPT) {
			dstate.count = 0;
			base64_decode_block((const char *)srcblk, ldone, (char *)dstblk, sizeof(dstblk), &dstate);
			ldone = dstate.count;
		}

		pblk = dstblk;
		if (ldone == 0) {
			do_stop = TFB64_STOPF;
			break;
		}
		lrem = ldone;
		ldone = 0;
_wagain:	lio = xwrite(dfd, pblk, lrem);
		if (lio != NOSIZE) ldone += lio;
		else xerror(NO, NO, NO, "%s", fargv[1]);
		if (do_edcrypt == TFC_DO_ENCRYPT) {
			size_t t;
			if (lread >= lblock || do_stop == TFB64_STOPF) {
				t = xwrite(dfd, "\n", 1);
				if (t != NOSIZE) lio += t;
				else lio = NOSIZE;
			}
		}
		if (lio != NOSIZE) ldone += lio;
		else xerror(NO, NO, NO, "%s", fargv[1]);
		if (do_fsync && fsync(dfd) == -1) xerror(NO, NO, NO, "%s", fargv[1]);
		if (lio < lrem) {
			pblk += lio;
			lrem -= lio;
			goto _wagain;
		}
	}

	if (do_edcrypt == TFC_DO_ENCRYPT && do_stop == TFB64_STOP1) {
		size_t t = estate.count;
		pblk = dstblk + estate.count;
		base64_encode_blockend((char *)dstblk, &estate);
		lrem = estate.count - t;
		ldone = 0;
		do_stop = TFB64_STOPF;
		goto _wagain;
	}

	memset(&estate, 0, sizeof(struct base64_encodestate));
	memset(&dstate, 0, sizeof(struct base64_decodestate));
	if (do_preserve_time) fcopy_matime(dfd, &s_stat);
	xexit(0);
}

static void base64_eprint(FILE *where, struct base64_encodestate *estate, const char *input, size_t inputl)
{
	static char t[256];
	ssize_t ix = inputl;

	while (ix > 0) {
		memset(t, 0, sizeof(t));
		estate->count = 0;
		base64_encode_block(input, ix > 128 ? 128 : ix, t, estate);
		ix -= 128;
		if (ix < 128) base64_encode_blockend(t, estate);
		fprintf(where, "%s", t);
		fflush(where);
	}

	memset(t, 0, sizeof(t));
}

void tfc_printbase64(FILE *where, const void *p, size_t n, tfc_yesno nl)
{
	struct base64_encodestate estate;
	memset(&estate, 0, sizeof(struct base64_encodestate));
	base64_eprint(where, &estate, (const char *)p, n);
	if (nl) tfc_nfsay(where, "\n");
}
