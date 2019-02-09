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
#include "tfcore.h"

void skein(void *hash, size_t bits, const void *key, const void *data, size_t szdata)
{
	struct skein sk;

	if (key) skein_init_key(&sk, key, bits);
	else skein_init(&sk, bits);
	skein_update(&sk, data, szdata);
	skein_final(hash, &sk);
}

void tf_key_tweak_compat(void *key)
{
	TF_UNIT_TYPE *ukey = key, c = THREEFISH_CONST;
	size_t x;

	for (x = 0; x < TF_NR_BLOCK_UNITS; x++) c ^= ukey[x];
	ukey[x] = c;
	ukey[TF_TWEAK_WORD3] = ukey[TF_TWEAK_WORD1] ^ ukey[TF_TWEAK_WORD2];
}

tfc_yesno skeinfd(void *hash, size_t bits, const void *key, int fd, tfc_fsize offset, tfc_fsize readto)
{
	static tfc_byte skblk[TFC_BLKSIZE];

	struct skein sk;
	tfc_byte *pblk;
	size_t ldone, lblock, lrem, lio;
	tfc_fsize total = 0;
	tfc_yesno stop;

	if (ctr_mode == TFC_MODE_SKSUM) total_processed_src = total_processed_dst = delta_processed = 0;

	if (fd == -1) goto _fail;
	if (fd > 2) {
		if (readto == NOFSIZE) {
			readto = tfc_fdsize(fd);
			if (readto == NOFSIZE) goto _fail;
		}
		if (offset != 0 && offset != NOFSIZE) {
			if (lseek(fd, (off_t)offset, SEEK_SET) == -1) {
				if (ignore_seek_errors == NO) goto _fail;
			}
		}
	}

	if (key) skein_init_key(&sk, key, bits);
	else skein_init(&sk, bits);

	errno = 0;
	stop = NO;
	while (1) {
		if (stop) break;
		pblk = skblk;
		lblock = lrem = blk_len_adj(readto, total, TFC_BLKSIZE);
		ldone = 0;
		if (error_action == TFC_ERRACT_SYNC) rdpos = tfc_fdgetpos(fd);
_again:		lio = xread(fd, pblk, lrem);
		if (lio == 0) stop = YES;
		if (lio != NOSIZE) ldone += lio;
		else {
			if (errno != EIO && catch_all_errors != YES) goto _fail;
			switch (error_action) {
				case TFC_ERRACT_CONT: xerror(YES, NO, NO, "skeinfd: %d", fd); goto _again; break;
				case TFC_ERRACT_SYNC:
				case TFC_ERRACT_LSYNC:
					xerror(YES, NO, NO, "skeinfd: %d", fd);
					lio = lrem = ldone = lblock;
					total += lio;
					memset(skblk, 0, lio);
					if (rdpos == NOFSIZE) lseek(fd, lio, SEEK_CUR);
					else lseek(fd, rdpos + lio, SEEK_SET);
					break;
				default: goto _fail; break;
			}
		}
		if (lio && lio < lrem) {
			pblk += lio;
			lrem -= lio;
			goto _again;
		}
		total += ldone;
		if (ctr_mode == TFC_MODE_SKSUM) {
			total_processed_src = total_processed_dst = total;
			delta_processed += ldone;
		}
		skein_update(&sk, skblk, ldone);
		if (readto != NOFSIZE && total >= readto) break;
	}

	if (fd > 2) lseek(fd, (off_t)readto, SEEK_SET);

	skein_final(hash, &sk);
	if (ctr_mode == TFC_MODE_SKSUM) {
		if (verbose || status_timer) print_crypt_status(-1);
		total_processed_src = total_processed_dst = delta_processed = 0;
	}
	memset(skblk, 0, TFC_BLKSIZE);
	return YES;

_fail:
	memset(&sk, 0, sizeof(struct skein));
	memset(hash, 0, SKEIN_DIGEST_SIZE);
	memset(skblk, 0, TFC_BLKSIZE);
	return NO;
}

void do_sksum(char *spec, char **fargv)
{
	static char sksblk[TFC_BLKSIZE / 2], tmp[TFC_TMPSIZE];
	tfc_byte hash[SKEIN_DIGEST_SIZE];
	int fd = -1;
	int x = 0, xx;
	size_t bits;

	if (macbits < TF_MAX_BITS) {
		bits = macbits;
		goto _dothat;
	}

	if (!strcmp(spec, "sksum")) {
		bits = TF_MAX_BITS;
		goto _dothat;
	}

	if ((sscanf(spec, "sk%zusum", &bits) < 1)) {
		bits = TF_MAX_BITS;
	}

	if (bits < 8 || bits > TF_MAX_BITS) {
		xerror(NO, YES, YES,
		"%u: invalid bits number specified!\n"
		"tfcrypt supports from 8 to %u bits, divisible by 8.",
		bits, TFC_U(TF_MAX_BITS));
	}

	if (!bits || bits % 8) {
		xerror(NO, YES, YES,
		"%u: invalid bits number specified!\n"
		"Number of bits must start from 8 and be divisible by 8.",
		bits, TFC_U(TF_MAX_BITS));
	}

_dothat:
	do_edcrypt = TFC_DO_PLAIN;
	ctr_mode = TFC_MODE_SKSUM;

	for (x = 1; x < NSIG; x++) signal(x, SIG_IGN);
	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_flags = SA_RESTART;
	sigact.sa_handler = print_crypt_status;
	sigaction(SIGUSR1, &sigact, NULL);
	sigaction(SIGTSTP, &sigact, NULL);
	sigaction(SIGALRM, &sigact, NULL);
	sigact.sa_handler = change_status_width;
	sigaction(SIGQUIT, &sigact, NULL);
	sigact.sa_handler = change_status_timer;
	sigaction(SIGUSR2, &sigact, NULL);
	sigact.sa_handler = exit_sigterm;
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);
	memset(&sigact, 0, sizeof(struct sigaction));

	tfc_getcurtime(&delta_time);

	if (sksum_hashlist_file) {
		FILE *f;
		char *s, *d, *t, *shash, *fname;
		int failed = 0, totaltested = 0;

		if (!strcmp(sksum_hashlist_file, "-")) f = stdin;
		else f = fopen(sksum_hashlist_file, "r");
		if (!f) xerror(NO, NO, YES, "%s", sksum_hashlist_file);

		while (1) {
			memset(sksblk, 0, sizeof(sksblk));
			x = xfgets(sksblk, sizeof(sksblk), f);
			if (x == 0) break;

			s = d = sksblk; t = NULL;
			shash = fname = NULL;
			while ((s = strtok_r(d, "\t", &t))) {
				if (d) d = NULL;

				if (!shash) shash = s;
				else if (shash && !fname) fname = s;
			}

			if (!shash || !fname) {
				xerror(YES, NO, YES, "invalid string %s", sksblk);
				exitcode = 2;
				continue;
			}

			s = strchr(shash, ' ');
			if (s && s[1] == ' ') *s = 0;

			fd = open(fname, O_RDONLY | O_LARGEFILE);
			if (fd == -1) {
				xerror(YES, NO, YES, "%s", fname);
				exitcode = 1;
				continue;
			}

			if (status_timer) setup_next_alarm(status_timer);
			if (skeinfd(hash, bits, mackey_opt ? mackey : NULL, fd, iseek, maxlen) != YES) {
				xerror(YES, NO, YES, "%s", fname);
				exitcode = 1;
				continue;
			}
			xclose(fd);
			if (sksum_turns > 1) {
				size_t y;
				for (y = 0; y < sksum_turns; y++)
					skein(hash, bits, mackey_opt ? mackey : NULL, hash, TF_FROM_BITS(bits));
			}
			if (isbase64(shash)) base64_decode(tmp, sizeof(tmp), shash, strlen(shash));
			else hex2bin(tmp, shash);

			if (!memcmp(hash, tmp, TF_FROM_BITS(bits))) {
				tfc_say("%s: OK", fname);
			}
			else {
				tfc_say("%s: FAILED", fname);
				failed++;
			}
			memset(tmp, 0, sizeof(tmp));
			memset(sksblk, 0, sizeof(sksblk));
			totaltested++;
		}

		fclose(f);
		if (failed) {
			tfc_esay("%s: WARNING: %u of %u computed checksums did NOT match",
				progname, failed, totaltested);
			exitcode = 1;
		}
		xexit(exitcode);
	}

	for (xx = 0; fargv[xx]; xx++);
	if (xx == 0) {
		fd = 0;
		x = 0;
		goto _dohash;
	}

	for (x = 0; fargv[x] && xx; x++) {
		if (!strcmp(fargv[x], "-")) fd = 0;
		else fd = open(fargv[x], O_RDONLY | O_LARGEFILE);
		if (fd == -1) {
			xerror(YES, NO, YES, "%s", fargv[x]);
			exitcode = 1;
			continue;
		}

_dohash:	if (status_timer) setup_next_alarm(status_timer);
		if (skeinfd(hash, bits, mackey_opt ? mackey : NULL, fd, iseek, maxlen) != YES) {
			xerror(YES, NO, YES, "%s", fargv[x]);
			exitcode = 1;
			continue;
		}
		xclose(fd);
		if (sksum_turns > 1) {
			size_t y;
			for (y = 0; y < sksum_turns; y++) skein(hash, bits, mackey_opt ? mackey : NULL, hash, TF_FROM_BITS(bits));
		}
		if (do_outfmt == TFC_OUTFMT_B64) tfc_printbase64(stdout, hash, TF_FROM_BITS(bits), 0);
		else if (do_outfmt == TFC_OUTFMT_RAW) xwrite(1, hash, TF_FROM_BITS(bits));
		else mhexdump(hash, TF_FROM_BITS(bits), TF_FROM_BITS(bits), 0);
		if (do_outfmt != TFC_OUTFMT_RAW) {
			if (quiet == NO || xx > 1) tfc_say("\t%s", fargv[x] ? fargv[x] : "-");
			else tfc_say("\n");
		}
	}

	memset(hash, 0, SKEIN_DIGEST_SIZE);
	xexit(exitcode);
}
