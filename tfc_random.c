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

static void print_crypt_status_genrnd(int signal)
{
	print_crypt_status(signal);
}

static void exit_sigterm_genrnd(int signal)
{
	exit_sigterm(signal);
}

static void get_urandom(const char *src, void *buf, size_t size)
{
	tfc_byte *ubuf = buf;
	int fd = -1;
	size_t sz = size, rd;

	if (src == NULL) fd = -1;
	else fd = open(src, O_RDONLY);

	if (fd == -1) fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1) fd = open("/dev/arandom", O_RDONLY);
	if (fd == -1) fd = open("/dev/prandom", O_RDONLY);
	if (fd == -1) fd = open("/dev/srandom", O_RDONLY);
	if (fd == -1) fd = open("/dev/random", O_RDONLY);
	if (fd == -1) xerror(NO, YES, YES, "random source is required (tried %s)", src);

_again:	rd = xread(fd, ubuf, sz);
	if (rd < sz && rd != NOSIZE) {
		ubuf += rd;
		sz -= rd;
		goto _again;
	}

	xclose(fd);
}

static tfc_yesno tfc_random_initialised;

static void tfc_initrandom(const char *rndsrc)
{
	tfc_byte k[TF_KEY_SIZE];

	if (tfc_random_initialised == YES) return;

	get_urandom(rndsrc, k, TF_KEY_SIZE);
	tf_prng_seedkey(k);
	memset(k, 0, TF_KEY_SIZE);

	tfc_random_initialised = YES;
}

void tfc_finirandom(void)
{
	tf_prng_seedkey(NULL);
	tfc_random_initialised = NO;
}

void tfc_getrandom(void *buf, size_t sz)
{
	if (tfc_random_initialised == NO) tfc_initrandom(randsource);
	tf_prng_genrandom(buf, sz);
}

void gen_write_bytes(const char *foutname, tfc_fsize offset, tfc_fsize nrbytes)
{
	static tfc_fsize wrpos = NOFSIZE;
	int fd, x;
	size_t lblock, lio, lrem;
	tfc_byte *pblk;

	for (x = 1; x < NSIG; x++) signal(x, SIG_IGN);
	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_flags = SA_RESTART;
	sigact.sa_handler = print_crypt_status;
	sigaction(SIGUSR1, &sigact, NULL);
	sigaction(SIGALRM, &sigact, NULL);
	if (status_timer) setup_next_alarm(status_timer > 1000000 ? 1000000 : status_timer);
	sigact.sa_handler = change_status_width;
	sigaction(SIGQUIT, &sigact, NULL);
	sigact.sa_handler = change_status_timer;
	sigaction(SIGUSR2, &sigact, NULL);
	if (quiet == NO) {
		sigact.sa_handler = print_crypt_status_genrnd;
		sigaction(SIGINT, &sigact, NULL);
		sigaction(SIGTERM, &sigact, NULL);
		sigaction(SIGTSTP, &sigact, NULL);
	}
	else {
		sigact.sa_handler = exit_sigterm_genrnd;
		sigaction(SIGINT, &sigact, NULL);
		sigaction(SIGTERM, &sigact, NULL);
		sigact.sa_handler = handle_sigtstp;
		sigaction(SIGTSTP, &sigact, NULL);
	}
	memset(&sigact, 0, sizeof(struct sigaction));

	tfc_getcurtime(&delta_time);

	if (do_less_stats) do_less_stats = NO;
	else do_less_stats = YES;

	if (!foutname) {
		fd = 1;
		foutname = TFC_STDOUT_NAME;
	}
	else if (!strcmp(foutname, "-")) {
		fd = 1;
		foutname = TFC_STDOUT_NAME;
	}
	else fd = xopen(foutname, O_WRONLY | O_CREAT | O_LARGEFILE | write_flags);

	if (offset) {
		if (lseek(fd, offset, SEEK_SET) == -1)
			xerror(ignore_seek_errors, NO, NO, "%s: seek failed", foutname);
	}

	if (do_edcrypt == TFC_DO_PLAIN) memset(srcblk, 0, sizeof(srcblk));

	if (verbose) tfc_nfsay(stderr, "%s: writing %lld bytes to %s ... ",
		tfc_format_pid(progname), nrbytes, foutname);

	errno = 0;
	do_stop = NO;
	while (1) {
		if (do_stop) break;
		pblk = srcblk;
		lblock = lrem = blk_len_adj(nrbytes, total_processed_src, blksize);

		if (do_edcrypt != TFC_DO_PLAIN) tfc_getrandom(srcblk, lblock);

		if (error_action == TFC_ERRACT_SYNC) wrpos = tfc_fdgetpos(fd);
_wagain:	lio = xwrite(fd, pblk, lrem);
		if (lio == NOSIZE) {
			if (errno != EIO && catch_all_errors != YES)
				xerror(NO, NO, YES, "%s", foutname);
			switch (error_action) {
				case TFC_ERRACT_CONT: xerror(YES, NO, YES, "%s", foutname); goto _wagain; break;
				case TFC_ERRACT_SYNC:
				case TFC_ERRACT_LSYNC:
					xerror(YES, NO, YES, "%s", foutname);
					if (wrpos == NOFSIZE) lseek(fd, lblock, SEEK_CUR);
					else lseek(fd, wrpos + lblock, SEEK_SET);
					break;
				default: xerror(NO, NO, YES, "%s", foutname); break;
			}
		}
		if (do_fsync && fsync(fd) == -1) xerror(NO, NO, YES, "%s", foutname);
		if (lio < lrem) {
			pblk += lio;
			lrem -= lio;
			goto _wagain;
		}

		total_processed_src += lblock;
		delta_processed += lblock;
		total_processed_dst = total_processed_src;
		if (total_processed_src >= nrbytes) break;
	}

	if (verbose) tfc_esay("done!");
	if (verbose || status_timer) {
		print_crypt_status(TFC_SIGSTAT);
		tfc_esay("\n");
	}

	xclose(fd);
	xexit(0);
}
