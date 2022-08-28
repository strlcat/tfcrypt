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

void do_benchmark(tfc_useconds useconds, double dseconds)
{
	size_t x, lblock;

	for (x = 1; x < NSIG; x++) signal(x, SIG_IGN);
	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_flags = SA_RESTART;
	sigact.sa_handler = print_crypt_status;
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);
	sigaction(SIGTSTP, &sigact, NULL);
	sigaction(SIGALRM, &sigact, NULL);
	setup_next_alarm(useconds);
	memset(&sigact, 0, sizeof(struct sigaction));

	tfc_getcurtime(&delta_time);

	tfc_getrandom(key, sizeof(key));
	tfc_getrandom(ctr, sizeof(ctr));
	if (do_mac != NO) {
		tfc_getrandom(mackey, sizeof(mackey));
		skein_init_key(&sk, mackey, macbits);
	}
	if (ctr_mode == TFC_MODE_STREAM) tfe_init_iv(&tfe, key, ctr);
	if (ctr_mode == TFC_MODE_XTS) tfc_getrandom(xtskey, sizeof(xtskey));

	tfc_nfsay(stdout, "%s: doing %s benchmark for %.4f seconds ... ", tfc_format_pid(progname), tfc_modename(ctr_mode), dseconds);

	do_stop = NO;
	while (1) {
		if (do_stop) break;

		lblock = blk_len_adj(NOFSIZE, total_processed_src, blksize);
		total_processed_src += lblock;

		if (do_mac != NO) skein_update(&sk, srcblk, lblock);

		if (ctr_mode == TFC_MODE_CTR) tf_ctr_crypt(key, ctr, srcblk, srcblk, lblock);
		else if (ctr_mode == TFC_MODE_STREAM) tf_stream_crypt(&tfe, srcblk, srcblk, lblock);
		else if (ctr_mode == TFC_MODE_XTS && do_edcrypt == TFC_DO_ENCRYPT)
			tf_xts_encrypt(key, xtskey, ctr, srcblk, srcblk, lblock, xtsblocks);
		else if (ctr_mode == TFC_MODE_XTS && do_edcrypt == TFC_DO_DECRYPT)
			tf_xts_decrypt(key, xtskey, ctr, srcblk, srcblk, lblock, xtsblocks);
		else if (ctr_mode == TFC_MODE_ECB && do_edcrypt == TFC_DO_ENCRYPT)
			tf_ecb_encrypt(key, srcblk, srcblk, lblock);
		else if (ctr_mode == TFC_MODE_ECB && do_edcrypt == TFC_DO_DECRYPT)
			tf_ecb_decrypt(key, srcblk, srcblk, lblock);
		else if (ctr_mode == TFC_MODE_CBC && do_edcrypt == TFC_DO_ENCRYPT)
			tf_cbc_encrypt(key, ctr, srcblk, srcblk, lblock);
		else if (ctr_mode == TFC_MODE_CBC && do_edcrypt == TFC_DO_DECRYPT)
			tf_cbc_decrypt(key, ctr, srcblk, srcblk, lblock);
		else if (ctr_mode == TFC_MODE_PCBC && do_edcrypt == TFC_DO_ENCRYPT)
			tf_pcbc_encrypt(key, ctr, srcblk, srcblk, lblock);
		else if (ctr_mode == TFC_MODE_PCBC && do_edcrypt == TFC_DO_DECRYPT)
			tf_pcbc_decrypt(key, ctr, srcblk, srcblk, lblock);

		delta_processed += lblock;
	}
}
