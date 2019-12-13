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
#include "tfcrypt_defs.h"

char *progname;
int exitcode;

tfc_byte key[TF_KEY_SIZE], ctr[TF_BLOCK_SIZE], xtskey[TF_KEY_SIZE], mackey[TF_FROM_BITS(TF_MAX_BITS)], tweak[TF_TWEAK_SIZE];
struct skein sk;
struct tfe_stream tfe;
tfc_byte srcblk[TFC_BLKSIZE], dstblk[TFC_BLKSIZE], *pblk;
tfc_byte macvrfy[SKEIN_DIGEST_SIZE], macresult[SKEIN_DIGEST_SIZE];
tfc_byte tmpdata[TFC_TMPSIZE];

char *randsource = TFC_DEFAULT_RANDSOURCE;

tfc_fsize iseek_blocks, iseek, oseek, maxlen = NOFSIZE, ftrunc_dfd = NOFSIZE;
tfc_fsize total_processed_src, total_processed_dst;
tfc_fsize delta_processed;
tfc_fsize genrandom_nr_bytes, genzero_nr_bytes;
tfc_fsize rdpos = NOFSIZE;
tfc_fsize maxkeylen = NOFSIZE, keyoffset;
int sfd, kfd = -1, dfd = 1;
struct stat s_stat;
size_t blksize = TFC_BLKSIZE, xtsblocks = TFC_XTSBLOCKS;
char pwdask[512], pwdagain[512];

size_t lio, lrem, ldone, lblock;
size_t ctrsz = NOSIZE;

struct sigaction sigact;

size_t sksum_turns;

int do_edcrypt = TFC_DO_ENCRYPT, do_stop, quiet, error_action;
int counter_opt, mackey_opt, do_mac, do_outfmt = TFC_OUTFMT_B64, rawkey;
int idx, write_flags;
tfc_yesno catch_all_errors, ignore_seek_errors, password, overwrite_source, do_fsync, do_pad, do_ftrunc = TFC_NO_FTRUNC;
tfc_yesno do_preserve_time, do_stats_in_gibs, do_statline_dynamic = YES, do_less_stats;
tfc_yesno no_repeat, do_full_hexdump = YES, verbose, statline_was_shown, show_secrets;
char *srcfname = TFC_STDIN_NAME, *dstfname = TFC_STDOUT_NAME, *do_mac_file, *counter_file, *sksum_hashlist_file;
char *saltf, *genkeyf, *mackeyf, *tweakf;
char *pw_prompt, *mac_pw_prompt;
tfc_useconds status_timer, bench_timer;
tfc_useconds total_time, current_time, delta_time;

struct getpasswd_state getps;
