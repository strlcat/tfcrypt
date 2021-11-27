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

static int getps_filter(struct getpasswd_state *getps, char chr, size_t pos)
{
	if (chr == '\x03') {
		getps->retn = ((size_t)-2);
		return 6;
	}
	return 1;
}

static int getps_hex_filter(struct getpasswd_state *getps, char chr, size_t pos)
{
	if (chr == '\x03') {
		getps->retn = ((size_t)-2);
		return 6;
	}
	if (chr >= '0' && chr <= '9') return 1;
	if (chr >= 'a' && chr <= 'f') return 1;
	if (chr >= 'A' && chr <= 'F') return 1;
	if (chr == '\x7f' || chr == '\x08'
	|| chr == '\x15' || chr == '\x17') return 1;
	return 0;
}

static inline int isctrlchr(int c)
{
	if (c == 9) return 0;
	if (c >= 0 && c <= 31) return 1;
	if (c == 127) return 1;
	return 0;
}

static int getps_plain_filter(struct getpasswd_state *getps, char chr, size_t pos)
{
	int x;

	x = getps_filter(getps, chr, pos);
	if (x != 1) return x;

	if (pos < getps->pwlen && !isctrlchr(chr))
		write(getps->efd, &chr, sizeof(char));
	return 1;
}

static int getps_plain_hex_filter(struct getpasswd_state *getps, char chr, size_t pos)
{
	int x;

	x = getps_hex_filter(getps, chr, pos);
	if (x != 1) return x;

	if (pos < getps->pwlen && !isctrlchr(chr))
		write(getps->efd, &chr, sizeof(char));
	return 1;
}

static void make_hint(void *hint, size_t szhint, const void *data, size_t szdata)
{
	char t[TF_FROM_BITS(TF_MAX_BITS)];

	skein(t, TF_MAX_BITS, NULL, data, szdata);
	xor_shrink(hint, szhint, t, sizeof(t));
	memset(t, 0, sizeof(t));
}

static void raw_say_hint(void *hint, size_t szhint, const void *data, size_t szdata, const char *prompt)
{
	make_hint(hint, szhint, data, szdata);
	if (prompt) tfc_nfsay(stderr, "%s: ", prompt);
	mehexdump(hint, szhint, szhint, 1);
	memset(hint, 0, szhint);
}

static void say_hint(const void *data, size_t szdata, const char *prompt)
{
	char t[TF_SIZE_UNIT];
	raw_say_hint(t, TF_SIZE_UNIT, data, szdata, prompt);
	/* t[] is erased (automatically) */
}

int main(int argc, char **argv)
{
	int c;
	double td;
	char *s, *d, *t, *stoi;
	size_t x, n;

	progname = basename(argv[0]);

	if (!isatty(2)) do_statline_dynamic = NO;

	s = (char *)srcblk;
	d = getenv("HOME");
	if (!d) d = "";
	n = PATH_MAX > sizeof(srcblk) ? sizeof(srcblk) : PATH_MAX;
	if (xstrlcpy(s, d, n) >= n) goto _baddfname;
	if (xstrlcat(s, "/.tfcrypt.defs", n) >= n) goto _baddfname;
	read_defaults(s, YES);
_baddfname:
	memset(s, 0, n);

	if (!strcmp(progname, "iotool")) {
		do_edcrypt = TFC_DO_PLAIN;
		password = YES;
		ctr_mode = TFC_MODE_PLAIN;
	}

	opterr = 0;
	while ((c = getopt(argc, argv, "L:s:aU:C:r:K:t:Pkzxc:l:qedn:vV:pwE:O:S:AmM:R:Z:WHD:")) != -1) {
		switch (c) {
			case 'L':
				read_defaults(optarg, NO);
				break;
			case 's':
				saltf = optarg;
				break;
			case 'r':
				randsource = optarg;
				break;
			case 'c':
				if (!strcasecmp(optarg, "show"))
					counter_opt = TFC_CTR_SHOW;
				else if (!strcasecmp(optarg, "head"))
					counter_opt = TFC_CTR_HEAD;
				else if (!strcasecmp(optarg, "rand"))
					counter_opt = TFC_CTR_RAND;
				else if (!strcasecmp(optarg, "zero"))
					counter_opt = TFC_CTR_ZERO;
				else if (strchr(optarg, ':')) {
					char *ss, chr;

					counter_opt = TFC_CTR_SSET;
					n = sizeof(ctr);

					s = d = optarg; t = NULL;
					while ((s = strtok_r(d, ",", &t))) {
						if (d) d = NULL;

						if (n == 0) break;
						ss = strchr(s, ':');
						if (!ss) continue;
						*ss = 0; ss++;
						chr = (char)strtoul(s, &stoi, 16);
						if (!str_empty(stoi)) continue;
						x = (size_t)strtoul(ss, &stoi, 10);
						if (!str_empty(stoi)) continue;
						if (x > n) x = n;
						memset(ctr+(sizeof(ctr)-n), (int)chr, x);
						n -= x;
					}
				}
				else counter_file = sksum_hashlist_file = optarg;
				break;
			case 'C':
				if (!strcasecmp(optarg, "ctr"))
					ctr_mode = TFC_MODE_CTR;
				else if (!strcasecmp(optarg, "stream"))
					ctr_mode = TFC_MODE_STREAM;
				else if (!strcasecmp(optarg, "cbc"))
					ctr_mode = TFC_MODE_CBC;
				else if (!strcasecmp(optarg, "ecb"))
					ctr_mode = TFC_MODE_ECB;
				else if (!strcasecmp(optarg, "xts"))
					ctr_mode = TFC_MODE_XTS;
				else if (!strcasecmp(optarg, "ocb"))
					ctr_mode = TFC_MODE_OCB;
				else xerror(NO, YES, YES, "%s: invalid mode of operation", optarg);
				break;
			case 'P':
				do_edcrypt = TFC_DO_PLAIN;
				password = YES;
				ctr_mode = TFC_MODE_PLAIN;
				break;
			case 'e':
				if (do_edcrypt != TFC_DO_PLAIN) do_edcrypt = TFC_DO_ENCRYPT;
				break;
			case 'd':
				if (do_edcrypt != TFC_DO_PLAIN) do_edcrypt = TFC_DO_DECRYPT;
				break;
			case 'D':
				macbits = strtoul(optarg, &stoi, 10);
				if (macbits == 0 || !str_empty(stoi) || macbits < 8
				|| macbits > TF_MAX_BITS || macbits % 8)
					xerror(NO, YES, YES, "%s: invalid MAC bits setting", optarg);
				break;
			case 'n':
				nr_turns = sksum_turns = strtoul(optarg, &stoi, 10);
				if (!str_empty(stoi)) xerror(NO, YES, YES, "%s: invalid number of turns", optarg);
				break;
			case 'U':
				if (!strcasecmp(optarg, "key"))
					mackey_opt = TFC_MACKEY_RAWKEY;
				else if (!strcasecmp(optarg, "pwd"))
					mackey_opt = TFC_MACKEY_PASSWORD;
				else {
					mackey_opt = TFC_MACKEY_FILE;
					mackeyf = optarg;
				}
				break;
			case 'p':
				password = YES;
				break;
			case 'k':
				rawkey = TFC_RAWKEY_KEYFILE;
				break;
			case 'z':
				rawkey = TFC_RAWKEY_ASKSTR;
				break;
			case 'x':
				rawkey = TFC_RAWKEY_ASKHEX;
				break;
			case 'K':
				verbose = YES;
				genkeyf = optarg;
				break;
			case 't':
				tweakf = optarg;
				do_full_key = NO;
				break;
			case 'l':
				if (maxlen != NOFSIZE) break;

				maxlen = tfc_humanfsize(optarg, &stoi);
				if (!str_empty(stoi)) {
					maxlen = tfc_fnamesize(optarg, YES);
					maxlen = tfc_modifysize(maxlen, strchr(optarg, ':'));
					if (maxlen == NOFSIZE) xerror(NO, YES, YES,
					"%s: invalid count value", optarg);
				}
				else maxlen = tfc_modifysize(maxlen, strchr(optarg, ':'));
				if (counter_opt == TFC_CTR_HEAD)
					maxlen += TF_BLOCK_SIZE;
				break;
			case 'w':
				overwrite_source = YES;
				break;
			case 'E':
				if (!strcmp(optarg, "xall")) {
					catch_all_errors = YES;
					break;
				}
				if (!strcmp(optarg, "xseek")) {
					ignore_seek_errors = YES;
					break;
				}
				if (!strcmp(optarg, "exit"))
					error_action = TFC_ERRACT_EXIT;
				else if (!strncmp(optarg, "cont", 4))
					error_action = TFC_ERRACT_CONT;
				else if (!strcmp(optarg, "sync"))
					error_action = TFC_ERRACT_SYNC;
				else if (!strcmp(optarg, "lsync"))
					error_action = TFC_ERRACT_LSYNC;
				else xerror(NO, YES, YES, "invalid error action %s specified", optarg);
				break;
			case 'O':
				s = d = optarg; t = NULL;
				while ((s = strtok_r(d, ",", &t))) {
					if (d) d = NULL;
					if (!strcmp(s, "sync"))
						write_flags |= O_SYNC;
					else if (!strcmp(s, "trunc"))
						write_flags |= O_TRUNC;
					else if (!strcmp(s, "fsync"))
						do_fsync = YES;
					else if (!strcmp(s, "pad"))
						do_pad = YES;
					else if (!strcmp(s, "xtime"))
						do_preserve_time = YES;
					else if (!strcmp(s, "gibsize"))
						do_stats_in_gibs = YES;
					else if (!strcmp(s, "plainstats"))
						do_statline_dynamic = NO;
					else if (!strcmp(s, "statless"))
						do_less_stats = YES;
					else if (!strcmp(s, "norepeat"))
						no_repeat = YES;
					else if (!strncmp(s, "prompt", 6) && *(s+6) == '=')
						pw_prompt = s+7;
					else if (!strncmp(s, "macprompt", 9) && *(s+9) == '=')
						mac_pw_prompt = s+10;
					else if (!strcmp(s, "shorthex"))
						do_full_hexdump = NO;
					else if (!strcmp(s, "fullkey"))
						do_full_key = YES;
					else if (!strcmp(s, "showsecrets"))
						show_secrets = YES;
					else if (!strncmp(s, "iobs", 4) && *(s+4) == '=') {
						s += 5;
						blksize = (size_t)tfc_humanfsize(s, &stoi);
						if (!str_empty(stoi)) {
							blksize = (size_t)tfc_fnamesize(s, YES);
							blksize = (size_t)tfc_modifysize((tfc_fsize)blksize, strchr(s, ':'));
							if (blksize == NOSIZE) xerror(NO, YES, YES,
							"%s: invalid block size value", s);
						}
						else blksize = (size_t)tfc_modifysize((tfc_fsize)blksize, strchr(s, ':'));
						if (blksize < TF_BLOCK_SIZE) xerror(NO, YES, YES,
							"%s: block size is lesser than TF_BLOCK_SIZE (%u bytes)", s, TFC_U(TF_BLOCK_SIZE));
						if (blksize > TFC_BLKSIZE) xerror(NO, YES, YES,
							"%s: block size exceeds %u bytes",
							s, TFC_U(TFC_BLKSIZE));
					}
					else if (!strncmp(s, "xtsblocks", 9) && *(s+9) == '=') {
						s += 10;
						xtsblocks = (size_t)tfc_humanfsize(s, &stoi);
						if (!str_empty(stoi)) {
							xtsblocks = (size_t)tfc_fnamesize(s, YES);
							xtsblocks = (size_t)tfc_modifysize((tfc_fsize)xtsblocks, strchr(s, ':'));
							if (xtsblocks == NOSIZE) xerror(NO, YES, YES,
							"%s: invalid blocks per xts block value", s);
						}
						else xtsblocks = (size_t)tfc_modifysize((tfc_fsize)xtsblocks, strchr(s, ':'));
						if (TFC_BLKSIZE % xtsblocks) xerror(NO, YES, YES,
							"%s: nr of blocks per xts block is not round to %u bytes",
							s, TFC_U(TFC_BLKSIZE));
						if ((xtsblocks * TF_BLOCK_SIZE) > TFC_BLKSIZE) xerror(NO, YES, YES,
							"%s: nr of blocks per xts block exceeds %u bytes",
							s, TFC_U(TFC_BLKSIZE));
					}
					else if (!strncmp(s, "iseek", 5) && *(s+5) == '=') {
						s += 6;
						iseek = tfc_humanfsize(s, &stoi);
						if (!str_empty(stoi)) {
							iseek = tfc_fnamesize(s, YES);
							iseek = tfc_modifysize(iseek, strchr(s, ':'));
							if (iseek == NOFSIZE) xerror(NO, YES, YES,
							"%s: invalid iseek value", s);
						}
						else iseek = tfc_modifysize(iseek, strchr(s, ':'));
						if (ctr_mode != TFC_MODE_PLAIN && iseek % TF_BLOCK_SIZE)
							xerror(NO, YES, YES,
								"%s: not round to TF block size "
								"of %u bytes",
								s, TFC_U(TF_BLOCK_SIZE));
						iseek_blocks = iseek / TF_BLOCK_SIZE;
					}
					else if (!strncmp(s, "ixseek", 6) && *(s+6) == '=') {
						s += 7;
						iseek = tfc_humanfsize(s, &stoi);
						if (!str_empty(stoi)) {
							iseek = tfc_fnamesize(s, YES);
							iseek = tfc_modifysize(iseek, strchr(s, ':'));
							if (iseek == NOFSIZE) xerror(NO, YES, YES,
								"%s: invalid ixseek value", s);
						}
						else iseek = tfc_modifysize(iseek, strchr(s, ':'));
					}
					else if (!strncmp(s, "ictr", 4) && *(s+4) == '=') {
						s += 5;
						iseek_blocks = tfc_humanfsize(s, &stoi);
						if (!str_empty(stoi)) {
							iseek_blocks = tfc_fnamesize(s, YES);
							if (iseek_blocks == NOFSIZE)
								xerror(NO, YES, YES,
								"%s: invalid ictr value", s);
							iseek_blocks /= TF_BLOCK_SIZE;
							iseek_blocks = tfc_modifysize(iseek_blocks, strchr(s, ':'));
						}
						else iseek_blocks = tfc_modifysize(iseek_blocks, strchr(s, ':'));
					}
					else if (!strncmp(s, "ixctr", 5) && *(s+5) == '=') {
						s += 6;
						iseek_blocks = tfc_humanfsize(s, &stoi);
						if (!str_empty(stoi)) {
							iseek_blocks = tfc_fnamesize(s, YES);
							iseek_blocks = tfc_modifysize(iseek_blocks, strchr(s, ':'));
							if (iseek_blocks == NOFSIZE)
								xerror(NO, YES, YES,
								"%s: invalid ixctr value", s);
						}
						else iseek_blocks = tfc_modifysize(iseek_blocks, strchr(s, ':'));
						if (iseek_blocks % TF_BLOCK_SIZE)
							xerror(NO, YES, YES,
							"%s: not round to TF block size "
							"of %u bytes", s, TFC_U(TF_BLOCK_SIZE));
						iseek_blocks /= TF_BLOCK_SIZE;
					}
					else if (!strncmp(s, "oseek", 5) && *(s+5) == '=') {
						s += 6;
						oseek = tfc_humanfsize(s, &stoi);
						if (!str_empty(stoi)) {
							oseek = tfc_fnamesize(s, YES);
							oseek = tfc_modifysize(oseek, strchr(s, ':'));
							if (oseek == NOFSIZE) xerror(NO, YES, YES,
							"%s: invalid oseek value", s);
						}
						else oseek = tfc_modifysize(oseek, strchr(s, ':'));
					}
					else if (!strncmp(s, "count", 5) && *(s+5) == '=') {
						s += 6;
						maxlen = tfc_humanfsize(s, &stoi);
						if (!str_empty(stoi)) {
							maxlen = tfc_fnamesize(s, YES);
							maxlen = tfc_modifysize(maxlen, strchr(s, ':'));
							if (maxlen == NOFSIZE) xerror(NO, YES, YES,
							"%s: invalid count value", s);
						}
						else maxlen = tfc_modifysize(maxlen, strchr(s, ':'));
						if (counter_opt == TFC_CTR_HEAD)
							maxlen += TF_BLOCK_SIZE;
					}
					else if (!strncmp(s, "ftrunc", 6) && *(s+6) == '=') {
						s += 7;
						if (!strcmp(s, "tail")) {
							do_ftrunc = TFC_FTRUNC_TAIL;
							ftrunc_dfd = NOFSIZE;
						}
						else {
							do_ftrunc = TFC_DO_FTRUNC;
							ftrunc_dfd = tfc_humanfsize(s, &stoi);
							if (!str_empty(stoi)) {
								ftrunc_dfd = tfc_fnamesize(s, YES);
								ftrunc_dfd = tfc_modifysize(ftrunc_dfd, strchr(s, ':'));
								if (ftrunc_dfd == NOFSIZE) xerror(NO, YES, YES,
								"%s: invalid ftrunc value", s);
							}
							else ftrunc_dfd = tfc_modifysize(ftrunc_dfd, strchr(s, ':'));
						}
					}
					else if (!strncmp(s, "xkey", 4) && *(s+4) == '=') {
						s += 5;
						maxkeylen = tfc_humanfsize(s, &stoi);
						if (!str_empty(stoi)) {
							maxkeylen = tfc_fnamesize(s, YES);
							maxkeylen = tfc_modifysize(maxkeylen, strchr(s, ':'));
							if (maxkeylen == NOSIZE)
								xerror(NO, YES, YES,
								"%s: invalid key length value", s);
						}
						else maxkeylen = tfc_modifysize(maxkeylen, strchr(s, ':'));
					}
					else if (!strncmp(s, "okey", 4) && *(s+4) == '=') {
						s += 5;
						keyoffset = tfc_humanfsize(s, &stoi);
						if (!str_empty(stoi)) {
							keyoffset = tfc_fnamesize(s, YES);
							keyoffset = tfc_modifysize(keyoffset, strchr(s, ':'));
							if (keyoffset == NOFSIZE)
								xerror(NO, YES, YES,
								"%s: invalid key offset value", s);
						}
						else keyoffset = tfc_modifysize(keyoffset, strchr(s, ':'));
					}
					else if (!strncmp(s, "xctr", 4) && *(s+4) == '=') {
						s += 5;
						ctrsz = tfc_humanfsize(s, &stoi);
						if (!str_empty(stoi)) {
							ctrsz = (size_t)tfc_fnamesize(s, YES);
							ctrsz = (size_t)tfc_modifysize((tfc_fsize)ctrsz, strchr(s, ':'));
							if (ctrsz == NOSIZE)
								xerror(NO, YES, YES,
								"%s: invalid counter length value", s);
						}
						else ctrsz = (size_t)tfc_modifysize((tfc_fsize)ctrsz, strchr(s, ':'));
						if (ctrsz > TF_BLOCK_SIZE)
							xerror(NO, YES, YES, "%s: counter size cannot exceed TF block size", s);
					}
					else xerror(NO, YES, YES, "invalid option %s", s);
				}
				break;
			case 'S':
				do_mac = TFC_MAC_SIGN;
				if (strcasecmp(optarg, "mac") != 0)
					do_mac_file = optarg;
				break;
			case 'M':
				do_mac = TFC_MAC_VRFY;
				if (!strcasecmp(optarg, "drop"))
					do_mac = TFC_MAC_DROP;
				else if (strcasecmp(optarg, "mac") != 0)
					do_mac_file = optarg;
				break;
			case 'm':
				if (do_mac != TFC_MAC_VRFY)
					xerror(NO, YES, YES, "signature source was not specified");
				do_mac = TFC_MAC_JUST_VRFY;
				break;
			case 'R':
			case 'Z':
				if (maxlen != NOFSIZE) {
					if (c == 'Z') genzero_nr_bytes = maxlen;
					else genrandom_nr_bytes = maxlen;
				}
				else {
					tfc_fsize t;
					if (!strcasecmp(optarg, "cbs"))
						t = TF_BLOCK_SIZE;
					else if (!strcasecmp(optarg, "ks"))
						t = TF_FROM_BITS(TFC_KEY_BITS);
					else if (!strcasecmp(optarg, "xks"))
						t = TF_FROM_BITS(TFC_KEY_BITS) * 2;
					else if (!strcasecmp(optarg, "iobs"))
						t = blksize;
					else {
						t = tfc_humanfsize(optarg, &stoi);
						if (!str_empty(stoi)) {
							t = tfc_fnamesize(optarg, NO);
							t = tfc_modifysize(t, strchr(optarg, ':'));
						}
						else t = tfc_modifysize(t, strchr(optarg, ':'));
					}
					if (c == 'Z') genzero_nr_bytes = maxlen = t;
					else genrandom_nr_bytes = maxlen = t;
				}
				break;
			case 'a':
				do_preserve_time = YES;
				break;
			case 'A':
				do_outfmt = TFC_OUTFMT_B64;
				break;
			case 'W':
				do_outfmt = TFC_OUTFMT_RAW;
				break;
			case 'H':
				do_outfmt = TFC_OUTFMT_HEX;
				break;
			case 'q':
				quiet = YES;
				verbose = NO;
				do_full_hexdump = NO;
				status_timer = 0;
				break;
			case 'v':
				verbose = YES;
				break;
			case 'V':
				td = strtod(optarg, &stoi);
				status_timer = TFC_DTOUSECS(td);
				if (status_timer <= TFC_DTOUSECS(0) || !str_empty(stoi)) status_timer = 0;
				break;
			default:
				usage();
				break;
		}
	}

	if (!strcmp(progname, "tfbench")) {
		if (!*(argv+optind)) usage();

		td = strtod(*(argv+optind), &stoi);
		if (td <= TFC_DTOUSECS(0) || !str_empty(stoi))
			xerror(NO, YES, YES,
			"%s: invalid benchmark time in seconds", *(argv+optind));
		bench_timer = TFC_DTOUSECS(td);
		do_benchmark(bench_timer, td);
	}
	if (genrandom_nr_bytes) {
		ctr_mode = TFC_MODE_STREAM;
		do_edcrypt = TFC_DO_ENCRYPT;
		gen_write_bytes(*(argv+optind), oseek, genrandom_nr_bytes);
	}
	if (genzero_nr_bytes) {
		ctr_mode = TFC_MODE_PLAIN;
		do_edcrypt = TFC_DO_PLAIN;
		gen_write_bytes(*(argv+optind), oseek, genzero_nr_bytes);
	}

	if (rawkey && password)
		xerror(NO, YES, YES, "Cannot use rawkey and hashing password!");
	if (do_edcrypt == TFC_DO_ENCRYPT && do_mac >= TFC_MAC_VRFY)
		xerror(NO, YES, YES, "Cannot encrypt and verify signature!");
	if (do_edcrypt == TFC_DO_DECRYPT && do_mac == TFC_MAC_SIGN)
		xerror(NO, YES, YES, "Cannot decrypt and calculate signature!");
	if (do_edcrypt == TFC_DO_DECRYPT && counter_opt == TFC_CTR_RAND)
		xerror(NO, YES, YES, "Cannot decrypt and embed a generated CTR into file!");
	if (do_edcrypt == TFC_DO_ENCRYPT && counter_opt == TFC_CTR_HEAD)
		xerror(NO, YES, YES, "Cannot encrypt and read CTR from source!");
	if (overwrite_source && counter_opt == TFC_CTR_RAND)
		xerror(NO, YES, YES, "Cannot embed a CTR into file when overwriting it!");
	if (ctr_mode == TFC_MODE_PLAIN
	&& (do_edcrypt || do_mac || rawkey
	|| mackey_opt || counter_opt || counter_file))
		xerror(NO, YES, YES, "Encryption facility is disabled when in plain IO mode.");

	errno = 0;
	do_stop = NO;

	if (saltf) {
		int saltfd;

		memset(tfc_salt, 0, TFC_MAX_SALT);
		tfc_saltsz = 0;
		if (!strcasecmp(saltf, "disable")) goto _nosalt;

		if (!strcmp(saltf, "-")) saltfd = 0;
		else saltfd = open(saltf, O_RDONLY | O_LARGEFILE);
		if (saltfd == -1) xerror(NO, NO, YES, "%s", saltf);
		lio = xread(saltfd, tfc_salt, TFC_MAX_SALT - TF_FROM_BITS(TFC_KEY_BITS));
		if (lio == NOSIZE) xerror(NO, NO, YES, "%s", saltf);
		tfc_saltsz = lio;
		xclose(saltfd);
	}

_nosalt:
	if (mackey_opt == TFC_MACKEY_FILE && mackeyf) {
		int mkfd = -1;
		tfc_yesno do_stop;

		if (!strcmp(mackeyf, "-")) mkfd = 0;
		else mkfd = open(mackeyf, O_RDONLY | O_LARGEFILE);
		if (mkfd == -1) xerror(NO, NO, YES, "%s", mackeyf);

		skein_init(&sk, TFC_KEY_BITS);

		do_stop = NO;
		while (1) {
			if (do_stop) break;
			pblk = tmpdata;
			ldone = 0;
			lrem = lblock = sizeof(tmpdata);
			if (error_action == TFC_ERRACT_SYNC) rdpos = tfc_fdgetpos(mkfd);
_mkragain:		lio = xread(mkfd, pblk, lrem);
			if (lio == 0 && do_stop == NO) do_stop = YES;
			if (lio != NOSIZE) ldone += lio;
			else {
				if (errno != EIO && catch_all_errors != YES)
					xerror(NO, NO, NO, "%s", mackeyf);
				switch (error_action) {
					case TFC_ERRACT_CONT: xerror(YES, NO, NO, "%s", mackeyf); goto _mkragain; break;
					case TFC_ERRACT_SYNC:
					case TFC_ERRACT_LSYNC:
						xerror(YES, NO, NO, "%s", mackeyf);
						lio = ldone = lrem = lblock;
						memset(tmpdata, 0, lio);
						if (rdpos == NOFSIZE) lseek(mkfd, lio, SEEK_CUR);
						else lseek(mkfd, rdpos + lio, SEEK_SET);
						break;
					default: xerror(NO, NO, NO, "%s", mackeyf); break;
				}
			}
			if (lio && lio < lrem) {
				pblk += lio;
				lrem -= lio;
				goto _mkragain;
			}

			skein_update(&sk, tmpdata, ldone);
		}

		skein_final(mackey, &sk);

		xclose(mkfd);
	}
	else if (mackey_opt == TFC_MACKEY_PASSWORD) {
		memset(&getps, 0, sizeof(struct getpasswd_state));
		getps.fd = getps.efd = -1;
		getps.passwd = pwdask;
		getps.pwlen = sizeof(pwdask)-1;
		getps.echo = mac_pw_prompt ? mac_pw_prompt : "Enter MAC password: ";
		getps.charfilter = (show_secrets == YES) ? getps_plain_filter : getps_filter;
		getps.maskchar = (show_secrets == YES) ? 0 : 'x';
		getps.flags = GETP_WAITFILL;
		n = xgetpasswd(&getps);
		if (n == NOSIZE) xerror(NO, NO, YES, "getting MAC password");
		if (n == ((size_t)-2)) xexit(1);
		if (verbose) say_hint(pwdask, n, "MAC password hint");
		skein(mackey, TF_MAX_BITS, NULL, pwdask, n);
	}

	
	if ((strlen(progname) <= 9)
	&& ((!strcmp(progname, "sksum"))
	|| ((!memcmp(progname, "sk", 2))
	&& (!memcmp(progname+3, "sum", 3)
	|| !memcmp(progname+4, "sum", 3)
	|| !memcmp(progname+5, "sum", 3)
	|| !memcmp(progname+6, "sum", 3)))))
		do_sksum(progname, argv+optind);
	if (!strcmp(progname, "tfbase64")) do_edbase64(argv+optind);

	idx = optind;

	if (argv[idx]) {
		if (password || rawkey > TFC_RAWKEY_KEYFILE) goto _nokeyfd;
		if (!strcmp(argv[idx], "-")) kfd = 0;
		else kfd = open(argv[idx], O_RDONLY | O_LARGEFILE);
		if (kfd == -1) xerror(NO, NO, YES, "%s", argv[idx]);

		lio = strnlen(argv[idx], PATH_MAX);
		memset(argv[idx], '*', lio);

		idx++;
	}
	else password = YES;

	errno = 0;
	if (do_full_key == NO && tweakf) {
		int twfd;

		if (!strcmp(tweakf, "-")) twfd = 0;
		else twfd = open(tweakf, O_RDONLY | O_LARGEFILE);
		if (twfd == -1) xerror(NO, NO, YES, "%s", tweakf);
		lio = ldone = xread(twfd, tweak, TF_TWEAK_SIZE);
		if (lio == NOSIZE) xerror(NO, NO, YES, "%s", tweakf);
		if (ldone < TF_TWEAK_SIZE)
			xerror(NO, NO, YES, "%s: %zu bytes tweak required", tweakf, TF_TWEAK_SIZE);
		xclose(twfd);
	}

_nokeyfd:
	errno = 0;
	if (argv[idx]) {
		if (!strcmp(argv[idx], "-") && kfd) sfd = 0;
		else {
			sfd = open(argv[idx], O_RDONLY | O_LARGEFILE);
			if (do_preserve_time) if (fstat(sfd, &s_stat) == -1)
				xerror(YES, NO, YES, "stat(%s)", argv[idx]);
		}
		if (sfd == -1) xerror(NO, NO, YES, "%s", argv[idx]);

		if (do_edcrypt == TFC_DO_DECRYPT && do_mac != NO && maxlen != NOFSIZE) {
			if (verbose) tfc_esay("%s: disabling signature verification on "
				"requested partial decryption.", progname);
			do_mac = NO;
		}

		if ((do_mac >= TFC_MAC_VRFY || do_mac == TFC_MAC_DROP) && !do_mac_file) {
			maxlen = tfc_fdsize(sfd);
			if (maxlen == NOFSIZE)
				xerror(NO, YES, YES,
				"Cannot verify embedded MAC with non-seekable source!");
			maxlen -= TF_FROM_BITS(macbits);
		}
		srcfname = argv[idx];
		idx++;
	}

	if (!do_mac_file && (do_mac >= TFC_MAC_VRFY && sfd == 0))
		xerror(NO, YES, YES, "Cannot verify embedded MAC with non-seekable source!");

	if (ctrsz == NOSIZE) ctrsz = TF_BLOCK_SIZE;
	if (ctrsz > TF_BLOCK_SIZE) ctrsz = TF_BLOCK_SIZE;

	if (ctr_mode == TFC_MODE_ECB) goto _ctrskip1;
	errno = 0;
	if (counter_file) {
		int ctrfd;

		if (!strcmp(counter_file, "-")) ctrfd = 0;
		else ctrfd = open(counter_file, O_RDONLY | O_LARGEFILE);
		if (ctrfd == -1) xerror(NO, NO, YES, "%s", counter_file);
		lio = xread(ctrfd, ctr, ctrsz);
		if (lio == NOSIZE) xerror(NO, NO, YES, "%s", counter_file);
		if (lio < ctrsz) xerror(NO, YES, YES, "counter file is too small (%zu)!", lio);
		xclose(ctrfd);
	}
	else if (counter_opt == TFC_CTR_HEAD) {
		pblk = ctr;
		ldone = 0;
		lrem = lblock = ctrsz;
		if (error_action == TFC_ERRACT_SYNC) rdpos = tfc_fdgetpos(sfd);
_ctrragain:	lio = xread(sfd, pblk, lrem);
		if (lio != NOSIZE) ldone += lio;
		else {
			if (errno != EIO && catch_all_errors != YES)
				xerror(NO, NO, NO, "%s", srcfname);
			switch (error_action) {
				case TFC_ERRACT_CONT: xerror(YES, NO, NO, "%s", srcfname); goto _ctrragain; break;
				case TFC_ERRACT_SYNC:
				case TFC_ERRACT_LSYNC:
					xerror(YES, NO, NO, "%s", srcfname);
					lio = ldone = lrem = lblock;
					memset(ctr, 0, lio);
					if (rdpos == NOFSIZE) lseek(sfd, lio, SEEK_CUR);
					else lseek(sfd, rdpos + lio, SEEK_SET);
					break;
				default: xerror(NO, NO, NO, "%s", srcfname); break;
			}
		}
		if (lio && lio < lrem) {
			pblk += lio;
			lrem -= lio;
			goto _ctrragain;
		}
		total_processed_src += ldone;
	}

_ctrskip1:
	if (iseek) {
		if (counter_opt == TFC_CTR_HEAD && ctr_mode != TFC_MODE_ECB)
			iseek += ctrsz;
		if (lseek(sfd, iseek, SEEK_SET) == -1)
			xerror(ignore_seek_errors, NO, NO, "%s: seek failed", srcfname);
	}

	if (ctr_mode == TFC_MODE_PLAIN) goto _plain;

	if (verbose) tfc_esay("%s: hashing password", progname);

	if (rawkey == TFC_RAWKEY_KEYFILE) {
		tfc_yesno xtskeyset = NO;

		pblk = key;
_xts2key:	ldone = 0;
		lrem = lblock = TF_FROM_BITS(TFC_KEY_BITS);
		if (error_action == TFC_ERRACT_SYNC) rdpos = tfc_fdgetpos(kfd);
_keyragain:	lio = xread(kfd, pblk, lrem);
		if (lio != NOSIZE) ldone += lio;
		else {
			if (errno != EIO && catch_all_errors != YES)
				xerror(NO, NO, NO, "reading key");
			switch (error_action) {
				case TFC_ERRACT_CONT: xerror(YES, NO, NO, "reading key"); goto _keyragain; break;
				case TFC_ERRACT_SYNC:
				case TFC_ERRACT_LSYNC:
					xerror(YES, NO, NO, "reading key");
					lio = ldone = lrem = lblock;
					memset(key, 0, lio);
					if (rdpos == NOFSIZE) lseek(kfd, lio, SEEK_CUR);
					else lseek(kfd, rdpos + lio, SEEK_SET);
					break;
				default: xerror(NO, NO, NO, "reading key"); break;
			}
		}
		if (lio && lio < lrem) {
			pblk += lio;
			lrem -= lio;
			goto _keyragain;
		}
		if (ldone < lblock) xerror(NO, YES, YES, "rawkey too small! (%zu)", ldone);

		if (ctr_mode == TFC_MODE_XTS) {
			if (xtskeyset == NO) {
				pblk = xtskey;
				xtskeyset = YES;
				goto _xts2key;
			}
		}
	}
	else if (rawkey == TFC_RAWKEY_ASKSTR) {
		tfc_yesno xtskeyset = NO;

		pblk = key; n = sizeof(key);
_xts2keyaskstr:	memset(&getps, 0, sizeof(struct getpasswd_state));
		getps.fd = getps.efd = -1;
		getps.passwd = (char *)pblk;
		getps.pwlen = n;
		getps.echo = pw_prompt ? pw_prompt : "Enter rawkey (str): ";
		getps.charfilter = (show_secrets == YES) ? getps_plain_filter : getps_filter;
		getps.maskchar = (show_secrets == YES) ? 0 : 'x';
		getps.flags = GETP_WAITFILL;
		n = xgetpasswd(&getps);
		if (n == NOSIZE) xerror(NO, NO, YES, "getting string rawkey");
		if (n == ((size_t)-2)) xexit(1);
		if (verbose) say_hint(pblk, n, "Raw string key hint");
		if (ctr_mode == TFC_MODE_XTS) {
			if (xtskeyset == NO) {
				pblk = xtskey; n = sizeof(xtskey);
				xtskeyset = YES;
				goto _xts2keyaskstr;
			}
		}
	}
	else if (rawkey == TFC_RAWKEY_ASKHEX) {
		tfc_yesno xtskeyset = NO;

		pblk = key;
_rawkey_hex_again:
		memset(&getps, 0, sizeof(struct getpasswd_state));
		getps.fd = getps.efd = -1;
		getps.passwd = pwdask;
		getps.pwlen = (TF_FROM_BITS(TFC_KEY_BITS)*2);
		getps.echo = pw_prompt ? pw_prompt : "Enter rawkey (hex): ";
		getps.charfilter = (show_secrets == YES) ? getps_plain_hex_filter : getps_hex_filter;
		getps.maskchar = (show_secrets == YES) ? 0 : 'x';
		getps.flags = GETP_WAITFILL;
		n = xgetpasswd(&getps);
		if (n == NOSIZE) xerror(NO, NO, YES, "getting hex rawkey");
		if (n == ((size_t)-2)) xexit(1);
		if (n % 2) {
			tfc_esay("Please input even number of hex digits!");
			goto _rawkey_hex_again;
		}
		hex2bin(pblk, pwdask);
		memset(pwdask, 0, sizeof(pwdask));
		if (verbose) say_hint(pblk, n/2, "Raw hex key hint");
		if (ctr_mode == TFC_MODE_XTS) {
			if (xtskeyset == NO) {
				pblk = xtskey;
				xtskeyset = YES;
				goto _rawkey_hex_again;
			}
		}
	}
	else if (password) {
_pwdagain:	memset(&getps, 0, sizeof(struct getpasswd_state));
		getps.fd = getps.efd = -1;
		getps.passwd = pwdask;
		getps.pwlen = sizeof(pwdask)-1;
		getps.echo = pw_prompt ? pw_prompt : "Enter password: ";
		getps.charfilter = (show_secrets == YES) ? getps_plain_filter : getps_filter;
		getps.maskchar = (show_secrets == YES) ? 0 : 'x';
		getps.flags = GETP_WAITFILL;
		n = xgetpasswd(&getps);
		if (n == NOSIZE) xerror(NO, NO, YES, "getting password");
		if (n == ((size_t)-2)) xexit(1);
		if (do_edcrypt == TFC_DO_ENCRYPT && no_repeat == NO) {
			getps.fd = getps.efd = -1;
			getps.passwd = pwdagain;
			getps.pwlen = sizeof(pwdagain)-1;
			getps.echo = "Enter it again: ";
			getps.flags = GETP_WAITFILL;
			n = xgetpasswd(&getps);
			if (n == NOSIZE) xerror(NO, NO, YES, "getting password again");
			if (n == ((size_t)-2)) xexit(1);
			if (strncmp(pwdask, pwdagain, sizeof(pwdagain)-1) != 0) {
				tfc_esay("Passwords are different, try again");
				goto _pwdagain;
			}
		}
		if (verbose) say_hint(pwdask, n, "Password hint");
		skein(key, TFC_KEY_BITS, mackey_opt ? mackey : NULL, pwdask, n);
		memset(pwdask, 0, sizeof(pwdask));
		memset(pwdagain, 0, sizeof(pwdagain));
	}
	else {
		if (skeinfd(key, TFC_KEY_BITS, mackey_opt ? mackey : NULL, kfd, keyoffset, maxkeylen) != YES)
			xerror(NO, NO, YES, "hashing key");
	}

	if (rawkey == NO) {
		if (tfc_saltsz > 0) {
			memcpy(tfc_salt+tfc_saltsz, key, TF_FROM_BITS(TFC_KEY_BITS));
			skein(key, TFC_KEY_BITS, mackey_opt ? mackey : NULL, tfc_salt, tfc_saltsz+TF_FROM_BITS(TFC_KEY_BITS));
		}
		if (nr_turns > 1) for (x = 0; x < nr_turns; x++)
			skein(key, TFC_KEY_BITS, mackey_opt ? mackey : NULL, key, TF_FROM_BITS(TFC_KEY_BITS));
		memset(tfc_salt, 0, TFC_MAX_SALT);
	}

	if (ctr_mode == TFC_MODE_XTS && rawkey == NO) {
		skein(xtskey, TF_NR_KEY_BITS, mackey_opt ? mackey : NULL, key, TF_FROM_BITS(TFC_KEY_BITS));
	}

	if (genkeyf) {
		int krfd;
		tfc_yesno xtskeyset = NO;

		pblk = key;
		if (!strcmp(genkeyf, "-")) krfd = 1;
		else krfd = open(genkeyf, O_WRONLY | O_CREAT | O_LARGEFILE | write_flags, 0666);
		if (krfd == -1) xerror(NO, NO, YES, "%s", genkeyf);
_xts2genkey:	if (xwrite(krfd, pblk, TF_FROM_BITS(TFC_KEY_BITS)) == NOSIZE) xerror(NO, NO, YES, "%s", genkeyf);
		if (do_fsync && fsync(krfd) == -1) xerror(NO, NO, YES, "%s", genkeyf);
		if (verbose && xtskeyset == NO) {
			tfc_esay("%s: password hashing done", progname);
			tfc_esay("%s: rawkey written to %s.", progname, genkeyf);
			tfc_esay("%s: Have a nice day!", progname);
		}

		if (ctr_mode == TFC_MODE_XTS) {
			if (xtskeyset == NO) {
				pblk = xtskey;
				xtskeyset = YES;
				goto _xts2genkey;
			}
		}

		fchmod(krfd, 0600);
		xclose(krfd);
		xexit(0);
	}

	if (iseek_blocks && (do_edcrypt == TFC_DO_DECRYPT && do_mac != NO)) {
		if (verbose) tfc_esay("%s: disabling signature verification on "
			"requested partial decryption.", progname);
		do_mac = NO;
	}

	if (do_mac != NO) {
		if (mackey_opt == TFC_MACKEY_RAWKEY) skein(mackey, TF_MAX_BITS, key, key, TF_FROM_BITS(TFC_KEY_BITS));
		if (ctr_mode < TFC_MODE_OCB) {
			if (verbose) tfc_esay("%s: doing MAC calculation, processing speed "
				"will be slower.", progname);
			if (mackey_opt) skein_init_key(&sk, mackey, macbits);
			else skein_init(&sk, macbits);
		}
	}

	if (!counter_file && counter_opt <= TFC_CTR_SHOW && ctr_mode != TFC_MODE_ECB) {
		skein(ctr, TF_TO_BITS(ctrsz), mackey_opt ? mackey : NULL, key, TF_FROM_BITS(TFC_KEY_BITS));
	}

	tf_convkey(key);
	if (ctr_mode == TFC_MODE_XTS) tf_convkey(xtskey);
	if (do_full_key == NO) {
		if (!tweakf) skein(tweak, TF_NR_TWEAK_BITS, NULL, key, TF_FROM_BITS(TFC_KEY_BITS));
		tf_tweak_set(key, tweak);
	}
	if (ctr_mode == TFC_MODE_ECB) goto _ctrskip2;

	if (counter_opt == TFC_CTR_ZERO) memset(ctr, 0, ctrsz);

	tfc_data_to_words64(&iseek_blocks, sizeof(iseek_blocks));
	tf_ctr_set(ctr, &iseek_blocks, sizeof(iseek_blocks));

	if (counter_opt == TFC_CTR_SHOW) {
		switch (do_outfmt) {
			case TFC_OUTFMT_B64: tfc_printbase64(stderr, ctr, ctrsz, YES); break;
			case TFC_OUTFMT_RAW: xwrite(2, ctr, ctrsz); break;
			case TFC_OUTFMT_HEX: mehexdump(ctr, ctrsz, ctrsz, YES); break;
		}
	}
	else if (counter_opt == TFC_CTR_RAND) tfc_getrandom(ctr, ctrsz);

_ctrskip2:
	if (kfd != -1) {
		xclose(kfd);
		kfd = -1;
	}
	if (verbose) tfc_esay("%s: password hashing done", progname);

	if (overwrite_source && srcfname) argv[idx] = srcfname;

_plain:
	if (argv[idx]) {
		if (!strcmp(argv[idx], "-")) dfd = 1;
		else dfd = open(argv[idx], O_RDWR | O_LARGEFILE | write_flags, 0666);
		if (dfd == -1) {
			dfd = open(argv[idx], O_WRONLY | O_CREAT | O_LARGEFILE | write_flags, 0666);
			if (dfd == -1) xerror(NO, NO, YES, "%s", argv[idx]);
		}
		dstfname = argv[idx];
		idx++;
	}

	if (oseek) {
		if (lseek(dfd, oseek, SEEK_SET) == -1)
			xerror(ignore_seek_errors, NO, NO, "%s: seek failed", dstfname);
	}

	for (x = 1; x < NSIG; x++) signal(x, SIG_IGN);
	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_flags = SA_RESTART;
	sigact.sa_handler = print_crypt_status;
	sigaction(SIGUSR1, &sigact, NULL);
	sigaction(SIGTSTP, &sigact, NULL);
	sigaction(SIGALRM, &sigact, NULL);
	if (status_timer) setup_next_alarm(status_timer);
	sigact.sa_handler = change_status_width;
	sigaction(SIGQUIT, &sigact, NULL);
	sigact.sa_handler = change_status_timer;
	sigaction(SIGUSR2, &sigact, NULL);
	if (quiet == NO) {
		sigact.sa_handler = print_crypt_status;
		sigaction(SIGINT, &sigact, NULL);
		sigaction(SIGTERM, &sigact, NULL);
	}
	else {
		sigact.sa_handler = exit_sigterm;
		sigaction(SIGINT, &sigact, NULL);
		sigaction(SIGTERM, &sigact, NULL);
	}
	memset(&sigact, 0, sizeof(struct sigaction));

	tfc_getcurtime(&delta_time);

	errno = 0;
	if (counter_opt == TFC_CTR_RAND && ctr_mode != TFC_MODE_ECB) {
		pblk = ctr;
		lio = lrem = ctrsz;
		ldone = 0;
_ctrwagain:	lio = xwrite(dfd, pblk, lrem);
		if (lio != NOSIZE) ldone += lio;
		else xerror(NO, NO, NO, "%s", dstfname);
		if (do_fsync && fsync(dfd) == -1) xerror(NO, NO, NO, "%s", dstfname);
		if (lio < lrem) {
			pblk += lio;
			lrem -= lio;
			goto _ctrwagain;
		}
		total_processed_dst += ldone;
		delta_processed += ldone;
	}

	if (ctr_mode == TFC_MODE_STREAM) tfe_init_iv(&tfe, key, ctr);

	errno = 0;
	do_stop = NO;
	while (1) {
		if (do_stop) break;
		pblk = srcblk;
		ldone = 0;
		lrem = lblock = blk_len_adj(maxlen, total_processed_src, blksize);
		if (error_action == TFC_ERRACT_SYNC) rdpos = tfc_fdgetpos(sfd);
_ragain:	lio = xread(sfd, pblk, lrem);
		if (lio == 0) do_stop = YES;
		if (lio != NOSIZE) ldone += lio;
		else {
			if (errno != EIO && catch_all_errors != YES)
				xerror(NO, NO, NO, "%s", srcfname);
			switch (error_action) {
				case TFC_ERRACT_CONT: xerror(YES, NO, NO, "%s", srcfname); goto _ragain; break;
				case TFC_ERRACT_SYNC:
				case TFC_ERRACT_LSYNC:
					xerror(YES, NO, NO, "%s", srcfname);
					lio = ldone = lrem = lblock;
					memset(srcblk, 0, lio);
					if (rdpos == NOFSIZE) lseek(sfd, lio, SEEK_CUR);
					else lseek(sfd, rdpos + lio, SEEK_SET);
					break;
				default: xerror(NO, NO, NO, "%s", srcfname); break;
			}
		}
		if (lio && lio < lrem) {
			pblk += lio;
			lrem -= lio;
			goto _ragain;
		}
		total_processed_src += ldone;

		if (do_pad && (ldone % TF_BLOCK_SIZE)) {
			size_t orig = ldone;
			ldone += (TF_BLOCK_SIZE - (ldone % TF_BLOCK_SIZE));
			if (ldone > blksize) ldone = blksize;
			memset(srcblk+orig, 0, sizeof(srcblk)-orig);
		}

		if (do_mac == TFC_MAC_SIGN && ctr_mode < TFC_MODE_OCB)
			skein_update(&sk, srcblk, ldone);

		if (ctr_mode == TFC_MODE_CTR) tf_ctr_crypt(key, ctr, dstblk, srcblk, ldone);
		else if (ctr_mode == TFC_MODE_STREAM) tf_stream_crypt(&tfe, dstblk, srcblk, ldone);
		else if (ctr_mode == TFC_MODE_XTS && do_edcrypt == TFC_DO_ENCRYPT)
			tf_xts_encrypt(key, xtskey, ctr, dstblk, srcblk, ldone, xtsblocks);
		else if (ctr_mode == TFC_MODE_XTS && do_edcrypt == TFC_DO_DECRYPT)
			tf_xts_decrypt(key, xtskey, ctr, dstblk, srcblk, ldone, xtsblocks);
		else if (ctr_mode == TFC_MODE_ECB && do_edcrypt == TFC_DO_ENCRYPT)
			tf_ecb_encrypt(key, dstblk, srcblk, ldone);
		else if (ctr_mode == TFC_MODE_ECB && do_edcrypt == TFC_DO_DECRYPT)
			tf_ecb_decrypt(key, dstblk, srcblk, ldone);
		else if (ctr_mode == TFC_MODE_CBC && do_edcrypt == TFC_DO_ENCRYPT)
			tf_cbc_encrypt(key, ctr, dstblk, srcblk, ldone);
		else if (ctr_mode == TFC_MODE_CBC && do_edcrypt == TFC_DO_DECRYPT)
			tf_cbc_decrypt(key, ctr, dstblk, srcblk, ldone);

		else if (ctr_mode == TFC_MODE_OCB && do_edcrypt == TFC_DO_ENCRYPT)
			tf_ocb_encrypt(key, ctr, dstblk, do_mac == TFC_MAC_SIGN ? macresult : NULL, srcblk, ldone, xtsblocks);
		else if (ctr_mode == TFC_MODE_OCB && do_edcrypt == TFC_DO_DECRYPT)
			tf_ocb_decrypt(key, ctr, dstblk, do_mac >= TFC_MAC_VRFY ? macresult : NULL, srcblk, ldone, xtsblocks);

		else if (ctr_mode == TFC_MODE_PLAIN)
			memcpy(dstblk, srcblk, ldone);

		if (do_mac >= TFC_MAC_VRFY && ctr_mode < TFC_MODE_OCB)
			skein_update(&sk, dstblk, ldone);
		if (do_mac == TFC_MAC_JUST_VRFY) goto _nowrite;

		pblk = dstblk;
		lrem = ldone;
		ldone = 0;
_wagain:	lio = xwrite(dfd, pblk, lrem);
		if (lio != NOSIZE) ldone += lio;
		else xerror(NO, NO, NO, "%s", dstfname);
		if (do_fsync && fsync(dfd) == -1) xerror(NO, NO, NO, "%s", dstfname);
		if (lio < lrem) {
			pblk += lio;
			lrem -= lio;
			goto _wagain;
		}
_nowrite:	total_processed_dst += ldone;
		delta_processed += ldone;

		if (maxlen != NOFSIZE && total_processed_src >= maxlen) break;
	}

	errno = 0;
	if (do_mac >= TFC_MAC_VRFY) {
		if (!do_mac_file) {
			pblk = macvrfy;
			ldone = 0;
			lrem = lblock = TF_FROM_BITS(macbits);
			if (error_action == TFC_ERRACT_SYNC) rdpos = tfc_fdgetpos(sfd);
_macragain:		lio = xread(sfd, pblk, lrem);
			if (lio != NOSIZE) ldone += lio;
			else {
				if (errno != EIO && catch_all_errors != YES)
					xerror(NO, NO, NO, "%s", srcfname);
				switch (error_action) {
					case TFC_ERRACT_CONT: xerror(YES, NO, NO, "%s", srcfname); goto _macragain; break;
					case TFC_ERRACT_SYNC:
					case TFC_ERRACT_LSYNC:
						xerror(YES, NO, NO, "%s", srcfname);
						lio = ldone = lrem = lblock;
						memset(macvrfy, 0, lio);
						if (rdpos == NOFSIZE) lseek(sfd, lio, SEEK_CUR);
						else lseek(sfd, rdpos + lio, SEEK_SET);
						break;
					default: xerror(NO, NO, NO, "%s", srcfname); break;
				}
			}
			if (lio && lio < lrem) {
				pblk += lio;
				lrem -= lio;
				goto _macragain;
			}
			total_processed_src += ldone;
		}
		else {
			int mfd;

			if (!strcmp(do_mac_file, "-")) mfd = 0;
			else mfd = open(do_mac_file, O_RDONLY | O_LARGEFILE);
			if (mfd == -1) xerror(YES, NO, NO, "%s", do_mac_file);
			lio = ldone = xread(mfd, tmpdata, sizeof(tmpdata));
			if (lio == NOSIZE) xerror(NO, NO, YES, "%s", do_mac_file);
			if (!memcmp(tmpdata, TFC_ASCII_TFC_MAC_FOURCC, TFC_ASCII_TFC_MAC_FOURCC_LEN)) {
				memmove(tmpdata, tmpdata+TFC_ASCII_TFC_MAC_FOURCC_LEN,
					sizeof(tmpdata)-TFC_ASCII_TFC_MAC_FOURCC_LEN);
				lio = TF_FROM_BITS(macbits);
				base64_decode((char *)macvrfy, lio, (char *)tmpdata, sizeof(tmpdata));
			}
			else memcpy(macvrfy, tmpdata, TF_FROM_BITS(macbits));
			xclose(mfd);
		}

		if (ldone < TF_FROM_BITS(macbits)) {
			if (quiet == NO) tfc_esay("%s: short signature (%zu), "
				"not verifying", progname, ldone);
			exitcode = 1;
			goto _shortmac;
		}

		if (ctr_mode < TFC_MODE_OCB) skein_final(macresult, &sk);
		else skein(macresult, macbits, mackey, macresult, TF_FROM_BITS(macbits));

		if (ctr_mode == TFC_MODE_CTR) tf_ctr_crypt(key, ctr, tmpdata, macvrfy, TF_FROM_BITS(macbits));
		else if (ctr_mode == TFC_MODE_STREAM) tf_stream_crypt(&tfe, tmpdata, macvrfy, TF_FROM_BITS(macbits));
		else if (ctr_mode == TFC_MODE_XTS) tf_xts_decrypt(key, xtskey, ctr, tmpdata, macvrfy, TF_FROM_BITS(macbits), xtsblocks);
		else if (ctr_mode == TFC_MODE_ECB) tf_ecb_decrypt(key, tmpdata, macvrfy, TF_FROM_BITS(macbits));
		else if (ctr_mode == TFC_MODE_CBC) tf_cbc_decrypt(key, ctr, tmpdata, macvrfy, TF_FROM_BITS(macbits));
		else if (ctr_mode == TFC_MODE_OCB) tf_ocb_decrypt(key, ctr, tmpdata, NULL, macvrfy, TF_FROM_BITS(macbits), xtsblocks);

		if (!memcmp(tmpdata, macresult, TF_FROM_BITS(macbits))) {
			if (quiet == NO) {
				tfc_esay("%s: signature is good", progname);
				if (verbose) {
					if (do_outfmt == TFC_OUTFMT_B64) tfc_printbase64(stderr, macresult, TF_FROM_BITS(macbits), YES);
					else mehexdump(macresult, TF_FROM_BITS(macbits), TF_FROM_BITS(macbits), YES);
				}
			}
		}
		else {
			if (quiet == NO) tfc_esay("%s: signature is BAD: "
				"wrong password, key, mode, or file is not signed", progname);
			exitcode = 1;
		}

_shortmac:	memset(macvrfy, 0, sizeof(macvrfy));
		memset(macresult, 0, sizeof(macresult));
		memset(tmpdata, 0, sizeof(tmpdata));
	}

	else if (do_mac == TFC_MAC_SIGN) {
		if (ctr_mode < TFC_MODE_OCB) skein_final(macresult, &sk);
		else skein(macresult, macbits, mackey, macresult, TF_FROM_BITS(macbits));

		if (ctr_mode == TFC_MODE_CTR) tf_ctr_crypt(key, ctr, tmpdata, macresult, TF_FROM_BITS(macbits));
		else if (ctr_mode == TFC_MODE_STREAM) tf_stream_crypt(&tfe, tmpdata, macresult, TF_FROM_BITS(macbits));
		else if (ctr_mode == TFC_MODE_XTS) tf_xts_encrypt(key, xtskey, ctr, tmpdata, macresult, TF_FROM_BITS(macbits), xtsblocks);
		else if (ctr_mode == TFC_MODE_ECB) tf_ecb_encrypt(key, tmpdata, macresult, TF_FROM_BITS(macbits));
		else if (ctr_mode == TFC_MODE_CBC) tf_cbc_encrypt(key, ctr, tmpdata, macresult, TF_FROM_BITS(macbits));
		else if (ctr_mode == TFC_MODE_OCB) tf_ocb_encrypt(key, ctr, tmpdata, NULL, macresult, TF_FROM_BITS(macbits), xtsblocks);
		memset(macresult, 0, sizeof(macresult));

		if (!do_mac_file) {
			pblk = tmpdata;
			lio = lrem = TF_FROM_BITS(macbits);
			ldone = 0;
_macwagain:		lio = xwrite(dfd, pblk, lrem);
			if (lio != NOSIZE) ldone += lio;
			else xerror(NO, NO, NO, "%s", dstfname);
			if (do_fsync && fsync(dfd) == -1) xerror(NO, NO, NO, "%s", dstfname);
			if (lio < lrem) {
				pblk += lio;
				lrem -= lio;
				goto _macwagain;
			}
			total_processed_dst += ldone;
			delta_processed += ldone;
		}
		else {
			int mfd;

			if (!strcmp(do_mac_file, "-")) mfd = 1;
			else mfd = open(do_mac_file, O_WRONLY | O_CREAT | O_LARGEFILE | write_flags, 0666);
			if (mfd == -1) xerror(YES, NO, NO, "%s", do_mac_file);
			if (do_outfmt == TFC_OUTFMT_B64) {
				memcpy(macvrfy, tmpdata, TF_FROM_BITS(macbits));
				memset(tmpdata, 0, TFC_TMPSIZE);
				memcpy(tmpdata, TFC_ASCII_TFC_MAC_FOURCC, TFC_ASCII_TFC_MAC_FOURCC_LEN);
				base64_encode((char *)tmpdata+TFC_ASCII_TFC_MAC_FOURCC_LEN, (char *)macvrfy, TF_FROM_BITS(macbits));
				lrem = strnlen((char *)tmpdata, sizeof(tmpdata));
				if (lrem) {
					tmpdata[lrem] = '\n';
					lrem++;
				}
				lio = xwrite(mfd, tmpdata, lrem);
			}
			else lio = xwrite(mfd, tmpdata, TF_FROM_BITS(macbits));
			if (lio == NOSIZE) xerror(NO, NO, YES, "%s", do_mac_file);
			if (do_fsync && fsync(mfd) == -1) xerror(NO, NO, YES, "%s", do_mac_file);
			xclose(mfd);
		}

		memset(macvrfy, 0, sizeof(macvrfy));
		memset(macresult, 0, sizeof(macresult));
		memset(tmpdata, 0, sizeof(tmpdata));
	}

	if (verbose || status_timer || do_stop == YES) print_crypt_status(0);

	if (do_preserve_time) fcopy_matime(dfd, &s_stat);
	xclose(sfd);
	if (do_ftrunc > TFC_NO_FTRUNC) {
		if (do_ftrunc == TFC_FTRUNC_TAIL) ftrunc_dfd = total_processed_dst;
		if (ftruncate(dfd, (off_t)ftrunc_dfd) == -1) xerror(YES, NO, YES, "ftruncate(%d)", dfd);
	}
	xclose(dfd);

	xexit(exitcode);
	return -1;
}
