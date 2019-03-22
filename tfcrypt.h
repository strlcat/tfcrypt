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

#ifndef _TFCRYPT_H
#define _TFCRYPT_H

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#ifndef _TFCRYPT_VERSION
#error Version number may help you to identify missing functionality.
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <libgen.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <stdint.h>

typedef void (*sighandler_t)(int);

#include "base64.h"
#include "getpasswd.h"
#include "tfdef.h"
#include "skein.h"
#include "tfe.h"
#include "tfprng.h"

typedef short tfc_yesno;
typedef TF_BYTE_TYPE tfc_byte;
typedef unsigned long long tfc_fsize;
typedef unsigned long long tfc_useconds;

#ifndef TFC_BLKSIZE
#define TFC_BLKSIZE 65536
#endif

#ifndef TFC_MAX_SALT
#define TFC_MAX_SALT (2048 + TF_KEY_SIZE)
#endif

#ifndef TFC_XTSBLOCKS
#define TFC_XTSBLOCKS 32
#endif

#ifndef TFC_B64_WIDTH
#define TFC_B64_WIDTH 76
#endif
#define TFC_B64_EWIDTH (TFC_B64_WIDTH - (TFC_B64_WIDTH / 4))
#define TFC_B64_DWIDTH TFC_BLKSIZE

#define NOSIZE ((size_t)-1)
#define NOFSIZE ((tfc_fsize)-1)
#define TFC_ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

#define TFC_KEY_BITS (do_tfcrypt1 == YES ? TF_MAX_BITS : TF_NR_KEY_BITS)

#define TFC_ASCII_TFC_MAC_FOURCC "%TF"
#define TFC_ASCII_TFC_MAC_FOURCC_LEN (sizeof(TFC_ASCII_TFC_MAC_FOURCC)-1)

#define TFC_U(x) ((unsigned)x)
#define TFC_DTOUSECS(x) ((x) * 1000000.0)
#define TFC_UTODSECS(x) ((x) / 1000000.0)

#define TFC_DEFAULT_RANDSOURCE "/dev/urandom"
#define TFC_STDIN_NAME "(stdin)"
#define TFC_STDOUT_NAME "(stdout)"

#define TFC_TMPSIZE	(TF_BLOCK_SIZE * 4)

int xmhexdump(int to, const void *data, size_t szdata, int hgroup, int hexstr, int newline);
#define mhexdump(data, szdata, group, newline) xmhexdump(1, data, szdata, group, do_full_hexdump, newline)
#define mehexdump(data, szdata, group, newline) xmhexdump(2, data, szdata, group, do_full_hexdump, newline)

size_t xstrlcpy(char *dst, const char *src, size_t size);
size_t xstrlcat(char *dst, const char *src, size_t size);

extern size_t nr_turns;
extern int ctr_mode;
extern size_t macbits;
extern size_t tfc_saltsz;
extern tfc_byte tfc_salt[TFC_MAX_SALT];

extern char *progname;
extern int exitcode;
extern tfc_byte key[TF_KEY_SIZE], ctr[TF_BLOCK_SIZE], xtskey[TF_KEY_SIZE], mackey[TF_FROM_BITS(TF_MAX_BITS)];
extern struct skein sk;
extern struct tfe_stream tfe;
extern tfc_byte srcblk[TFC_BLKSIZE], dstblk[TFC_BLKSIZE], *pblk;
extern tfc_byte macvrfy[SKEIN_DIGEST_SIZE], macresult[SKEIN_DIGEST_SIZE];
extern tfc_byte tmpdata[TFC_TMPSIZE];
extern char *randsource;
extern tfc_fsize iseek_blocks, iseek, oseek, maxlen;
extern tfc_fsize total_processed_src, total_processed_dst;
extern tfc_fsize delta_processed;
extern tfc_fsize genrandom_nr_bytes, genzero_nr_bytes;
extern tfc_fsize rdpos;
extern tfc_fsize maxkeylen, keyoffset;
extern int sfd, kfd, dfd;
extern struct stat s_stat;
extern size_t blksize, xtsblocks;
extern char pwdask[512], pwdagain[512];
extern size_t lio, lrem, ldone, lblock;
extern size_t ctrsz;
extern struct sigaction sigact;
extern size_t sksum_turns;
extern int do_edcrypt, do_stop, quiet, error_action;
extern int counter_opt, mackey_opt, do_mac, do_outfmt, rawkey;
extern int idx, write_flags;
extern tfc_yesno catch_all_errors, ignore_seek_errors, password, overwrite_source, do_fsync, do_pad, do_tfcrypt1;
extern tfc_yesno do_preserve_time, do_stats_in_gibs, do_statline_dynamic, do_less_stats;
extern tfc_yesno no_repeat, do_full_hexdump, verbose, statline_was_shown;
extern char *srcfname, *dstfname, *do_mac_file, *counter_file, *sksum_hashlist_file;
extern char *saltf, *genkeyf, *mackeyf, *tweakf;
extern char *pw_prompt, *mac_pw_prompt;
extern tfc_useconds status_timer, bench_timer;
extern tfc_useconds current_time, delta_time;
extern struct getpasswd_state getps;

size_t xread(int fd, void *data, size_t szdata);
size_t xwrite(int fd, const void *data, size_t szdata);

void xerror(tfc_yesno noexit, tfc_yesno noerrno, tfc_yesno nostats, const char *fmt, ...);
void xexit(int status);
void usage(void);

void tfc_vfsay(FILE *where, tfc_yesno addnl, const char *fmt, va_list ap);
void tfc_nfsay(FILE *where, const char *fmt, ...);
void tfc_esay(const char *fmt, ...);
void tfc_say(const char *fmt, ...);

void tfc_printbase64(FILE *where, const void *p, size_t n, tfc_yesno nl);
void tfc_data_to_words64(void *data, size_t szdata);
tfc_fsize tfc_humanfsize(const char *s, char **stoi);
const char *tfc_getscale(int scale);
void tfc_describescale(tfc_fsize num, double *w, int *scale);
size_t blk_len_adj(tfc_fsize filelen, tfc_fsize read_already, size_t blklen);
tfc_yesno xor_shrink(void *dst, size_t szdst, const void *src, size_t szsrc);
tfc_yesno str_empty(const char *str);
void xclose(int fd);
const char *tfc_modename(int mode);
void tfc_getcurtime(tfc_useconds *tx);
tfc_fsize tfc_fdsize(int fd);
tfc_fsize tfc_fdgetpos(int fd);
tfc_fsize tfc_fnamesize(char *fname, tfc_yesno noexit);
tfc_fsize tfc_modifysize(tfc_fsize szmodify, const char *szspec);
void fcopy_matime(int fd, const struct stat *st);
tfc_yesno xfgets(char *s, size_t n, FILE *f);
tfc_yesno isbase64(const char *s);
void hex2bin(void *d, const char *s);
void tfc_finirandom(void);
void tfc_getrandom(void *buf, size_t sz);
void exit_sigterm(int signal);
void print_crypt_status(int signal);
void change_status_width(int signal);
void change_status_timer(int signal);
void setup_next_alarm(tfc_useconds useconds);
void skein(void *hash, size_t bits, const void *key, const void *data, size_t szdata);
void tf_key_tweak_compat(void *key);
tfc_yesno skeinfd(void *hash, size_t bits, const void *key, int fd, tfc_fsize offset, tfc_fsize readto);

void read_defaults(const char *path, tfc_yesno noerr);

void gen_write_bytes(const char *foutname, tfc_fsize offset, tfc_fsize nrbytes);
void do_edbase64(char **fargv);
void do_sksum(char *spec, char **fargv);
void do_benchmark(tfc_useconds useconds, double dseconds);

enum { NO, YES };

enum { TFC_ERRACT_EXIT, TFC_ERRACT_CONT, TFC_ERRACT_SYNC, TFC_ERRACT_LSYNC };
enum { TFC_STOP_BEGAN = 1, TFC_STOP_FULL };
enum { TFC_DO_PLAIN, TFC_DO_ENCRYPT, TFC_DO_DECRYPT };
enum { TFC_MAC_DROP = -1, TFC_MAC_SIGN = 1, TFC_MAC_VRFY, TFC_MAC_JUST_VRFY };
enum { TFC_MACKEY_RAWKEY = 1, TFC_MACKEY_PASSWORD, TFC_MACKEY_FILE };
enum { TFC_RAWKEY_KEYFILE = 1, TFC_RAWKEY_ASKSTR, TFC_RAWKEY_ASKHEX };
enum { TFC_OUTFMT_HEX = 1, TFC_OUTFMT_B64, TFC_OUTFMT_RAW };
enum {
	TFC_MODE_SKSUM = -2, TFC_MODE_PLAIN = -1, TFC_MODE_CTR = 1,
	TFC_MODE_STREAM, TFC_MODE_XTS, TFC_MODE_ECB, TFC_MODE_CBC, TFC_MODE_OCB
};
enum { TFC_CTR_SHOW = 1, TFC_CTR_HEAD, TFC_CTR_RAND, TFC_CTR_ZERO };

#endif
