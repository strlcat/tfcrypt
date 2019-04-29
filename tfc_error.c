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

void xerror(tfc_yesno noexit, tfc_yesno noerrno, tfc_yesno nostats, const char *fmt, ...)
{
	va_list ap;
	char *s;

	if (quiet) goto _ex;

	va_start(ap, fmt);

	if (statline_was_shown == YES && do_statline_dynamic == YES) tfc_esay("\n");

	tfc_nfsay(stderr, "%s: ", progname);
	tfc_vfsay(stderr, NO, fmt, ap);
	if (errno && noerrno == NO) {
		s = strerror(errno);
		tfc_esay(": %s", s);
	}
	else tfc_esay("\n");

	va_end(ap);

	if (nostats == NO) print_crypt_status(-1);

_ex:
	if (noexit == YES) {
		errno = 0;
		return;
	}

	xexit(2);
}

void xexit(int status)
{
	memset(srcblk, 0, sizeof(srcblk));
	memset(dstblk, 0, sizeof(dstblk));

	memset(key, 0, sizeof(key));
	memset(ctr, 0, sizeof(ctr));
	memset(mackey, 0, sizeof(mackey));
	memset(xtskey, 0, sizeof(xtskey));
	memset(tweak, 0, sizeof(tweak));
	memset(&sk, 0, sizeof(struct skein));
	memset(&tfe, 0, sizeof(struct tfe_stream));

	tfc_finirandom();

	memset(macvrfy, 0, sizeof(macvrfy));
	memset(macresult, 0, sizeof(macresult));

	memset(tmpdata, 0, sizeof(tmpdata));
	memset(&getps, 0, sizeof(struct getpasswd_state));
	memset(pwdask, 0, sizeof(pwdask));
	memset(pwdagain, 0, sizeof(pwdagain));

	exit(status);
}

void usage(void)
{
	tfc_yesno is_embedded_prog = NO;

	if (optopt == 'V') {
		char shash[64];
		tfc_say("tfcrypt toolkit, version %s.", _TFCRYPT_VERSION);
		hash_defaults(shash, sizeof(shash));
		tfc_say("Defaults hash: %s", shash);
		memset(shash, 0, sizeof(shash));
		xexit(0);
	}

	if ((strlen(progname) <= 9)
	&& ((!strcmp(progname, "sksum"))
	|| ((!memcmp(progname, "sk", 2))
	&& (!memcmp(progname+3, "sum", 3)
	|| !memcmp(progname+4, "sum", 3)
	|| !memcmp(progname+5, "sum", 3)
	|| !memcmp(progname+6, "sum", 3))))) {
		is_embedded_prog = YES;
		tfc_say("usage: %s [-AW] [-D BITS] [-n TURNS] [-l length] [-c <file>] [-U <file>] [source] ...", progname);
		tfc_say("\n");
		tfc_say("%s: calculate and print Skein hashsum of stream.", progname);
		tfc_say("  -D BITS: specify bits as it was skBITSsum.");
		tfc_say("  -n TURNS: number of turns to perform in Skein function.");
		tfc_say("    sksum defaults to just one in all modes.");
		tfc_say("  -A: format checksum in base64 rather than in binary hex.");
		tfc_say("  -W: output raw binary checksum and remove filename(s) from output.");
		tfc_say("  -H: output small hexdump (hex string and ASCII printable characters).");
		tfc_say("  -l length: read only these first bytes of source.");
		tfc_say("  -c <file>: read hashes list from file and check them.");
		tfc_say("  -U <file>: read Skein MAC key from file.");
		tfc_say("multiple sources can be given in cmdline, and if one of");
		tfc_say("them is specified as \"-\", then reads are performed from stdin.");
		tfc_say("\n");
	}
	else if (!strcmp(progname, "base64")) {
		is_embedded_prog = YES;
		tfc_say("usage: %s [-ed] [source] [output]", progname);
		tfc_say("\n");
		tfc_say("tfcrypt embedded base64 encoder/decoder.");
		tfc_say("  -e: encode stream into base64.");
		tfc_say("  -d: decode base64 stream.");
		tfc_say("no error checking is performed.");
		tfc_say("\n");
	}
	else if (!strcmp(progname, "tfbench")) {
		is_embedded_prog = YES;
		tfc_say("usage: %s seconds", progname);
		tfc_say("do an in-memory random data benchmark of Threefish.");
		tfc_say("\n");
	}

	if (is_embedded_prog) {
		tfc_say("This program is physical part of tfcrypt toolkit.");
		tfc_say("(see it's version with %s -V)", progname);
		tfc_say("Please note that other tfcrypt options are either ignored there,");
		tfc_say("or result of using them is undefined and it's not a bug.");

		xexit(1);
	}

	tfc_say("usage: %s [opts] [--] [key] [source] [output]", progname);
	tfc_say("\n");
	tfc_say("tfcrypt toolkit: encrypt streams with Threefish in CTR mode,");
	tfc_say("calculate and check Skein hashsums, generate CSPRNG quality random data,");
	tfc_say("convert encrypted data into ASCII format to ease transmission.");
	tfc_say("\n");
	tfc_say("  -e, -d: encrypt, decrypt (it maybe required).");
	tfc_say("  -L <file>: load tfcrypt defaults from file.");
	tfc_say("    defaults is text file which defines salt, nr_turns and default mode.");
	tfc_say("  -s <file>: load tfcrypt salt from file.");
	tfc_say("  -s disable: disable key salting at all.");
	tfc_say("  -p: instead of using key, ask for password.");
	tfc_say("  -k: use raw (%u byte) key instead of deriving it from arbitrary data.", TFC_U(TF_KEY_SIZE));
	tfc_say("  -z: ask for key in plain C string form through password asker.");
	tfc_say("  -x: ask for key in hex string form through password asker.");
	tfc_say("  -K <file>: generate key from keyfile or password and write it to file.");
	tfc_say("  -t <file>: use (raw) tweak from file.");
	tfc_say("  -w: overwrite source file. If not file, ignored.");
	tfc_say("  -n TURNS: number of turns to perform in Skein function.");
	tfc_say("    Default is always defined when building tfcrypt.");
	tfc_say("  -C mode: mode of operation: CTR, STREAM, XTS, ECB, CBC, OCB.");
	tfc_say("    Default encryption mode can be changed when building tfcrypt.");
	tfc_say("  -c opt: initial CTR value initialisation mode:");
	tfc_say("    show: do default action, then dump CTR value to stderr,");
	tfc_say("    head: when decrypting, read CTR from beginning of stream,");
	tfc_say("    rand: generate random CTR and write it to beginning of stream,");
	tfc_say("    zero: assume zero CTR is used, do not read from and write it to stream,");
	tfc_say("    hexc:nr[,hexc:nr,...]: construct counter from given pattern.");
	tfc_say("      Example: \"ff:124,08:2,80:2\" will fill counter first with 124 0xff bytes,");
	tfc_say("      then with 2 0x08 bytes, then 2 0x80 bytes. To fill with zeroes, it is");
	tfc_say("      simple to specify just a \"0:128\" as a pattern. Note that bytes that");
	tfc_say("      exceed CTR space will be just dropped, and any unused bytes are set to zeroes.");
	tfc_say("    <file>: read CTR from given file (both when encrypting/decrypting).");
	tfc_say("      default is to derive CTR from user provided password or keyfile with");
	tfc_say("      a single Skein function turn over derived, %u byte raw key", TFC_U(TF_KEY_SIZE));
	tfc_say("  -q: always be quiet, never tell anything (except when signaled).");
	tfc_say("  -v: print number of read and written encrypted bytes, and explain stages.");
	tfc_say("  -V seconds: activate timer that will repeatedly print statistics to stderr.");
	tfc_say("  -a: shortcut of -O xtime.");
	tfc_say("  -r <file>: specify random source instead of /dev/urandom.");
	tfc_say("  -R nr_bytes: generate nr_bytes of random bytes suitable for use as key data.");
	tfc_say("    -R also supports these aliases specified instead of nr_bytes:");
	tfc_say("    cbs: output fixed maximum crypt block size (%u bytes),", TFC_U(TF_BLOCK_SIZE));
	tfc_say("    ks: output fixed maximum crypt key size (%u bytes)", TFC_U(TF_KEY_SIZE));
	tfc_say("    xks: output fixed maximum crypt XTS key size (%u bytes)", TFC_U(TF_KEY_SIZE*2));
	tfc_say("    iobs: output %s builtin block size TFC_BLKSIZE (%u bytes),", progname, TFC_U(TFC_BLKSIZE));
	tfc_say("    if nr_bytes is not a valid number or alias, this string will be");
	tfc_say("    used to attempt to open it as file, and examine it's size.");
	tfc_say("    Then this examined size will be set as nr_bytes to output.");
	tfc_say("  -Z nr_bytes: like -R, but emit zero stream instead of random.");
	tfc_say("  -D MACBITS: specify bit width of a MAC signature.");
	tfc_say("  -U key/pwd/<file>: read Skein MAC key from file.");
	tfc_say("    key: use primary encryption rawkey as a MAC key.");
	tfc_say("    pwd: ask for password string that will be used as MAC key.");
	tfc_say("  -S MAC: append MAC signature to end of file:");
	tfc_say("    MAC: embed MAC signature into file itself at the end,");
	tfc_say("    <file>: write a detached MAC signature into separate <file>,");
	tfc_say("    -: write a detached MAC signature to stdout.");
	tfc_say("    useful only with variable length files! For block devices,");
	tfc_say("    specify a separate file name to save signature to: -S file.");
	tfc_say("  -A: format raw binary data, like MAC signature or Skein hash, in base64.");
	tfc_say("  -W: output pure binary data, and disable any strings addition in Skein.");
	tfc_say("  -H: output small hexdump (hex string and ASCII printable characters).");
	tfc_say("  -M MAC: verify attached MAC signature when decrypting a file:");
	tfc_say("    MAC: embed MAC signature into file itself at the end,");
	tfc_say("    <file>: write a detached MAC signature into separate <file>,");
	tfc_say("    -: read a detached MAC signature from stdin,");
	tfc_say("    drop: do not verify attached MAC, if any, and drop it from output.");
	tfc_say("  -m: just verify MAC provided with -M. Do not write output file.");
	tfc_say("    This option must be specified after -M.");
	tfc_say("  -E how: how to behave on I/O errors (both src or dst):");
	tfc_say("    exit: print error if not quiet, then exit,");
	tfc_say("    cont: print error if not quiet, then continue,");
	tfc_say("      no action to pad missing data is attempted.");
	tfc_say("      may be dangerous when working with block devices.");
	tfc_say("    sync: print error if not quiet, then continue,");
	tfc_say("      pad missing data block with zeroes.");
	tfc_say("    lsync: same as sync, but does not use SEEK_SET logic,");
	tfc_say("      lsync uses only relative seek operations, and does not prequery");
	tfc_say("      the current file position for exact offsets, which maybe unsafe.");
	tfc_say("      For this reason, it is HIGHLY recommended to use sync instead!");
	tfc_say("      Note that both sync and lsync work only with read errors!");
	tfc_say("  default error action is exit with printing status if not quiet.");
	tfc_say("  -E xall: turn on error actions above for all errors, not just EIO errors.");
	tfc_say("  -E xseek: ignore positioning and other seek related errors.");
	tfc_say("    Multiple -E specifiers may be given in separate options.");
	tfc_say("  -O opts: set options (comma separated list):");
	tfc_say("    sync: request a synchronous I/O for a output,");
	tfc_say("    fsync: on each write() call a corresponding fsync(fd),");
	tfc_say("    trunc: open(O_WRONLY) will truncate output file to zero size.");
	tfc_say("    pad: pad incomplete (l.t. %u bytes) block with zeroes.", TFC_U(TF_BLOCK_SIZE));
	tfc_say("    xtime: copy timestamps from source to destination files.");
	tfc_say("    gibsize: use SI units of size: 1k = 1000. Applies only to size prefixes.");
	tfc_say("    Computers convention is to use 1024, whereas SI/hdd measure in 1000.");
	tfc_say("    plainstats: force status line to be plain: no fancy dynamic stuff.");
	tfc_say("    Dynamic line works well only on VT100 compatible ttys, and");
	tfc_say("    when the whole status line width is smaller than tty width.");
	tfc_say("    statless: emit less information in status line (only processed data).");
	tfc_say("    norepeat: do not ask for any possible password confirmations.");
	tfc_say("    showsecrets: show passwords in plaintext instead of masking them.");
	tfc_say("    prompt=str: set main password prompts to this string.");
	tfc_say("    macprompt=str: set MAC password prompts to this string.");
	tfc_say("    shorthex: with -H, do not print printable characters, dump only hex string.");
	tfc_say("    iobs=val: set IO block size value. Must not exceed %u bytes.", TFC_U(TFC_BLKSIZE));
	tfc_say("    xtsblocks=val: use these nr of TF blocks per XTS block. Default is %u.", TFC_U(TFC_XTSBLOCKS));
	tfc_say("    iseek=val: seek source file/device by these val bytes.");
	tfc_say("    Initial counter is adjusted automatically.");
	tfc_say("    ixseek=val: rawseek source file/device by these val bytes.");
	tfc_say("    Do not adjust initial counter automatically.");
	tfc_say("    ictr=val: Increment initial counter by this val blocks.");
	tfc_say("    The size of each block is %u bytes.", TFC_U(TF_BLOCK_SIZE));
	tfc_say("    ictr option is valid only for CTR and CTR like modes.");
	tfc_say("    ixctr=val: Increment initial counter by this val bytes.");
	tfc_say("    Internally this number is translated into number of %u byte blocks.", TFC_U(TF_BLOCK_SIZE));
	tfc_say("    oseek=val: seek destination file/device by these val bytes.");
	tfc_say("    count=val: process only these val bytes, both input and output.");
	tfc_say("    ftrunc=val: truncate output file to these val bytes before closing it.");
	tfc_say("    xkey=val: take only val bytes from user keyfile.");
	tfc_say("    okey=val: seek the key before reading it (usually a device).");
	tfc_say("    xctr=val: specify size in bytes of initial counter prepended or read.");
	tfc_say("    fullkey: occupy tweak space by key space, extending key size by 256 bits.");
	tfc_say("  -P: plain IO mode: disable encryption/decryption code at all.");
	tfc_say("\n");
	tfc_say("Default is to ask for password, then encrypt stdin into stdout.");
	tfc_say("Some cmdline parameters may be mutually exclusive, or they can");
	tfc_say("generate errors or behave abnormally. Please understand that some");
	tfc_say("dumb mode error checking may be not performed well, and please read");
	tfc_say("the README included within package and this help text carefully.");
	tfc_say("\n");

	xexit(1);
}
