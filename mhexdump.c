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

#include <string.h>
#include <stdlib.h>

#include <stdio.h>
#include <ctype.h>
#include <stdint.h>

#undef MACHINE_16BIT
#undef MACHINE_32BIT
#undef MACHINE_64BIT

#if UINTPTR_MAX == UINT32_MAX
#define MACHINE_32BIT
#elif UINTPTR_MAX == UINT64_MAX
#define MACHINE_64BIT
#elif UINTPTR_MAX == UINT16_MAX
#define MACHINE_16BIT
#endif

struct mhexdump_args {
	const void *data;
	size_t szdata;
	int group;
	int hexgroup;
	int hexstr;
	int addaddr;
	int newline;
	FILE *fp;
	int closef;
};

#if defined(MACHINE_32BIT)
#define ADDRFMT "%08x: "
#define paddr (mha->addaddr == 2 ? (uint32_t)P+(x*mha->group) : (x*mha->group))
#elif defined(MACHINE_64BIT)
#define ADDRFMT "%016lx: "
#define paddr (mha->addaddr == 2 ? (uint64_t)P+(x*mha->group) : (x*mha->group))
#elif defined(MACHINE_16BIT)
#define ADDRFMT "%04x: "
#define paddr (mha->addaddr == 2 ? (uint16_t)P+(x*mha->group) : (x*mha->group))
#else
#error No machine word size detected!
#endif

#define BYTEOUT ((unsigned char)P[y+(x*mha->group)])

int fmhexdump(const struct mhexdump_args *mha)
{
	const unsigned char *P = mha->data;
	int x, y;

	if (!mha->fp || !mha->data || mha->szdata == 0) return 0;

	for (x = 0; x < mha->szdata/mha->group; x++) {
		if (mha->addaddr) fprintf(mha->fp, ADDRFMT, paddr);
		for (y = 0; y < mha->group; y++) {
			fprintf(mha->fp, "%02hhx", BYTEOUT);
			if (((y+1) % mha->hexgroup) == 0 && (y != (mha->group)-1)) fputc(' ', mha->fp);
		}
		if (mha->hexstr) fprintf(mha->fp, "  ");
		if (mha->hexstr) for (y = 0; y < mha->group; y++) {
			if (isprint(BYTEOUT)) fprintf(mha->fp, "%c", BYTEOUT);
			else fputc('.', mha->fp);
		}
		if (mha->szdata/mha->group == 1 && mha->szdata-mha->group == 0) {
			if (mha->newline) fputc('\n', mha->fp);
		}
		else fputc('\n', mha->fp);
	}
	if (mha->szdata-(x*mha->group) == 0) goto _ret;

	if (mha->addaddr) fprintf(mha->fp, ADDRFMT, paddr);
	for (y = 0; y < mha->szdata-(x*mha->group); y++) {
		fprintf(mha->fp, "%02hhx", BYTEOUT);
		if (((y+1) % mha->hexgroup) == 0) fputc(' ', mha->fp);
	}
	if (mha->hexstr) for (; y < mha->group; y++) {
		fprintf(mha->fp, "  ");
		if (((y+1) % mha->hexgroup) == 0 && (y != mha->group-1)) fputc(' ', mha->fp);
	}
	if (mha->hexstr) fprintf(mha->fp, "  ");
	if (mha->hexstr) for (y = 0; y < mha->szdata-(x*mha->group); y++) {
		if (isprint(BYTEOUT)) fprintf(mha->fp, "%c", BYTEOUT);
		else fputc('.', mha->fp);
	}

	if (mha->newline) fputc('\n', mha->fp);

_ret:	fflush(mha->fp);
	if (mha->closef) fclose(mha->fp);
	return 1;
}

#undef BYTEOUT

int xmhexdump(int to, const void *data, size_t szdata, int hgroup, int hexstr, int newline)
{
	struct mhexdump_args mha;

	if (hgroup == 0) hgroup = 16;

	memset(&mha, 0, sizeof(struct mhexdump_args));
	mha.fp = (to == 2) ? stderr : stdout;
	mha.closef = 0;
	mha.data = data;
	mha.szdata = szdata;
	mha.group = hgroup;
	mha.hexgroup = hgroup;
	mha.hexstr = hexstr;
	mha.addaddr = 0;
	mha.newline = newline;

	return fmhexdump(&mha);
}
