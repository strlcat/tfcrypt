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

void tfc_vfsay(FILE *where, tfc_yesno addnl, const char *fmt, va_list ap)
{
	if (!strcmp(fmt, "\n")) {
		fputc('\n', where);
		return;
	}

	vfprintf(where, fmt, ap);
	if (addnl) fputc('\n', where);
	fflush(where);
}

void tfc_nfsay(FILE *where, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	tfc_vfsay(where, NO, fmt, ap);
	va_end(ap);
}

void tfc_esay(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	tfc_vfsay(stderr, YES, fmt, ap);
	va_end(ap);
}

void tfc_say(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	tfc_vfsay(stdout, YES, fmt, ap);
	va_end(ap);
}
