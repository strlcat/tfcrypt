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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "getpasswd.h"

size_t xgetpasswd(struct getpasswd_state *getps)
{
	char c;
	int tty_opened = 0, x;
	int clear;
	struct termios s, t;
	size_t l, echolen = 0;

	if (!getps) return ((size_t)-1);

	/*
	 * Both stdin and stderr point to same fd. This cannot happen.
	 * This only means that getps was memzero'd.
	 * Do not blame user for that, just fix it.
	 */
	if ((getps->fd == 0 && getps->efd == 0) || getps->efd == -1) getps->efd = 2;

	if (getps->fd == -1) {
		if ((getps->fd = open("/dev/tty", O_RDONLY|O_NOCTTY)) == -1) getps->fd = 0;
		else tty_opened = 1;
	}

	memset(&t, 0, sizeof(struct termios));
	memset(&s, 0, sizeof(struct termios));
	if (tcgetattr(getps->fd, &t) == -1) {
		getps->error = errno;
		return ((size_t)-1);
	}
	s = t;
	if (getps->sanetty) memcpy(getps->sanetty, &s, sizeof(struct termios));
	cfmakeraw(&t);
	t.c_iflag |= ICRNL;
	if (tcsetattr(getps->fd, TCSANOW, &t) == -1) {
		getps->error = errno;
		return ((size_t)-1);
	}

	if (getps->echo) {
		echolen = strlen(getps->echo);
		if (write(getps->efd, getps->echo, echolen) == -1) {
			getps->error = errno;
			l = ((size_t)-1);
			goto _xerr;
		}
	}

	l = 0; x = 0;
	memset(getps->passwd, 0, getps->pwlen);
	while (1) {
		clear = 1;
		if (read(getps->fd, &c, sizeof(char)) == -1) {
			getps->error = errno;
			l = ((size_t)-1);
			goto _xerr;
		}
		if (getps->charfilter) {
			x = getps->charfilter(getps, c, l);
			if (x == 0) {
				clear = 0;
				goto _newl;
			}
			else if (x == 2) continue;
			else if (x == 3) goto _erase;
			else if (x == 4) goto _delete;
			else if (x == 5) break;
			else if (x == 6) {
				clear = 0;
				l = getps->retn;
				memset(getps->passwd, 0, getps->pwlen);
				goto _err;
			}
		}
		if (l >= getps->pwlen && (getps->flags & GETP_WAITFILL)) clear = 0;

		if (c == '\x7f'
		|| (c == '\x08' && !(getps->flags & GETP_NOINTERP))) { /* Backspace / ^H */
_erase:			if (l == 0) continue;
			clear = 0;
			l--;
			if (!(getps->flags & GETP_NOECHO)) {
				if (write(getps->efd, "\x08\033[1X", sizeof("\x08\033[1X")-1) == -1) {
					getps->error = errno;
					l = ((size_t)-1);
					goto _xerr;
				}
			}
		}
		else if (!(getps->flags & GETP_NOINTERP)
		&& (c == '\x15' || c == '\x17')) { /* ^U / ^W */
_delete:		clear = 0;
			l = 0;
			memset(getps->passwd, 0, getps->pwlen);
			if (write(getps->efd, "\033[2K\033[0G", sizeof("\033[2K\033[0G")-1) == -1) {
				getps->error = errno;
				l = ((size_t)-1);
				goto _xerr;
			}
			if (getps->echo) {
				if (write(getps->efd, getps->echo, echolen) == -1) {
					getps->error = errno;
					l = ((size_t)-1);
					goto _xerr;
				}
			}
		}
_newl:		if (c == '\n'
		|| c == '\r'
		|| (!(getps->flags & GETP_NOINTERP) && c == '\x04')) break;
		if (clear) {
			*(getps->passwd+l) = c;
			l++;
			if (!(getps->flags & GETP_NOECHO)) {
				if (getps->maskchar &&
					write(getps->efd, &getps->maskchar,
					sizeof(char)) == -1) {
						getps->error = errno;
						l = ((size_t)-1);
						goto _xerr;
				}
			}
		}
		if (l >= getps->pwlen && !(getps->flags & GETP_WAITFILL)) break;
	};

_err:	if (write(getps->efd, "\r\n", sizeof("\r\n")-1) == -1) {
		getps->error = errno;
		l = ((size_t)-1);
	}
	if (x != 6) *(getps->passwd+l) = 0;

_xerr:	if (tcsetattr(getps->fd, TCSANOW, &s) == -1) {
		if (getps->error == 0) {
			getps->error = errno;
			l = ((size_t)-1);
		}
	}

	if (tty_opened) close(getps->fd);

	return l;
}
