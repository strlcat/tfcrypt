#include <string.h>

size_t xstrlcpy(char *dst, const char *src, size_t size)
{
	size_t len, srclen;
	srclen = strlen(src);
	if (size-- <= 0) return srclen;
	len = (size < srclen) ? size : srclen;
	memmove(dst, src, len);
	dst[len] = '\0';
	return srclen;
}

size_t xstrlcat(char *dst, const char *src, size_t size)
{
	size_t dstlen = strnlen(dst, size);
	if (dstlen == size) return dstlen + strlen(src);
	return dstlen + xstrlcpy(dst+dstlen, src, size-dstlen);
}
