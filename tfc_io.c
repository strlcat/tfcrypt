#include "tfcrypt.h"

size_t xread(int fd, void *data, size_t szdata)
{
	size_t x;

	do {
		x = (size_t)read(fd, data, szdata);
	} while (x == NOSIZE && errno == EINTR);

	return x;
}

size_t xwrite(int fd, const void *data, size_t szdata)
{
	size_t x;

	do {
		x = (size_t)write(fd, data, szdata);
	} while (x == NOSIZE && errno == EINTR);

	return x;
}
