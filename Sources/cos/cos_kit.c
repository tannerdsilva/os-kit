#include <errno.h>
#include "cos_kit.h"

int getErrno() {
	return errno;
}

int _putgrent(const struct group *grp, FILE *stream) {
	return putgrent(grp, stream);
}