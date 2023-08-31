#include <pwd.h>
#include <shadow.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <stdarg.h>

// returns the result of the errno alias, since errno is a macro that cannot resolve in Swift.
int getErrno();

int _putgrent(const struct group *grp, FILE *stream);