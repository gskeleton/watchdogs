#ifndef PACKAGE_H
#define PACKAGE_H

#include "obj.h"

struct library_version_info { char key; const char *name; const char *linux_url; const char *linux_file; const char *windows_url; const char *windows_file; };

_EXTRN _Bool installing_pawncc;
_EXTRN _Bool installing_pcc_posix;

int dog_install_pawncc(const char *platform);
int dog_install_server(const char *platform);

#endif
