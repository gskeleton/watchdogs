#ifndef WATCHDOGS
#define WATCHDOGS

#include "obj.h"

_EXTRN _Bool unit_selection_state;
_EXTRN const char*watchdogs_release;

void unit_ret_main(void *prefilled_command);

#endif
