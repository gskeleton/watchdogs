#ifndef COMPILER_H
#define COMPILER_H

#include "obj.h"

#define ANDROID_SHARED_DOWNLOADS_PATH  \
    "../storage/shared/Download"

#define PC_RETRY_STATE_NONE (0)
#define PC_RETRY_STATE_FIRST (1)
#define PC_RETRY_STATE_FINAL (2)

typedef struct {
  char *output;
  char direct_path[DOG_PATH_MAX];
  char file_name_buf[DOG_PATH_MAX];
  char input_path[DOG_PATH_MAX];
  char temp_path[DOG_PATH_MAX];
  _Bool flag_detailed; _Bool flag_assembly;
  _Bool flag_compat; _Bool flag_compact;
  _Bool flag_prolix; _Bool flag_debug;
  _Bool flag_clean; _Bool flag_fast;
} io_compilers;

_EXTRN io_compilers all_pc_field;

typedef struct {
  int flag;
  const char *option;
  size_t len;
} CompilerOption;

typedef struct {
  const char *full_name;
  const char *short_name;
  _Bool *flag_ptr;
} OptionMap;

#ifdef DOG_WINDOWS

typedef struct {
	char *pc_input;
	STARTUPINFO *startup_info;
	PROCESS_INFORMATION *process_info;
	HANDLE hFile;
	struct timespec *pre_start;
	struct timespec *post_end;
	const char *windows_redist_err;
	const char *windows_redist_err2;
} pc_thread_data_t;

#endif

_EXTRN const CompilerOption object_opt[];
_EXTRN struct
timespec pre_start,post_end;
_EXTRN char *pc_full_includes;
_EXTRN char pc_include_path[DOG_PATH_MAX];
_EXTRN _Bool pc_is_error,
  pc_debug_options,
  pc_input_info,
  spawn_succeeded;

typedef enum { BIT_FLAG_DEBUG = 1 << 0, BIT_FLAG_ASSEMBLER = 1 << 1, BIT_FLAG_COMPAT = 1 << 2, BIT_FLAG_PROLIX = 1 << 3, BIT_FLAG_COMPACT = 1 << 4, BIT_FLAG_TIME = 1 << 5 } CompilerFlags;

int
dog_exec_compiler(const char *arg,
				char *compile_args,
				const char *second_arg,
				const char *four_arg,
				const char *five_arg,
				const char *six_arg,
				const char *seven_arg,
				const char *eight_arg,
				const char *nine_arg,
                const char *ten_arg);

#endif
