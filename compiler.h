#ifndef COMPILER_H
#define COMPILER_H

#include "utils.h"

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
    bool flag_detailed; bool flag_assembly;
    bool flag_compat; bool flag_compact;
    bool flag_prolix; bool flag_debug;
    bool flag_clean; bool flag_fast;
} io_compilers;

typedef enum {
    BIT_FLAG_DEBUG = 1 << 0,
    BIT_FLAG_ASSEMBLER = 1 << 1,
    BIT_FLAG_COMPAT = 1 << 2,
    BIT_FLAG_PROLIX = 1 << 3,
    BIT_FLAG_COMPACT = 1 << 4,
    BIT_FLAG_TIME = 1 << 5
} CompilerFlags;

typedef struct {
    int flag;
    const char *option;
    size_t len;
} CompilerOption;

typedef struct {
    const char *full_name;
    const char *short_name;
    bool *flag_ptr;
} OptionMap;

extern const CompilerOption object_opt[];

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

extern struct
timespec pre_start,post_end;
extern char *pc_full_includes;
extern char pc_include_path[DOG_PATH_MAX];
extern bool pc_is_error,
    pc_missing_stdlib,
    pc_debug_options,
    pc_input_info,
    process_file_success;

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
