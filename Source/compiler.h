#ifndef COMPILER_H
#define COMPILER_H

#include "utils.h"

#define ANDROID_DOWNLOADS "../storage/shared/Download"

typedef struct {
    char *container_output                     ;
    char compiler_direct_path    [DOG_PATH_MAX];
    char compiler_size_file_name [DOG_PATH_MAX];
    char compiler_size_input_path[DOG_PATH_MAX];
    char compiler_size_temp      [DOG_PATH_MAX];
} io_compilers;

typedef enum {
    BIT_FLAG_DEBUG     = 1 << 0,
    BIT_FLAG_ASSEMBLER = 1 << 1,
    BIT_FLAG_COMPAT    = 1 << 2,
    BIT_FLAG_PROLIX    = 1 << 3,
    BIT_FLAG_COMPACT   = 1 << 4,
    BIT_FLAG_TIME      = 1 << 5
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
	char *compiler_input;
	STARTUPINFO *startup_info;
	PROCESS_INFORMATION *process_info;
	HANDLE hFile;
	struct timespec *pre_start;
	struct timespec *post_end;
	const char *windows_redist_err;
	const char *windows_redist_err2;
} compiler_thread_data_t;

#endif

extern struct
timespec pre_start,post_end;
extern char *compiler_full_includes;
extern char compiler_path_include_buf[];
extern bool compiler_is_err,
    compiler_installing_stdlib,
    compiler_debug_flag_is_exists,
    compiler_dog_flag_debug,
    compiler_input_debug,
    compiler_dog_flag_clean,
    compiler_dog_flag_fast,
    process_file_success;

int
dog_exec_compiler(const char *arg,
				const char *compile_args,
				const char *second_arg,
				const char *four_arg,
				const char *five_arg,
				const char *six_arg,
				const char *seven_arg,
				const char *eight_arg,
				const char *nine_arg,
                const char *ten_arg);

#endif
