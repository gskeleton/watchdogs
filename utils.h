#ifndef UTILS_H
#define UTILS_H

#include "obj.h"

enum { DOG_PATH_MAX = 260 + 128, DOG_MAX_PATH = 4096, DOG_MORE_MAX_PATH = 8192 };
enum { RATE_SEF_EMPTY = 0, MAX_SEF_ENTRIES = 200, MAX_SEF_PATH_SIZE = DOG_PATH_MAX };

typedef struct {
char * dog_os_type; char * dog_is_samp; char * dog_is_omp;
size_t dog_sef_count; char dog_sef_found_list[MAX_SEF_ENTRIES][MAX_SEF_PATH_SIZE];
char * dog_pawncc_path;
char * dog_ptr_samp; char * dog_ptr_omp;
char * dog_toml_os_type;
char * dog_toml_server_binary; char * dog_toml_server_config;
char * dog_toml_server_logs;
char * dog_toml_full_opt;
char * dog_toml_serv_input; char * dog_toml_serv_output;
} WatchdogConfig;

_EXTRN WatchdogConfig dogconfig;

#ifdef DOG_WINDOWS
  #define IS_PATH_SEP(chr) ((chr) == _PATH_CHR_SEP_POSIX || (chr) == _PATH_CHR_SEP_WIN32)
#else
  #define IS_PATH_SEP(chr) ((chr) == _PATH_CHR_SEP_POSIX)
#endif

#define _PATH_CHR_SEP_POSIX '/'
#define _PATH_CHR_SEP_WIN32 '\\'
#define _PATH_STR_SEP_POSIX "/"
#define _PATH_STR_SEP_WIN32 "\\"

#define CRC32_TRUE "fdfc4c8d"
#define CRC32_FALSE "2bcd6830"
#define CRC32_UNKNOWN "ad26a7c7"

#define OSYS_WINDOWS "windows"
#define OSYS_LINUX "linux"
#define OSYS_UNKNOWN CRC32_UNKNOWN

#define TOML_TABLE_GENERAL "general"
#define TOML_TABLE_COMPILER "compiler"

#define LINUX_LIB_PATH "/usr/local/lib"
#define LINUX_LIB32_PATH "/usr/local/lib32"
#define TMUX_LIB_PATH "/data/data/com.termux/files/usr/lib"
#define TMUX_LIB_LOC_PATH "/data/data/com.termux/files/usr/local/lib"
#define TMUX_LIB_ARM64_PATH "/data/data/com.termux/arm64/usr/lib"
#define TMUX_LIB_ARM32_PATH "/data/data/com.termux/arm32/usr/lib"
#define TMUX_LIB_AMD64_PATH "/data/data/com.termux/amd64/usr/lib"
#define TMUX_LIB_AMD32_PATH "/data/data/com.termux/amd32/usr/lib"

#define LR_RED "\033[0;31m"
#define LR_GREEN "\033[0;32m"
#define LR_YELLOW "\033[0;33m"
#define LR_BLUE "\033[94m"
#define LR_CYAN "\033[0;36m"
#define LR_WHITE "\033[0;37m"
#define LR_BRED "\033[1;31m"
#define LR_BGREEN "\033[1;32m"
#define LR_BYELLOW "\033[1;33m"
#define LR_BBLUE "\033[1;34m"
#define LR_BMAGENTA "\033[1;35m"
#define LR_BCYAN "\033[1;36m"
#define LR_BWHITE "\033[1;37m"
#define LR_B_BLUE "\033[1;94m"
#define LR_BOLD "\033[1m"
#define LR_DIM "\033[2m"
#define LR_UNDERLINE "\033[4m"
#define LR_BLINK "\033[5m"
#define LR_REVERSE "\033[7m"
#define LR_HIDDEN "\033[8m"
#define BKG_RED "\033[41m"
#define BKG_GREEN "\033[42m"
#define BKG_YELLOW "\033[43m"
#define BKG_BLUE "\033[44m"
#define BKG_CYAN "\033[46m"
#define BKG_WHITE "\033[47m"
#define LR_RESET "\033[0m"
#define LR_DEFAULT "\033[39m"
#define BKG_DEFAULT "\033[49m"

#define pr_color printf_colour
#define pr_info printf_info
#define pr_warning printf_warning
#define pr_error printf_error

void print_restore_color(void);
void println(FILE *stream, const char* format, ...);
void printf_colour(FILE *stream, const char *color, const char *format, ...);
void printf_info(FILE *stream, const char *format, ...);
void printf_warning(FILE *stream, const char *format, ...);
void printf_error(FILE *stream, const char *format, ...);

#ifdef DOG_LINUX

#ifndef strlcpy
size_t strlcpy(char *dst, const char *src, size_t size);
#endif
#ifndef strlcat
size_t strlcat(char *dst, const char *src, size_t size);
#endif

#else

size_t w_strlcpy(char *dst, const char *src, size_t size);
size_t w_strlcat(char *dst, const char *src, size_t size);

#define strlcpy w_strlcpy
#define strlcat w_strlcat

#endif

void _sef_restore(void);
_Bool fet_server_env(void);

_EXTRN const char* dog_find_near_command(const char *ptr_command,
  const char *__commands[], size_t num_cmds, int *out_distance);

struct struct_of { int (*title)(const char *); };
_EXTRN const char* unit_command_list[];
_EXTRN const size_t unit_command_len;

void* dog_malloc(size_t size);
void* dog_calloc(size_t count, size_t size);
void* dog_realloc(void* ptr, size_t size);
void  dog_free(void *ptr);

void path_sep_to_posix(char *path);
void path_sep_to_win32(char *path);

int dir_exists(const char *path);
int path_exists(const char *path);
int dir_writable(const char *path);
int path_access(const char *path);
int file_regular(const char *path);
int same_file(const char *a, const char *b);
int dot_or_dotdot(const char *name);

const char *lookup_path_sep(const char *sep_path);
const char *fet_filename(const char *path);
char * fet_basename(const char *path);

int __MKDIR(const char *path);
char *procure_pwd(void);

void print_file(const char *path);
_Bool console_title(const char *__title);

_Bool _strcase(const char *text, const char *pattern);
_Bool _strend(const char *str, const char *suffix, _Bool nocase);
_Bool _strfind(const char *text, const char *pattern, _Bool nocase);
int match_wildcard(const char *str, const char *pat);

void normalize_spaces(char *str);
int equals(const char *a, const char *b);

_Bool terminate_proc(const char *process);

int find_path(const char *sef_path,
          const char *sef_name,
          const char *ignore_dir);

int configure_toml(void);
void configure_libpcc(void);

int wcopy(const char *c_src, const char *c_dest);
int wmove(const char *c_src, const char *c_dest);

#endif /* UTILS_H */
