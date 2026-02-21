#include "utils.h"
#include "server.h"
#include "units.h"
#include "crypto.h"
#include "compiler.h"
#include "debug.h"

static void unit_restore(void) {
    if (dir_exists(".watchdogs") == 0)
        MKDIR(".watchdogs");

    _sef_restore();
    dog_configure_toml();

    signal(SIGINT, SIG_DFL);
    sigint_handler
        = !sigint_handler;
    pc_is_error
        = !pc_is_error;
    unit_selection_state
        = !unit_selection_state;
}

#ifdef DOG_WINDOWS
void enable_ansi()
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE)
        return;

    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode))
        return;

    if (!(dwMode & ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        SetConsoleMode(hOut, dwMode |
            ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
}
#endif

void _unit_debugger(int multi_debug,
    const char* function,
    const char* file, int line) {

    static bool unit_refresh = false;
    if (!unit_refresh) {
#ifdef DOG_WINDOWS
        enable_ansi();
#endif
        unit_refresh = !unit_refresh;
        clear_history();
        rl_on_new_line();
        rl_redisplay();
        dog_console_title(NULL);
        crypto_crc32_init_table();
    }

    unit_restore();

#if ! defined(_DBG_PRINT)
    return;
#endif

    if (multi_debug == 1) {
        /* Full debug with all configuration options */
        pr_color(stdout, DOG_COL_YELLOW, "-DEBUGGER ");
        char* tokens = dog_masked_text(5, dogconfig.dog_toml_github_tokens);
        printf("[function: %s | "
            "line: %d | "
            "file: %s | "
            "date: %s | "
            "time: %s | "
            "timestamp: %s | "
            "C standard: %ld | "
            "C version: %s | "
            "compiler version: %d | "
            "architecture: %s | "
            "os_type: %s (CRC32) | "
            "pawncc path: %s | "
            "pointer_samp: %s | "
            "pointer_openmp: %s | "
            "f_samp: %s (CRC32) | "
            "f_openmp: %s (CRC32) | "
            "toml gamemode input: %s | "
            "toml gamemode output: %s | "
            "toml binary: %s | "
            "toml configs: %s | "
            "toml logs: %s | "
            "toml github tokens: %s | "
            "toml aio opt: %s | "
            "toml aio packages: %s]\n",
            function,
            line, file,
            __DATE__, __TIME__,
            __TIMESTAMP__,
            __STDC_VERSION__,
            __VERSION__,
            __GNUC__,
#ifdef __x86_64__
            "x86_64",
#elif defined(__i386__)
            "i386",
#elif defined(__arm__)
            "ARM",
#elif defined(__aarch64__)
            "ARM64",
#else
            "Unknown",
#endif
            dogconfig.dog_os_type, dogconfig.dog_pawncc_path, dogconfig.dog_ptr_samp,
            dogconfig.dog_ptr_omp, dogconfig.dog_is_samp, dogconfig.dog_is_omp,
            dogconfig.dog_toml_serv_input, dogconfig.dog_toml_serv_output,
            dogconfig.dog_toml_server_binary, dogconfig.dog_toml_server_config, dogconfig.dog_toml_server_logs,
            tokens, dogconfig.dog_toml_full_opt, dogconfig.dog_toml_packages);
        free(tokens);

        /* Additional system information */
        printf("STDC: %d\n", __STDC__);
        printf("STDC_HOSTED: %d\n", __STDC_HOSTED__);

        printf("BYTE_ORDER: ");
#ifdef __BYTE_ORDER__
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        printf("Little Endian\n");
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        printf("Big Endian\n");
#else
        printf("Unknown\n");
#endif
#else
        printf("Not defined\n");
#endif

        printf("SIZE_OF_PTR: %zu bytes\n", sizeof(void*));
        printf("SIZE_OF_INT: %zu bytes\n", sizeof(int));
        printf("SIZE_OF_LONG: %zu bytes\n", sizeof(long));

#ifdef __LP64__
        printf("DATA_MODEL: LP64\n");
#elif defined(__ILP32__)
        printf("DATA_MODEL: ILP32\n");
#endif

#ifdef __GNUC__
        printf("GNUC: %d.%d.%d\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#endif

#ifdef __clang__
        printf("CLANG: %d.%d.%d\n", __clang_major__, __clang_minor__, __clang_patchlevel__);
#endif

        printf("OS: ");
#ifdef __SSE__
        printf("SSE: Supported\n");
#endif
#ifdef __AVX__
        printf("AVX: Supported\n");
#endif
#ifdef __FMA__
        printf("FMA: Supported\n");
#endif

    }
    else if (multi_debug == 0) {
        /* Standard debug output */
        char* tokens = dog_masked_text(5, dogconfig.dog_toml_github_tokens);
        pr_color(stdout, DOG_COL_YELLOW, "-DEBUGGER ");
        printf("[function: %s | "
            "line: %d | "
            "file: %s | "
            "date: %s | "
            "time: %s | "
            "timestamp: %s | "
            "C standard: %ld | "
            "C version: %s | "
            "compiler version: %d | "
            "architecture: %s | "
            "os_type: %s (CRC32) | "
            "pawncc path: %s | "
            "pointer_samp: %s | "
            "pointer_openmp: %s | "
            "f_samp: %s (CRC32) | "
            "f_openmp: %s (CRC32) | "
            "toml gamemode input: %s | "
            "toml gamemode output: %s | "
            "toml binary: %s | "
            "toml configs: %s | "
            "toml logs: %s | "
            "toml github tokens: %s]\n",
            function,
            line, file,
            __DATE__, __TIME__,
            __TIMESTAMP__,
            __STDC_VERSION__,
            __VERSION__,
            __GNUC__,
#ifdef __x86_64__
            "x86_64",
#elif defined(__i386__)
            "i386",
#elif defined(__arm__)
            "ARM",
#elif defined(__aarch64__)
            "ARM64",
#else
            "Unknown",
#endif
            dogconfig.dog_os_type, dogconfig.dog_pawncc_path, dogconfig.dog_ptr_samp,
            dogconfig.dog_ptr_omp, dogconfig.dog_is_samp, dogconfig.dog_is_omp,
            dogconfig.dog_toml_serv_input, dogconfig.dog_toml_serv_output,
            dogconfig.dog_toml_server_binary, dogconfig.dog_toml_server_config, dogconfig.dog_toml_server_logs,
            tokens);
        free(tokens);
    }

    fflush(stdout);

    return;
}

void _minimal_debugger(const char* function,
    const char* file, int line) {

#if ! defined (_DBG_PRINT)
    return;
#endif

    pr_color(stdout, DOG_COL_YELLOW, "-DEBUGGER ");
    printf("[function: %s | "
        "line: %d | "
        "file: %s | "
        "date: %s | "
        "time: %s | "
        "timestamp: %s | "
        "C standard: %ld | "
        "C version: %s | "
        "compiler version: %d | "
        "architecture: %s]\n",
        function,
        line, file,
        __DATE__, __TIME__,
        __TIMESTAMP__,
        __STDC_VERSION__,
        __VERSION__,
        __GNUC__,
#ifdef __x86_64__
        "x86_64");
#elif defined(__i386__)
        "i386");
#elif defined(__arm__)
        "ARM");
#elif defined(__aarch64__)
        "ARM64");
#else
        "Unknown");
#endif

    fflush(stdout);

    return;
}