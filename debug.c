#include "utils.h"
#include "server.h"
#include "units.h"
#include "crypto.h"
#include "compiler.h"
#include "debug.h"

static void unit_restore(void) {
    /* Validate directory existence and create if needed */
    if (dir_exists(".watchdogs") == 0) {
        if (MKDIR(".watchdogs") != 0) {
            pr_error(stdout, "unit_restore: failed to create .watchdogs directory");
        } else {
            ;
        } /* if */
    } /* if */

    /* Restore SEF and configure TOML */
    _sef_restore();
    dog_configure_toml();

    /* Reset signal handlers */
    (void)signal(SIGINT, SIG_DFL);
    
    /* Toggle state variables */
    sigint_handler = !sigint_handler;
    pc_is_error = !pc_is_error;
    unit_selection_state = !unit_selection_state;

#if defined(_DBG_PRINT)
    pr_info(stdout, "unit_restore: state restored - sigint=%d, error=%d, selection=%d", 
             sigint_handler, pc_is_error, unit_selection_state);
#endif
} /* unit_restore */

#ifdef DOG_WINDOWS
void enable_ansi()
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    
    /* Validate handle */
    if (hOut == INVALID_HANDLE_VALUE) {
        pr_error(stdout, "enable_ansi: invalid console handle");
        return;
    } /* if */

    /* Get current console mode */
    if (!GetConsoleMode(hOut, &dwMode)) {
        pr_error(stdout, "enable_ansi: failed to get console mode");
        return;
    } /* if */

    /* Enable virtual terminal processing if not already enabled */
    if (!(dwMode & ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        if (SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
            ; /* enable */
        } else {
            pr_warning(stdout, "enable_ansi: failed to enable ANSI support");
        } /* if */
    } else {
        ; /* already */
    } /* if */
} /* enable_ansi */
#endif

void _unit_debugger(int multi_debug,
    const char* function,
    const char* file, int line) {

    static bool unit_refresh = false;
    
    /* Validate input parameters */
    if (function == NULL) {
        pr_error(stdout, "_unit_debugger: function name is NULL");
        function = "unknown";
    } /* if */
    
    if (file == NULL) {
        pr_error(stdout, "_unit_debugger: file name is NULL");
        file = "unknown";
    } /* if */
    
    if (line < 0) {
        pr_warning(stdout, "_unit_debugger: line number %d is negative", line);
    } /* if */

    /* Initialize on first call */
    if (!unit_refresh) {
#ifdef DOG_WINDOWS
        enable_ansi();
#endif
        unit_refresh = !unit_refresh;
        
        /* Clear readline history */
        clear_history();
        rl_on_new_line();
        rl_redisplay();
        
        /* Set console title */
        (void)dog_console_title(NULL);
        
        /* Initialize CRC32 table */
        crypto_crc32_init_table();
    } /* if */

    /* Restore unit state */
    unit_restore();

#if ! defined(_DBG_PRINT)
    /* Debug printing disabled, return early */
    return;
#endif

    /* Handle different debug levels */
    if (multi_debug == 1) {
        /* Full debug with all configuration options */
        char* tokens = NULL;
        
        pr_color(stdout, DOG_COL_YELLOW, "-DEBUGGER ");
        
        /* Mask GitHub tokens for security */
        if (dogconfig.dog_toml_github_tokens != NULL) {
            tokens = dog_masked_text(5, dogconfig.dog_toml_github_tokens);
        } else {
            tokens = strdup("(null)");
        } /* if */
        
        /* Print main debug information */
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
            dogconfig.dog_os_type ? dogconfig.dog_os_type : "(null)", 
            dogconfig.dog_pawncc_path ? dogconfig.dog_pawncc_path : "(null)", 
            dogconfig.dog_ptr_samp ? dogconfig.dog_ptr_samp : "(null)",
            dogconfig.dog_ptr_omp ? dogconfig.dog_ptr_omp : "(null)", 
            dogconfig.dog_is_samp ? dogconfig.dog_is_samp : "(null)", 
            dogconfig.dog_is_omp ? dogconfig.dog_is_omp : "(null)",
            dogconfig.dog_toml_serv_input ? dogconfig.dog_toml_serv_input : "(null)", 
            dogconfig.dog_toml_serv_output ? dogconfig.dog_toml_serv_output : "(null)",
            dogconfig.dog_toml_server_binary ? dogconfig.dog_toml_server_binary : "(null)", 
            dogconfig.dog_toml_server_config ? dogconfig.dog_toml_server_config : "(null)", 
            dogconfig.dog_toml_server_logs ? dogconfig.dog_toml_server_logs : "(null)",
            tokens ? tokens : "(null)", 
            dogconfig.dog_toml_full_opt ? dogconfig.dog_toml_full_opt : "(null)", 
            dogconfig.dog_toml_packages ? dogconfig.dog_toml_packages : "(null)");
        
        if (tokens != NULL) {
            free(tokens);
        } /* if */

        /* Additional system information */
        printf("STDC: %d\n", __STDC__);
        printf("STDC_HOSTED: %d\n", __STDC_HOSTED__);

        /* Display byte order */
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

        /* Display size information */
        printf("SIZE_OF_PTR: %zu bytes\n", sizeof(void*));
        printf("SIZE_OF_INT: %zu bytes\n", sizeof(int));
        printf("SIZE_OF_LONG: %zu bytes\n", sizeof(long));

        /* Display data model */
#ifdef __LP64__
        printf("DATA_MODEL: LP64\n");
#elif defined(__ILP32__)
        printf("DATA_MODEL: ILP32\n");
#else
        printf("DATA_MODEL: Unknown\n");
#endif

        /* Display compiler information */
#ifdef __GNUC__
        printf("GNUC: %d.%d.%d\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#endif

#ifdef __clang__
        printf("CLANG: %d.%d.%d\n", __clang_major__, __clang_minor__, __clang_patchlevel__);
#endif

        /* Display CPU feature support */
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

    } else if (multi_debug == 0) {
        /* Standard debug output */
        char* tokens = NULL;
        
        /* Mask GitHub tokens for security */
        if (dogconfig.dog_toml_github_tokens != NULL) {
            tokens = dog_masked_text(5, dogconfig.dog_toml_github_tokens);
        } else {
            tokens = strdup("(null)");
        } /* if */
        
        pr_color(stdout, DOG_COL_YELLOW, "-DEBUGGER ");
        
        /* Print standard debug information */
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
            dogconfig.dog_os_type ? dogconfig.dog_os_type : "(null)", 
            dogconfig.dog_pawncc_path ? dogconfig.dog_pawncc_path : "(null)", 
            dogconfig.dog_ptr_samp ? dogconfig.dog_ptr_samp : "(null)",
            dogconfig.dog_ptr_omp ? dogconfig.dog_ptr_omp : "(null)", 
            dogconfig.dog_is_samp ? dogconfig.dog_is_samp : "(null)", 
            dogconfig.dog_is_omp ? dogconfig.dog_is_omp : "(null)",
            dogconfig.dog_toml_serv_input ? dogconfig.dog_toml_serv_input : "(null)", 
            dogconfig.dog_toml_serv_output ? dogconfig.dog_toml_serv_output : "(null)",
            dogconfig.dog_toml_server_binary ? dogconfig.dog_toml_server_binary : "(null)", 
            dogconfig.dog_toml_server_config ? dogconfig.dog_toml_server_config : "(null)", 
            dogconfig.dog_toml_server_logs ? dogconfig.dog_toml_server_logs : "(null)",
            tokens ? tokens : "(null)");
        
        if (tokens != NULL) {
            free(tokens);
        } /* if */
    } else {
        /* Unknown debug level */
        pr_warning(stdout, "_unit_debugger: unknown debug level %d", multi_debug);
    } /* if */

    fflush(stdout);
    return;
} /* _unit_debugger */

void _minimal_debugger(const char* function,
    const char* file, int line) {

    /* Validate input parameters */
    if (function == NULL) {
        pr_error(stdout, "_minimal_debugger: function name is NULL");
        function = "unknown";
    } /* if */
    
    if (file == NULL) {
        pr_error(stdout, "_minimal_debugger: file name is NULL");
        file = "unknown";
    } /* if */
    
    if (line < 0) {
        pr_warning(stdout, "_minimal_debugger: line number %d is negative", line);
    } /* if */

#if ! defined (_DBG_PRINT)
    /* Debug printing disabled, return early */
    return;
#endif

    pr_info(stdout, "_minimal_debugger: minimal debug for %s at %s:%d", function, file, line);

    pr_color(stdout, DOG_COL_YELLOW, "-DEBUGGER ");
    
    /* Print minimal debug information */
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
} /* _minimal_debugger */