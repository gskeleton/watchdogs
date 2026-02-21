#include "units.h"
#include "utils.h"
#include "crypto.h"
#include "replicate.h"
#include "compiler.h"
#include "debug.h"
#include "server.h"

static char sbuf[0x400];
int sigint_handler = 0;
static char* sampvoice_port = NULL;
static int rate_sampvoice_server = 0;
static int rate_problem_stat = 0;
static int server_crashdetect = 0;
static int server_rcon_pass = 0;

/**
 * Signal handler for SIGINT (Ctrl+C)
 */
void
unit_sigint_handler(int sig __UNUSED__)
{
    sigint_handler = 1;

    struct timespec stop_all_timer;
    clock_gettime(CLOCK_MONOTONIC, &stop_all_timer);
}

/**
 * Stop running server processes
 */
void
dog_stop_server_tasks(void)
{
    bool ret = false;
    ret = dog_kill_process(dogconfig.dog_toml_server_binary);
    if (ret == false) {
        dog_kill_process(dogconfig.dog_toml_server_binary);
    }
}

/* Forward declarations of static helper functions */
static void separator_print(void);
static void error_print(const char*, const char*);
static void runtime_error_check(const char*);
static void recompile_check(const char*);
static void filesystem_error_check(const char*);
static void gamemode_error_check(const char*);
static void address_check(const char*);
static int crashdetect_check(const char*);
static int general_crash_check(const char*);
static void outofbounds_check(const char*);
static void critical_check(const char*);
static void warning_check(const char*);
static void failure_check(const char*);
static void timeout_check(const char*);
static void plugin_check(const char*);
static void database_check(const char*);
static void memory_check(const char*);
static void alloc_check(const char*);
static void info_check(const char*);
static void sampvoice_port_detect(const char*);
static void sampvoice_port_check(void);
static void rcon_password_check(void);
static void rcon_password_fix(void);
static void crashdetect_install_check(void);

/**
 * Main server crash log analysis function
 */
void
dog_server_crash_check(void)
{
    FILE* fp;
    char buf[DOG_MAX_PATH];

    /* Reset state variables */
    rate_sampvoice_server = 0;
    rate_problem_stat = 0;
    server_crashdetect = 0;
    server_rcon_pass = 0;
    sampvoice_port = NULL;

    fp = fopen(dogconfig.dog_toml_server_logs, "rb");
    if (fp == NULL) {
        pr_error(stdout, "log file not found!.");
        minimal_debugging();
        return;
    }

    /* Check for crashinfo.txt */
    if (path_exists("crashinfo.txt") == 1) {
        char* confirm;

        pr_info(stdout, "crashinfo.txt detected..");
        confirm = readline("-> show? ");
        if (confirm && (confirm[0] == '\0' || confirm[0] == 'Y' || confirm[0] == 'y'))
            dog_printfile("crashinfo.txt");
        dog_free(confirm);
    }

    separator_print();

    /* Parse log file line by line */
    while (fgets(buf, sizeof(buf), fp)) {
        if (strfind(buf, "Unable to load filterscript", 1)) {
            error_print("@ Unable to load filterscript detected", buf);
            continue;
        }

        if (strfind(buf, "Invalid index parameter (bad entry point)", 1)) {
            error_print("@ Invalid index parameter detected", buf);
            continue;
        }

        if (strfind(buf, "run time error", 1)) {
            runtime_error_check(buf);
            continue;
        }

        if (strfind(buf, "The script might need to be recompiled with the latest include file.", 1)) {
            recompile_check(buf);
            continue;
        }

        if (strfind(buf, "terminate called after throwing an instance of 'ghc::filesystem::filesystem_error", 1) ||
            strfind(buf, "filesystem_error", 1)) {
            filesystem_error_check(buf);
            continue;
        }

        if (strfind(buf, "I couldn't load any gamemode scripts.", 1)) {
            gamemode_error_check(buf);
            continue;
        }

        if (strfind(buf, "0x", 1) || strfind(buf, "address", 1) || strfind(buf, "Address", 1)) {
            address_check(buf);
            continue;
        }

        if (rate_problem_stat) {
            if (crashdetect_check(buf))
                continue;
            if (general_crash_check(buf))
                continue;
        }

        if (strfind(buf, "out of bounds", 1) || strfind(buf, "out-of-bounds", 1)) {
            outofbounds_check(buf);
            continue;
        }

        if (!fet_server_env() && strfind(buf, "Your password must be changed from the default password", 1)) {
            server_rcon_pass++;
            continue;
        }

        if (strfind(buf, "It needs a gamemode0 buffer", 1)) {
            critical_check(buf);
            continue;
        }

        if (strfind(buf, "warning", 1)) {
            warning_check(buf);
            continue;
        }

        if (strfind(buf, "failed", 1)) {
            failure_check(buf);
            continue;
        }

        if (strfind(buf, "timeout", 1)) {
            timeout_check(buf);
            continue;
        }

        if (strfind(buf, "plugin", 1)) {
            plugin_check(buf);
            continue;
        }

        if (strfind(buf, "database", 1) || strfind(buf, "mysql", 1)) {
            database_check(buf);
            continue;
        }

        if (strfind(buf, "out of memory", 1) || strfind(buf, "memory allocation", 1)) {
            memory_check(buf);
            continue;
        }

        if (strfind(buf, "malloc", 1) || strfind(buf, "free", 1) ||
            strfind(buf, "realloc", 1) || strfind(buf, "calloc", 1)) {
            alloc_check(buf);
            continue;
        }

        if (strfind(buf, "Info", 1)) {
            info_check(buf);
            continue;
        }

        sampvoice_port_detect(buf);
    }

    fclose(fp);

    /* Post-analysis checks */
    sampvoice_port_check();
    rcon_password_check();
    crashdetect_install_check();

    if (sampvoice_port) {
        free(sampvoice_port);
        sampvoice_port = NULL;
    }

    separator_print();
}

/**
 * Print separator line
 */
static void
separator_print(void)
{
    char out[64];
    int n;

    n = snprintf(out, sizeof(out),
        "--------------------------------------------------------------\n");
    fwrite(out, 1, (n < 0) ? 0 : (size_t)n, stdout);
    fflush(stdout);
}

/**
 * Print error message with context
 */
static void
error_print(const char* msg, const char* buf)
{
    char out[DOG_MAX_PATH + 26];
    int n;

    n = snprintf(out, sizeof(out), "%s\n\t", msg);
    fwrite(out, 1, (n < 0) ? 0 : (size_t)n, stdout);
    pr_color(stdout, DOG_COL_BLUE, "%s", buf);
    fflush(stdout);
}

/**
 * Check for runtime errors
 */
static void
runtime_error_check(const char* buf)
{
    char out[512];
    int n;
    size_t len;

    rate_problem_stat = 1;

    n = snprintf(out, sizeof(out), "@ Runtime error detected\n\t");
    len = (n < 0) ? 0 : (size_t)n;
    fwrite(out, 1, len, stdout);
    pr_color(stdout, DOG_COL_BLUE, "%s", buf);
    fflush(stdout);

    /* Handle AMX version mismatch */
    if (strfind(buf, "\"File is for a newer version of the AMX\"", 1)) {
        n = snprintf(out, sizeof(out),
            " * You need to open watchdogs.toml and "
            "change -O:2 to -O:1, then recompile your gamemode.\n");
        len = (n < 0) ? 0 : (size_t)n;
        fwrite(out, 1, len, stdout);
        fflush(stdout);
    }
}

/**
 * Handle recompile suggestion
 */
static void
recompile_check(const char* buf)
{
    char* input;
    char out[512];
    int n;
    size_t len;

    n = snprintf(out, sizeof(out), "@ Needed for recompiled\n\t");
    len = (n < 0) ? 0 : (size_t)n;
    fwrite(out, 1, len, stdout);
    pr_color(stdout, DOG_COL_BLUE, "%s", buf);
    fflush(stdout);

    input = readline("Recompile now? ");
    if (input == NULL)
        return;

    if (input[0] == '\0' || !strcmp(input, "Y") || !strcmp(input, "y")) {
        dog_free(input);
        printf(DOG_COL_BCYAN
            "Please input the pawn file\n\t* (enter for %s - input E/e to exit):" DOG_COL_DEFAULT,
            dogconfig.dog_toml_serv_input);
        input = readline(" ");

        if (input) {
            if (strlen(input) < 1)
                dog_exec_compiler(NULL, ".", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            else if (strlen(input) > 0 && input[0] != 'E' && input[0] != 'e')
                dog_exec_compiler(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            dog_free(input);
        }
    }
    else {
        dog_free(input);
    }
}

/**
 * Handle filesystem errors (especially WSL-related)
 */
static void
filesystem_error_check(const char* buf)
{
    char out[1024];
    int n;
    size_t len;

    n = snprintf(out, sizeof(out), "@ Filesystem C++ Error Detected\n\t");
    len = (n < 0) ? 0 : (size_t)n;
    fwrite(out, 1, len, stdout);
    pr_color(stdout, DOG_COL_BLUE, "%s", buf);
    fflush(stdout);

    n = snprintf(out, sizeof(out),
        " * Are you currently using the WSL ecosystem?\n"
        " * You need to move the open.mp server folder from the /mnt area (your Windows directory) to \"~\" (your WSL HOME).\n"
        " * This is because open.mp C++ filesystem cannot properly read directories inside the /mnt area,\n"
        "   which isn't part of the directory model targeted by the Linux build.\n"
        " ** You must run it outside the /mnt area.\n");
    len = (n < 0) ? 0 : (size_t)n;
    fwrite(out, 1, len, stdout);
    fflush(stdout);
}

/**
 * Handle gamemode loading errors
 */
static void
gamemode_error_check(const char* buf)
{
    char out[1024];
    int n;
    size_t len;

    n = snprintf(out, sizeof(out), "@ Can't found gamemode detected\n\t");
    len = (n < 0) ? 0 : (size_t)n;
    fwrite(out, 1, len, stdout);
    pr_color(stdout, DOG_COL_BLUE, "%s", buf);
    fflush(stdout);

    n = snprintf(out, sizeof(out),
        " * You need to ensure that the name specified "
        "   in the configuration file matches the one in the gamemodes/ folder,\n"
        " * and that the .amx file exists. For example, "
        " * if server.cfg contains\n"
        DOG_COL_CYAN "   gamemode0" DOG_COL_DEFAULT " main 1 or config.json" DOG_COL_CYAN " pawn.main_scripts [\"main 1\"]\n"
        DOG_COL_DEFAULT
        "  * then main.amx must be present in the gamemodes/ directory\n");
    len = (n < 0) ? 0 : (size_t)n;
    fwrite(out, 1, len, stdout);
    fflush(stdout);
}

/**
 * Handle memory address references
 */
static void
address_check(const char* buf)
{
    char out[128];

    if (strfind(buf, "0x", 1)) {
        snprintf(out, sizeof(out), "@ Hexadecimal address found\n\t");
        error_print(out, buf);
    }
    else {
        snprintf(out, sizeof(out), "@ Memory address reference found\n\t");
        error_print(out, buf);
    }
}

/**
 * Check for crashdetect plugin output
 */
static int
crashdetect_check(const char* buf)
{
    char out[256];
    int n;
    size_t len;

    if (!strfind(buf, "[debug]", 1) && !strfind(buf, "crashdetect", 1))
        return 0;

    server_crashdetect++;

    snprintf(out, sizeof(out), "@ Crashdetect debug information found\n\t");
    error_print(out, buf);

    if (strfind(buf, "AMX backtrace", 1)) {
        snprintf(out, sizeof(out), "@ Crashdetect: AMX backtrace detected\n\t");
        error_print(out, buf);
    }

    if (strfind(buf, "native stack trace", 1)) {
        snprintf(out, sizeof(out), "@ Crashdetect: Native stack trace detected\n\t");
        error_print(out, buf);
    }

    if (strfind(buf, "heap", 1)) {
        snprintf(out, sizeof(out), "@ Crashdetect: Heap issue detected\n\t");
        error_print(out, buf);
    }

    if (strfind(buf, "[debug]", 1)) {
        snprintf(out, sizeof(out), "@ Crashdetect: Debug detected\n\t");
        error_print(out, buf);
    }

    /* Handle native backtrace with specific plugin conflicts */
    if (strfind(buf, "Native backtrace", 1)) {
        char* input;
        char advice[2048];

        snprintf(out, sizeof(out), "@ Crashdetect: Native backtrace detected\n\t");
        error_print(out, buf);

        if (strfind(buf, "sampvoice", 1) && strfind(buf, "pawnraknet", 1)) {
            snprintf(out, sizeof(out), "@ Crash potential detected\n\t");
            error_print(out, buf);

            n = snprintf(advice, sizeof(advice),
                " * We have detected a crash and identified two plugins as potential causes,\n"
                " * namely SampVoice and Pawn.Raknet.\n"
                " * Are you using SampVoice version 3.1?\n"
                " * You can downgrade to SampVoice version 3.0 if necessary,\n"
                " * or you can remove either Sampvoice or Pawn.Raknet to avoid a potential crash.\n"
                " * You can review the changes between versions 3.0 and 3.1 to understand and analyze the possible reason for the crash\n"
                " ** on here: https://github.com/CyberMor/sampvoice/compare/v3.0-alpha...v3.1\n");
            len = (n < 0) ? 0 : (size_t)n;
            fwrite(advice, 1, len, stdout);
            fflush(stdout);

            printf("\x1b[32m==> downgrading sampvoice? 3.1 -> 3.0? \x1b[0m\n");
            input = readline("   answer (y/n): ");
            if (input && (input[0] == '\0' || input[0] == 'Y' || input[0] == 'y'))
                dog_install_depends("CyberMor/sampvoice?v3.0-alpha", "master", NULL);
            dog_free(input);
        }
    }

    return 1;
}

/**
 * Check for general crash indicators
 */
static int
general_crash_check(const char* buf)
{
    char out[128];

    if (strfind(buf, "stack", 1)) {
        snprintf(out, sizeof(out), "@ Stack-related issue detected\n\t");
        error_print(out, buf);
        return 1;
    }

    if (strfind(buf, "memory", 1)) {
        snprintf(out, sizeof(out), "@ Memory-related issue detected\n\t");
        error_print(out, buf);
        return 1;
    }

    if (strfind(buf, "access violation", 1)) {
        snprintf(out, sizeof(out), "@ Access violation detected\n\t");
        error_print(out, buf);
        return 1;
    }

    if (strfind(buf, "buffer overrun", 1) || strfind(buf, "buffer overflow", 1)) {
        snprintf(out, sizeof(out), "@ Buffer overflow detected\n\t");
        error_print(out, buf);
        return 1;
    }

    if (strfind(buf, "null pointer", 1)) {
        snprintf(out, sizeof(out), "@ Null pointer exception detected\n\t");
        error_print(out, buf);
        return 1;
    }

    return 0;
}

/**
 * Handle out-of-bounds errors
 */
static void
outofbounds_check(const char* buf)
{
    char out[1024];
    int n;
    size_t len;

    n = snprintf(out, sizeof(out), "@ out-of-bounds detected\n\t");
    len = (n < 0) ? 0 : (size_t)n;
    fwrite(out, 1, len, stdout);
    pr_color(stdout, DOG_COL_BLUE, "%s", buf);
    fflush(stdout);

    /* Provide example of correct array handling */
    n = snprintf(out, sizeof(out),
        "  new array[3];\n"
        "  main() {\n"
        "    for (new i = 0; i < 4; i++) < potent 4 of 3\n"
        "                        ^ sizeof(array)   for array[this] and array[this][]\n"
        "                        ^ sizeof(array[]) for array[][this]\n"
        "                        * instead of manual indexing..\n"
        "       array[i] = 0;\n"
        "  }\n");
    len = (n < 0) ? 0 : (size_t)n;
    fwrite(out, 1, len, stdout);
    fflush(stdout);
}

/**
 * Handle critical errors
 */
static void
critical_check(const char* buf)
{
    char out[1024];
    int n;
    size_t len;

    n = snprintf(out, sizeof(out), "@ Critical message found\n\t");
    len = (n < 0) ? 0 : (size_t)n;
    fwrite(out, 1, len, stdout);
    pr_color(stdout, DOG_COL_BLUE, "%s", buf);
    fflush(stdout);

    n = snprintf(out, sizeof(out),
        " * You need to ensure that the file name (.amx),\n"
        "   in your server.cfg under the parameter (gamemode0),\n"
        "   actually exists as a .amx file in the gamemodes/ folder.\n"
        " * If there's only a file with the corresponding name but it's only a single .pwn file,\n"
        "   you need to compile it.\n");
    len = (n < 0) ? 0 : (size_t)n;
    fwrite(out, 1, len, stdout);
    fflush(stdout);
}

/**
 * Handle warning messages
 */
static void
warning_check(const char* buf)
{
    char out[128];

    snprintf(out, sizeof(out), "@ Warning message found\n\t");
    error_print(out, buf);
}

/**
 * Handle failure messages
 */
static void
failure_check(const char* buf)
{
    char out[1024];
    int n;
    size_t len;

    n = snprintf(out, sizeof(out), "@ Failure detected\n\t");
    len = (n < 0) ? 0 : (size_t)n;
    fwrite(out, 1, len, stdout);
    pr_color(stdout, DOG_COL_BLUE, "%s", buf);
    fflush(stdout);

    n = snprintf(out, sizeof(out),
        " * Maybe the plugin failed to load? "
        " * You can try upgrading the failed plugin and, "
        " * if you're on Windows, make sure you have the Visual C++ Redistributable installed.\n\t");
    len = (n < 0) ? 0 : (size_t)n;
    fwrite(out, 1, len, stdout);
    fflush(stdout);
}

/**
 * Handle timeout messages
 */
static void
timeout_check(const char* buf)
{
    char out[128];

    snprintf(out, sizeof(out), "@ Timeout detected\n\t");
    error_print(out, buf);
}

/**
 * Handle plugin-related messages
 */
static void
plugin_check(const char* buf)
{
    char out[1024];
    int n;
    size_t len;

    if (strfind(buf, "failed to load", 1) || strfind(buf, "Failed.", 1)) {
        n = snprintf(out, sizeof(out), "@ Plugin load failure\n\t");
        len = (n < 0) ? 0 : (size_t)n;
        fwrite(out, 1, len, stdout);
        pr_color(stdout, DOG_COL_BLUE, "%s", buf);
        fflush(stdout);

        n = snprintf(out, sizeof(out),
            " * If you need to reinstall a plugin that failed, you can use the command:\n"
            "\n"
            "     install user/repo:tags\n"
            "\n"
            " * Example:\n"
            "\n"
            "     install user/repo:tags\n"
            "\n"
            " * You can also recheck the username shown on the failed plugin using the command:\n"
            "\n"
            "     tracker username\n"
            "\n");
        len = (n < 0) ? 0 : (size_t)n;
        fwrite(out, 1, len, stdout);
        fflush(stdout);
    }

    if (strfind(buf, "unloaded", 1)) {
        n = snprintf(out, sizeof(out), "@ Plugin unloaded\n\t");
        len = (n < 0) ? 0 : (size_t)n;
        fwrite(out, 1, len, stdout);
        pr_color(stdout, DOG_COL_BLUE, "%s", buf);
        fflush(stdout);

        n = snprintf(out, sizeof(out),
            " * LOADED (Active/In Use):\n"
            "   - Plugin is running, all features are available.\n"
            "   - Utilizing system memory and CPU (e.g., running background threads).\n"
            " * UNLOADED (Deactivated/Inactive):\n"
            "   - Plugin has been shut down and removed from memory.\n"
            "   - Features are no longer available; system resources (memory/CPU) are released.\n");
        len = (n < 0) ? 0 : (size_t)n;
        fwrite(out, 1, len, stdout);
        fflush(stdout);
    }
}

/**
 * Handle database-related messages
 */
static void
database_check(const char* buf)
{
    char out[128];

    if (strfind(buf, "connection failed", 1) || strfind(buf, "can't connect", 1)) {
        snprintf(out, sizeof(out), "@ Database connection failure\n\t");
        error_print(out, buf);
    }

    if (strfind(buf, "error", 1) || strfind(buf, "failed", 1)) {
        snprintf(out, sizeof(out), "@ Database error\n\t");
        error_print(out, buf);
    }
}

/**
 * Handle memory allocation errors
 */
static void
memory_check(const char* buf)
{
    char out[128];

    snprintf(out, sizeof(out), "@ Memory allocation failure\n\t");
    error_print(out, buf);
}

/**
 * Handle memory function references
 */
static void
alloc_check(const char* buf)
{
    char out[128];

    snprintf(out, sizeof(out), "@ Memory function referenced\n\t");
    error_print(out, buf);
}

/**
 * Handle info messages
 */
static void
info_check(const char* buf)
{
    char out[128];

    snprintf(out, sizeof(out), "@ Info message found\n\t");
    error_print(out, buf);
}

/**
 * Detect SampVoice port from log
 */
static void
sampvoice_port_detect(const char* buf)
{
    int port;

    if (!strfind(buf, "voice server running on port", 1))
        return;

    if (sscanf(buf, "%*[^v]voice server running on port %d", &port) != 1)
        return;

    rate_sampvoice_server++;
    dog_free(sampvoice_port);

    sampvoice_port = dog_malloc(16);
    if (sampvoice_port)
        snprintf(sampvoice_port, 16, "%d", port);
}

/**
 * Check SampVoice port configuration
 */
static void
sampvoice_port_check(void)
{
    FILE* fp;
    char buf[DOG_MAX_PATH];
    int cfg_port;
    char cfg_port_str[16];

    if (!rate_sampvoice_server)
        return;

    if (path_access("server.cfg") != 1)
        return;

    if (sampvoice_port == NULL)
        return;

    fp = fopen("server.cfg", "rb");
    if (fp == NULL)
        return;

    cfg_port = 0;
    while (fgets(buf, sizeof(buf), fp)) {
        if (strfind(buf, "sv_port", 1)) {
            if (sscanf(buf, "sv_port %d", &cfg_port) == 1)
                break;
        }
    }
    fclose(fp);

    if (cfg_port == 0)
        return;

    snprintf(cfg_port_str, sizeof(cfg_port_str), "%d", cfg_port);

    if (strcmp(cfg_port_str, sampvoice_port) != 0) {
        char out[1024];
        int n;
        size_t len;

        n = snprintf(out, sizeof(out), "@ SampVoice Port Mismatch\n\t");
        len = (n < 0) ? 0 : (size_t)n;
        fwrite(out, 1, len, stdout);

        n = snprintf(out, sizeof(out),
            " * server.cfg: %s, Log: %s\n"
            " * We have detected a mismatch between the sampvoice port in server.cfg\n"
            " * and the one loaded in the server log!\n"
            " ** Please make sure you have correctly set the port in server.cfg.\n",
            cfg_port_str, sampvoice_port);
        len = (n < 0) ? 0 : (size_t)n;
        fwrite(out, 1, len, stdout);
        fflush(stdout);
    }
}

/**
 * Check RCON password issues
 */
static void
rcon_password_check(void)
{
    char* input;
    char out[256];
    int n;
    size_t len;

    if (!server_rcon_pass)
        return;

    n = snprintf(out, sizeof(out),
        "@ Rcon Pass Error found\n\t* Error: Your password must be changed from the default password..\n");
    len = (n < 0) ? 0 : (size_t)n;
    fwrite(out, 1, len, stdout);
    fflush(stdout);

    input = readline("Tree-fix? (Y/n): ");
    if (input && (input[0] == '\0' || input[0] == 'Y' || input[0] == 'y')) {
        rcon_password_fix();
    }
    dog_free(input);
}

/**
 * Fix default RCON password
 */
static void
rcon_password_fix(void)
{
    FILE* fp;
    char* content, * new_content, * pos;
    long size;
    char rand_str[32];
    uint32_t crc;
    char out[1024];
    int n;
    size_t len;

    if (path_access("server.cfg") != 1) {
        n = snprintf(out, sizeof(out), "server.cfg not accessible\n");
        len = (n < 0) ? 0 : (size_t)n;
        fwrite(out, 1, len, stdout);
        return;
    }

    fp = fopen("server.cfg", "rb");
    if (fp == NULL)
        return;

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    content = dog_malloc(size + 1);
    if (content == NULL) {
        fclose(fp);
        return;
    }

    fread(content, 1, size, fp);
    content[size] = '\0';
    fclose(fp);

    pos = strstr(content, "rcon_password changeme");
    if (pos == NULL) {
        n = snprintf(out, sizeof(out),
            "-Replacement failed!\n"
            " It is not known what the primary cause is."
            " A reasonable explanation"
            " is that it occurs when server.cfg does not contain the rcon_password parameter.\n");
        len = (n < 0) ? 0 : (size_t)n;
        fwrite(out, 1, len, stdout);
        dog_free(content);
        return;
    }

    /* Generate random password */
    srand((unsigned int)time(NULL) ^ rand());
    snprintf(rand_str, sizeof(rand_str), "%d", rand() % 10000000);
    crc = crypto_generate_crc32(rand_str, strlen(rand_str));

    new_content = dog_malloc(size + 32);
    if (new_content == NULL) {
        dog_free(content);
        return;
    }

    /* Replace password in config */
    strncpy(new_content, content, pos - content);
    new_content[pos - content] = '\0';

    snprintf(rand_str, sizeof(rand_str), "rcon_password %08X", crc);
    strcat(new_content, rand_str);
    strcat(new_content, pos + strlen("rcon_password changeme"));

    fp = fopen("server.cfg", "wb");
    if (fp) {
        fwrite(new_content, 1, strlen(new_content), fp);
        fclose(fp);
        n = snprintf(out, sizeof(out), "done! * server.cfg - rcon_password from changeme to %08X.\n", crc);
        len = (n < 0) ? 0 : (size_t)n;
        fwrite(out, 1, len, stdout);
        fflush(stdout);
    }
    else {
        n = snprintf(out, sizeof(out), "Error: Cannot write to server.cfg\n");
        len = (n < 0) ? 0 : (size_t)n;
        fwrite(out, 1, len, stdout);
        fflush(stdout);
    }

    dog_free(new_content);
    dog_free(content);
}

/**
 * Check and suggest crashdetect installation
 */
static void
crashdetect_install_check(void)
{
    char* input;
    char out[256];
    int n;
    size_t len;

    if (rate_problem_stat != 1 || server_crashdetect >= 1)
        return;

    n = snprintf(out, sizeof(out), "INFO: crash found! "
        "and crashdetect not found.. "
        "install crashdetect now? (Tree-fix) ");
    len = (n < 0) ? 0 : (size_t)n;
    fwrite(out, 1, len, stdout);
    fflush(stdout);

    input = readline("Y/n ");
    if (input && (input[0] == '\0' || strfind(input, "y", 1)))
        dog_install_depends("Y-Less/samp-plugin-crashdetect?newer", "master", NULL);

    dog_free(input);
}
