#include "../units.h"
#include "../utils.h"
#include "../crypto.h"
#include "../replicate.h"
#include "../compiler.h"
#include "../debug.h"
#include "server.h"

static char sbuf[0x400];
int sigint_handler = 0;
static char *sampvoice_port = NULL;
static int rate_sampvoice_server = 0;
static int rate_problem_stat = 0;
static int server_crashdetect = 0;
static int server_rcon_pass = 0;

void
unit_sigint_handler(int sig __UNUSED__)
{
    /* Set signal handler flag to indicate cleanup is in progress */
    sigint_handler = 1;

    /* Record the time when signal was received */
    struct timespec stop_all_timer;
    clock_gettime(CLOCK_MONOTONIC, &stop_all_timer);
}

/*
 * dog_stop_server_tasks:
 *     Stop running server process.
 */

void
dog_stop_server_tasks(void)
{
    bool ret = false;
    ret = dog_kill_process(dogconfig.dog_toml_server_binary);
    if (ret == false) {
        /* retrying */
        dog_kill_process(dogconfig.dog_toml_server_binary);
    }
}

void
dog_server_crash_check(void)
{
    int n;  /* snprintf return value */
    size_t  size_l;  /* Output size tracker */
    FILE *this_proc_file = NULL;  /* Log file handle */
    char  out[DOG_MAX_PATH + 26]; /* Output buffer */
    char  buf[DOG_MAX_PATH];  /* Line buffer for log reading */
    rate_sampvoice_server = 0;
    rate_problem_stat = 0;
    server_crashdetect = 0;
    server_rcon_pass = 0;
    sampvoice_port = NULL;

    /* Open appropriate log file based on server environment */
    if (fet_server_env() == false)  /* SA-MP */
        this_proc_file = fopen(dogconfig.dog_toml_server_logs, "rb");
    else  /* open.mp */
        this_proc_file = fopen(dogconfig.dog_toml_server_logs, "rb");

    if (this_proc_file == NULL) {
        pr_error(stdout, "log file not found!.");
        minimal_debugging();
        return;
    }

    /* Check for crashinfo.txt file (crashdetect plugin output) */
    if (path_exists("crashinfo.txt") != 0) {
        pr_info(stdout, "crashinfo.txt detected..");
        char *confirm = readline("-> show? ");
        if (confirm && (confirm[0] == '\0' || confirm[0] == 'Y' || confirm[0] == 'y')) {
            dog_printfile("crashinfo.txt");  /* Display crash info */
        }
        dog_free(confirm);
    }

    /* Print separator for log analysis output */
    n = snprintf(out, sizeof(out),
        "--------------------------------------------------------------\n");
    size_l = (n < 0) ? 0 : (size_t)n;
    fwrite(out, 1, size_l, stdout);
    fflush(stdout);

    /* Process log file buffer by buffer */
    while (fgets(buf, sizeof(buf), this_proc_file)) {
        /* Pattern 1: Filterscript loading errors */
        if (strfind(buf, "Unable to load filterscript", true)) {
            n = snprintf(out, sizeof(out),
                "@ Unable to load filterscript detected - Please recompile our filterscripts.\n\t");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            pr_color(stdout, DOG_COL_BLUE, "%s", buf);
            fflush(stdout);
        }

        /* Pattern 2: Invalid index/entry point errors */
        if (strfind(buf, "Invalid index parameter (bad entry point)", true)) {
            n = snprintf(out, sizeof(out),
                "@ Invalid index parameter (bad entry point) detected - You're forget " DOG_COL_CYAN "'main'" DOG_COL_DEFAULT "?\n\t");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            pr_color(stdout, DOG_COL_BLUE, "%s", buf);
            fflush(stdout);
        }

        /* Pattern 3: Runtime errors (most common crash cause) */
        if (strfind(buf, "run time error", true)) {
            rate_problem_stat = 1;  /* Flag that we found a problem */
            n = snprintf(out, sizeof(out), "@ Runtime error detected\n\t");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            pr_color(stdout, DOG_COL_BLUE, "%s", buf);
            fflush(stdout);

            /* Version AMX */
            if (strfind(buf, "\"File is for a newer version of the AMX\"", true)) {
                pr_color(stdout, DOG_COL_BLUE, "%s", buf);
                fflush(stdout);
                n = snprintf(out, sizeof(out), "\tYou need to open watchdogs.toml and "
                    "change -O:2 to -O:1, then recompile your gamemode.\n");
                size_l = (n < 0) ? 0 : (size_t)n;
                fwrite(out, 1, size_l, stdout);
                fflush(stdout);
            }

            /* Specific runtime error subtypes */
            if (strfind(buf, "division by zero", true)) {
                n = snprintf(out, sizeof(out), "@ Division by zero error found\n\t");
                size_l = (n < 0) ? 0 : (size_t)n;
                fwrite(out, 1, size_l, stdout);
                pr_color(stdout, DOG_COL_BLUE, "%s", buf);
                fflush(stdout);
            }
            if (strfind(buf, "invalid index", true)) {
                n = snprintf(out, sizeof(out), "@ Invalid index error found\n\t");
                size_l = (n < 0) ? 0 : (size_t)n;
                fwrite(out, 1, size_l, stdout);
                pr_color(stdout, DOG_COL_BLUE, "%s", buf);
                fflush(stdout);
            }
        }

        /* Pattern 4: Outdated include files requiring recompilation */
        if (strfind(buf, "The script might need to be recompiled with the latest include file.", true)) {
            n = snprintf(out, sizeof(out), "@ Needed for recompiled\n\t");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            pr_color(stdout, DOG_COL_BLUE, "%s", buf);
            fflush(stdout);

            /* Offer tree-fix: recompile script */
            char *recompiled = readline("Recompile now? ");
            if (recompiled && (recompiled[0] == '\0' || !strcmp(recompiled, "Y") || !strcmp(recompiled, "y"))) {
                dog_free(recompiled);
                printf(DOG_COL_BCYAN "Please input the pawn file\n\t* (enter for %s - input E/e to exit):" DOG_COL_DEFAULT, dogconfig.dog_toml_serv_input);
                char *gamemode_compile = readline(" ");
                if (gamemode_compile && strlen(gamemode_compile) < 1) {
                    /* Use default project input */
                    const char *args[] = { NULL, ".", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
                    dog_exec_compiler(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9]);
                    dog_free(gamemode_compile);
                } else if (gamemode_compile) {
                    /* Use specified file */
                    const char *args[] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
                    dog_exec_compiler(args[0], gamemode_compile, args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9]);
                    dog_free(gamemode_compile);
                }
            } else {
                dog_free(recompiled);
            }
        }

        /* Pattern 5: Filesystem errors (common in WSL environments) */
        if (strfind(buf, "terminate called after throwing an instance of 'ghc::filesystem::filesystem_error", true)) {
            n = snprintf(out, sizeof(out), "@ Filesystem C++ Error Detected\n\t");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            pr_color(stdout, DOG_COL_BLUE, "%s", buf);
            fflush(stdout);
            n = snprintf(out, sizeof(out),
                "\tAre you currently using the WSL ecosystem?\n"
                "\tYou need to move the open.mp server folder from the /mnt area (your Windows directory) to \"~\" (your WSL HOME).\n"
                "\tThis is because open.mp C++ filesystem cannot properly read directories inside the /mnt area,\n"
                "\twhich isn't part of the directory model targeted by the Linux build.\n"
                "\t* You must run it outside the /mnt area.\n");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            fflush(stdout);
        }

        /* Pattern 6: SampVoice plugin port detection */
        if (strfind(buf, "voice server running on port", true)) {
            int _sampvoice_port;
            if (scanf("%*[^v]voice server running on port %d", &_sampvoice_port) != 1)
                continue;
            ++rate_sampvoice_server;
            dog_free(sampvoice_port);
            sampvoice_port = (char *)dog_malloc(16);
            if (sampvoice_port) {
                snprintf(sampvoice_port, 16, "%d", _sampvoice_port);
            }
        }

        /* Pattern 7: Missing gamemode files */
        if (strfind(buf, "I couldn't load any gamemode scripts.", true)) {
            n = snprintf(out, sizeof(out), "@ Can't found gamemode detected\n\t");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            pr_color(stdout, DOG_COL_BLUE, "%s", buf);
            fflush(stdout);
            n = snprintf(out, sizeof(out),
                "\tYou need to ensure that the name specified "
                "in the configuration file matches the one in the gamemodes/ folder,\n"
                "\tand that the .amx file exists. For example, "
                "if server.cfg contains " DOG_COL_CYAN "gamemode0" DOG_COL_DEFAULT" main 1 or config.json" DOG_COL_CYAN " pawn.main_scripts [\"main 1\"].\n"
                DOG_COL_DEFAULT
                "\tthen main.amx must be present in the gamemodes/ directory\n");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            fflush(stdout);
        }

        /* Pattern 8: Memory address references (potential crashes) */
        if (strfind(buf, "0x", true)) {
            n = snprintf(out, sizeof(out), "@ Hexadecimal address found\n\t");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            pr_color(stdout, DOG_COL_BLUE, "%s", buf);
            fflush(stdout);
        }
        if (strfind(buf, "address", true) || strfind(buf, "Address", true)) {
            n = snprintf(out, sizeof(out), "@ Memory address reference found\n\t");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            pr_color(stdout, DOG_COL_BLUE, "%s", buf);
            fflush(stdout);
        }

        /* Pattern 9: Crashdetect plugin output (detailed crash info) */
        if (rate_problem_stat) {
            if (strfind(buf, "[debug]", true) || strfind(buf, "crashdetect", true)) {
                ++server_crashdetect;
                n = snprintf(out, sizeof(out), "@ Crashdetect: Crashdetect debug information found\n\t");
                size_l = (n < 0) ? 0 : (size_t)n;
                fwrite(out, 1, size_l, stdout);
                pr_color(stdout, DOG_COL_BLUE, "%s", buf);
                fflush(stdout);

                /* Crashdetect-specific patterns */
                if (strfind(buf, "AMX backtrace", true)) {
                    n = snprintf(out, sizeof(out), "@ Crashdetect: AMX backtrace detected in crash log\n\t");
                    size_l = (n < 0) ? 0 : (size_t)n;
                    fwrite(out, 1, size_l, stdout);
                    pr_color(stdout, DOG_COL_BLUE, "%s", buf);
                    fflush(stdout);
                }
                if (strfind(buf, "native stack trace", true)) {
                    n = snprintf(out, sizeof(out), "@ Crashdetect: Native stack trace detected\n\t");
                    size_l = (n < 0) ? 0 : (size_t)n;
                    fwrite(out, 1, size_l, stdout);
                    pr_color(stdout, DOG_COL_BLUE, "%s", buf);
                    fflush(stdout);
                }
                if (strfind(buf, "heap", true)) {
                    n = snprintf(out, sizeof(out), "@ Crashdetect: Heap-related issue mentioned\n\t");
                    size_l = (n < 0) ? 0 : (size_t)n;
                    fwrite(out, 1, size_l, stdout);
                    pr_color(stdout, DOG_COL_BLUE, "%s", buf);
                    fflush(stdout);
                }
                if (strfind(buf, "[debug]", true)) {
                    n = snprintf(out, sizeof(out), "@ Crashdetect: Debug Detected\n\t");
                    size_l = (n < 0) ? 0 : (size_t)n;
                    fwrite(out, 1, size_l, stdout);
                    pr_color(stdout, DOG_COL_BLUE, "%s", buf);
                    fflush(stdout);
                }

                /* Native backtrace with plugin conflict detection */
                if (strfind(buf, "Native backtrace", true)) {
                    n = snprintf(out, sizeof(out), "@ Crashdetect: Native backtrace detected\n\t");
                    size_l = (n < 0) ? 0 : (size_t)n;
                    fwrite(out, 1, size_l, stdout);
                    pr_color(stdout, DOG_COL_BLUE, "%s", buf);
                    fflush(stdout);

                    /* Detect SampVoice and Pawn.Raknet plugin conflicts */
                    if (strfind(buf, "sampvoice", true)) {
                        if(strfind(buf, "pawnraknet", true)) {
                            n = snprintf(out, sizeof(out), "@ Crashdetect: Crash potent detected\n\t");
                            size_l = (n < 0) ? 0 : (size_t)n;
                            fwrite(out, 1, size_l, stdout);
                            pr_color(stdout, DOG_COL_BLUE, "%s", buf);
                            fflush(stdout);
                            n = snprintf(out, sizeof(out),
                                "\tWe have detected a crash and identified two plugins as potential causes,\n"
                                "\tnamely SampVoice and Pawn.Raknet.\n"
                                "\tAre you using SampVoice version 3.1?\n"
                                "\tYou can downgrade to SampVoice version 3.0 if necessary,\n"
                                "\tor you can remove either Sampvoice or Pawn.Raknet to avoid a potential crash.\n"
                                "\tYou can review the changes between versions 3.0 and 3.1 to understand and analyze the possible reason for the crash\n"
                                "\ton here: https://github.com/CyberMor/sampvoice/compare/v3.0-alpha...v3.1\n");
                            size_l = (n < 0) ? 0 : (size_t)n;
                            fwrite(out, 1, size_l, stdout);
                            fflush(stdout);

                            print("\x1b[32m==> downgrading sampvoice? 3.1 -> 3.0? \x1b[0m\n");
                            fwrite(out, 1, size_l, stdout);
                            fflush(stdout);
                            char *downgrading = readline("   answer (y/n): ");
                            if (downgrading && (downgrading[0] == '\0' || strcmp(downgrading, "Y") == 0 || strcmp(downgrading, "y") == 0)) {
                                dog_install_depends("CyberMor/sampvoice?v3.0-alpha", "master", NULL);
                            }
                            dog_free(downgrading);
                        }
                    }
                }
            }

            /* Memory-related error patterns */
            if (strfind(buf, "stack", true)) {
                n = snprintf(out, sizeof(out), "@ Stack-related issue detected\n\t");
                size_l = (n < 0) ? 0 : (size_t)n;
                fwrite(out, 1, size_l, stdout);
                pr_color(stdout, DOG_COL_BLUE, "%s", buf);
                fflush(stdout);
            }
            if (strfind(buf, "memory", true)) {
                n = snprintf(out, sizeof(out), "@ Memory-related issue detected\n\t");
                size_l = (n < 0) ? 0 : (size_t)n;
                fwrite(out, 1, size_l, stdout);
                pr_color(stdout, DOG_COL_BLUE, "%s", buf);
                fflush(stdout);
            }
            if (strfind(buf, "access violation", true)) {
                n = snprintf(out, sizeof(out), "@ Access violation detected\n\t");
                size_l = (n < 0) ? 0 : (size_t)n;
                fwrite(out, 1, size_l, stdout);
                pr_color(stdout, DOG_COL_BLUE, "%s", buf);
                fflush(stdout);
            }
            if (strfind(buf, "buffer overrun", true) || strfind(buf, "buffer overflow", true)) {
                n = snprintf(out, sizeof(out), "@ Buffer overflow detected\n\t");
                size_l = (n < 0) ? 0 : (size_t)n;
                fwrite(out, 1, size_l, stdout);
                pr_color(stdout, DOG_COL_BLUE, "%s", buf);
                fflush(stdout);
            }
            if (strfind(buf, "null pointer", true)) {
                n = snprintf(out, sizeof(out), "@ Null pointer exception detected\n\t");
                size_l = (n < 0) ? 0 : (size_t)n;
                fwrite(out, 1, size_l, stdout);
                pr_color(stdout, DOG_COL_BLUE, "%s", buf);
                fflush(stdout);
            }
        }

        /* Pattern 10: Array out-of-bounds errors with example fix */
        if (strfind(buf, "out of bounds", true) ||
            strfind(buf, "out-of-bounds", true)) {
            n = snprintf(out, sizeof(out), "@ out-of-bounds detected\n\t");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            pr_color(stdout, DOG_COL_BLUE, "%s", buf);
            fflush(stdout);
            n = snprintf(out, sizeof(out),
                "\tnew array[3];\n"
                "\tmain() {\n"
                "\t  for (new i = 0; i < 4; i++) < potent 4 of 3\n"
                "\t                      ^ sizeof(array)   for array[this] and array[this][]\n"
                "\t                      ^ sizeof(array[]) for array[][this]\n"
                "\t                      * instead of manual indexing..\n"
                "\t     array[i] = 0;\n"
                "\t}\n");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            fflush(stdout);
        }

        /* Pattern 11: RCON password security warning (SA-MP specific) */
        if (fet_server_env() == false) {
            if (strfind(buf, "Your password must be changed from the default password", true)) {
                ++server_rcon_pass;
            }
        }

        /* Pattern 12: Missing gamemode0 configuration buffer */
        if (strfind(buf, "It needs a gamemode0 buffer", true)) {
            n = snprintf(out, sizeof(out), "@ Critical message found\n\t");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            pr_color(stdout, DOG_COL_BLUE, "%s", buf);
            fflush(stdout);
            n = snprintf(out, sizeof(out),
                "\tYou need to ensure that the file name (.amx),\n"
                "\tin your server.cfg under the parameter (gamemode0),\n"
                "\tactually exists as a .amx file in the gamemodes/ folder.\n"
                "\tIf there's only a file with the corresponding name but it's only a single .pwn file,\n"
                "\tyou need to compile it.\n");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            fflush(stdout);
        }

        /* Pattern 13: Generic warning messages */
        if (strfind(buf, "warning", true)) {
            n = snprintf(out, sizeof(out), "@ Warning message found\n\t");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            pr_color(stdout, DOG_COL_BLUE, "%s", buf);
            fflush(stdout);
        }

        /* Pattern 14: Failure messages */
        if (strfind(buf, "failed", true)) {
            n = snprintf(out, sizeof(out), "@ Failure or Failed message detected\n\t");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            pr_color(stdout, DOG_COL_BLUE, "%s", buf);
            fflush(stdout);
        }

        /* Pattern 15: Timeout events */
        if (strfind(buf, "timeout", true)) {
            n = snprintf(out, sizeof(out), "@ Timeout event detected\n\t");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            pr_color(stdout, DOG_COL_BLUE, "%s", buf);
            fflush(stdout);
        }

        /* Pattern 16: Plugin-related issues */
        if (strfind(buf, "plugin", true)) {
            if (strfind(buf, "failed to load", true) || strfind(buf, "Failed.", true)) {
                n = snprintf(out, sizeof(out), "@ Plugin load failure or failed detected\n\t");
                size_l = (n < 0) ? 0 : (size_t)n;
                fwrite(out, 1, size_l, stdout);
                pr_color(stdout, DOG_COL_BLUE, "%s", buf);
                fflush(stdout);
                n = snprintf(out, sizeof(out),
                    "\tIf you need to reinstall a plugin that failed, you can use the command:\n"
                    "\t\tinstall user/repo:tags\n"
                    "\tExample:\n"
                    "\t\tinstall Y-Less/sscanf?newer\n"
                    "\tYou can also recheck the username shown on the failed plugin using the command:\n"
                    "\t\ttracker name\n");
                size_l = (n < 0) ? 0 : (size_t)n;
                fwrite(out, 1, size_l, stdout);
                fflush(stdout);
            }
            if (strfind(buf, "unloaded", true)) {
                n = snprintf(out, sizeof(out), "@ Plugin unloaded detected\n\t");
                size_l = (n < 0) ? 0 : (size_t)n;
                fwrite(out, 1, size_l, stdout);
                pr_color(stdout, DOG_COL_BLUE, "%s", buf);
                fflush(stdout);
                n = snprintf(out, sizeof(out),
                    "\tLOADED (Active/In Use):\n"
                    "\t  - Plugin is running, all features are available.\n"
                    "\t  - Utilizing system memory and CPU (e.g., running background threads).\n"
                    "\tUNLOADED (Deactivated/Inactive):\n"
                    "\t  - Plugin has been shut down and removed from memory.\n"
                    "\t  - Features are no longer available; system resources (memory/CPU) are released.\n");
                size_l = (n < 0) ? 0 : (size_t)n;
                fwrite(out, 1, size_l, stdout);
                fflush(stdout);
            }
        }

        /* Pattern 17: Database/MySQL connection issues */
        if (strfind(buf, "database", true) || strfind(buf, "mysql", true)) {
            if (strfind(buf, "connection failed", true) || strfind(buf, "can't connect", true)) {
                n = snprintf(out, sizeof(out), "@ Database connection failure detected\n\t");
                size_l = (n < 0) ? 0 : (size_t)n;
                fwrite(out, 1, size_l, stdout);
                pr_color(stdout, DOG_COL_BLUE, "%s", buf);
                fflush(stdout);
            }
            if (strfind(buf, "error", true) || strfind(buf, "failed", true)) {
                n = snprintf(out, sizeof(out), "@ Error or Failed database | mysql found\n\t");
                size_l = (n < 0) ? 0 : (size_t)n;
                fwrite(out, 1, size_l, stdout);
                pr_color(stdout, DOG_COL_BLUE, "%s", buf);
                fflush(stdout);
            }
        }

        /* Pattern 18: Memory allocation failures */
        if (strfind(buf, "out of memory", true) || strfind(buf, "memory allocation", true)) {
            n = snprintf(out, sizeof(out), "@ Memory allocation failure detected\n\t");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            pr_color(stdout, DOG_COL_BLUE, "%s", buf);
            fflush(stdout);
        }

        /* Pattern 19: Memory management function references */
        if (strfind(buf, "malloc", true) || strfind(buf, "free", true) ||
            strfind(buf, "realloc", true) || strfind(buf, "calloc", true)) {
            n = snprintf(out, sizeof(out), "@ Memory management function referenced\n\t");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            pr_color(stdout, DOG_COL_BLUE, "%s", buf);
            fflush(stdout);
        }

        /* Pattern 20: Info Message */
        if (strfind(buf, "Info", true)) {
            n = snprintf(out, sizeof(out), "@ Info message found\n\t");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            pr_color(stdout, DOG_COL_BLUE, "%s", buf);
        }

        fflush(stdout);
    }

    fclose(this_proc_file);

    /* SampVoice port mismatch detection */
    if (rate_sampvoice_server) {
        if (path_access("server.cfg") == 0)
            goto skip;  /* No server.cfg to check */

        this_proc_file = fopen("server.cfg", "rb");
        if (this_proc_file == NULL)
            goto skip;

        int _sampvoice_port = 0;
        char _p_sampvoice_port[16] = {0};

        /* Find sv_port setting in server.cfg */
        while (fgets(buf, sizeof(buf), this_proc_file)) {
            if (strfind(buf, "sv_port", true)) {
                if (sscanf(buf, "sv_port %d", &_sampvoice_port) != 1)
                    break;
                snprintf(_p_sampvoice_port, sizeof(_p_sampvoice_port), "%d", _sampvoice_port);
                break;
            }
        }
        fclose(this_proc_file);

        /* Compare configured port with actual running port */
        if (sampvoice_port && strcmp(_p_sampvoice_port, sampvoice_port) != 0) {
            n = snprintf(out, sizeof(out), "@ SampVoice Port\n\t");
            size_l = (n < 0) ? 0 : (size_t)n;
            pr_color(stdout, DOG_COL_BLUE, "in server.cfg: %s in server logs: %s", _p_sampvoice_port, sampvoice_port);
            fwrite(out, 1, size_l, stdout);
            n = snprintf(out, sizeof(out),
                "\tWe have detected a mismatch between the sampvoice port in server.cfg\n"
                "\tand the one loaded in the server log!\n"
                "\t* Please make sure you have correctly set the port in server.cfg.\n");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            fflush(stdout);
        }
    }

skip:
    /* RCON password tree-fix for default password vulnerability */
    if (server_rcon_pass) {
        n = snprintf(out, sizeof(out),
            "@ Rcon Pass Error found\n\t* Error: Your password must be changed from the default password..\n");
        size_l = (n < 0) ? 0 : (size_t)n;
        fwrite(out, 1, size_l, stdout);
        fflush(stdout);

        /* Offer to tree-fix RCON password */
        char *fixed_now = readline("Tree-fix? (Y/n): ");

        if (fixed_now && (fixed_now[0] == '\0' || !strcmp(fixed_now, "Y") || !strcmp(fixed_now, "y"))) {
            if (path_access("server.cfg")) {
            FILE *read_f = fopen("server.cfg", "rb");
            if (read_f) {
                /* Read entire server.cfg into memory */
                fseek(read_f, 0, SEEK_END);
                long server_fle_size = ftell(read_f);
                fseek(read_f, 0, SEEK_SET);

                char *serv_f_cent = NULL;
                serv_f_cent = dog_malloc(server_fle_size + (size_t)1);
                if (!serv_f_cent) { goto skip_fixing; }

                size_t br;
                br = fread(serv_f_cent, 1, server_fle_size, read_f);
                serv_f_cent[br] = '\0';
                fclose(read_f);

                /* Find and replace default RCON password */
                char *server_n_content = NULL;
                char *pos = strstr(serv_f_cent, "rcon_password changeme");

                uint32_t crc32_generate;
                if (pos) {
                server_n_content = dog_malloc(server_fle_size + (size_t)10);
                if (!server_n_content) {
                    dog_free(serv_f_cent);
                    goto skip_fixing;
                }

                /* Copy content before the password */
                strncpy(server_n_content, serv_f_cent, pos - serv_f_cent);
                server_n_content[pos - serv_f_cent] = '\0';

                srand((unsigned int)time(NULL) ^ rand());
                int rand7 = rand() % 10000000;
                char size_rand7[DOG_PATH_MAX];
                n = snprintf(size_rand7, sizeof(size_rand7), "%d", rand7);
                crc32_generate = crypto_generate_crc32(size_rand7, sizeof(size_rand7) - 1);

                /* Format new password buffer */
                char crc_str[14 + 11 + 1];
                sprintf(crc_str, "rcon_password %08X", crc32_generate);

                /* Build new file content */
                strcat(server_n_content, crc_str);
                strcat(server_n_content, pos + strlen("rcon_password changeme"));
                }

                /* Write updated content back to file */
                if (server_n_content) {
                    FILE *write_f = fopen("server.cfg", "wb");
                    if (write_f) {
                            fwrite(server_n_content, 1, strlen(server_n_content), write_f);
                            fclose(write_f);
                            n = snprintf(out, sizeof(out), "done! * server.cfg - rcon_password from changeme to %08X.\n", crc32_generate);
                            size_l = (n < 0) ? 0 : (size_t)n;
                            fwrite(out, 1, size_l, stdout);
                            fflush(stdout);
                    } else {
                            n = snprintf(out, sizeof(out), "Error: Cannot write to server.cfg\n");
                            size_l = (n < 0) ? 0 : (size_t)n;
                            fwrite(out, 1, size_l, stdout);
                            fflush(stdout);
                    }
                    dog_free(server_n_content);
                } else {
                    n = snprintf(out, sizeof(out),
                            "-Replacement failed!\n"
                            " It is not known what the primary cause is."
                            " A reasonable explanation"
                            " is that it occurs when server.cfg does not contain the rcon_password parameter.\n");
                    size_l = (n < 0) ? 0 : (size_t)n;
                    fwrite(out, 1, size_l, stdout);
                    fflush(stdout);
                }
                dog_free(serv_f_cent);
            }
        }
        }
        dog_free(fixed_now);
    }

skip_fixing:
    /* Print closing separator */
    n = snprintf(out, sizeof(out),
        "--------------------------------------------------------------\n");
    size_l = (n < 0) ? 0 : (size_t)n;
    fwrite(out, 1, size_l, stdout);
    fflush(stdout);

    /* Cleanup SampVoice port memory */
    if (sampvoice_port) {
        free(sampvoice_port);
        sampvoice_port = NULL;
    }

    /* Offer to install crashdetect plugin if crashes detected but plugin missing */
    if (rate_problem_stat == 1 && server_crashdetect < 1) {
            n = snprintf(out, sizeof(out), "INFO: crash found! "
                    "and crashdetect not found.. "
                    "install crashdetect now? (Tree-fix) ");
            size_l = (n < 0) ? 0 : (size_t)n;
            fwrite(out, 1, size_l, stdout);
            fflush(stdout);

            char *confirm;
            confirm = readline("Y/n ");
            if (confirm && (confirm[0] == '\0' || strfind(confirm, "y", true))) {
                dog_free(confirm);
                dog_install_depends("Y-Less/samp-plugin-crashdetect?newer", "master", NULL);
            } else {
                dog_free(confirm);
                return;
            }
    }

    return;
}