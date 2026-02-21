#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include  "utils.h"
#include  "crypto.h"
#include  "library.h"
#include  "archive.h"
#include  "curl.h"
#include  "extra/server.h"
#include  "compiler.h"
#include  "replicate.h"
#include  "extra/debug.h"
#include  "units.h"

#if defined(__W_VERSION__)
#define WATCHDOGS_RELEASE __W_VERSION__
#else
#define WATCHDOGS_RELEASE "WATCHDOGS"
#endif

const char *  watchdogs_release = WATCHDOGS_RELEASE;
bool          unit_selection_stat = false;
static struct timespec cmd_start = { 0 };
static struct timespec cmd_end = { 0 };
static double command_dur;
static char tmp_buf[DOG_MAX_PATH * 2];

static void
cleanup_local_resources(char **ptr_command_prompt, char **ptr_command, 
                       char **title_running_info,
                       char **size_command_ptr,
                       char **platform_ptr, char **signal_ptr,
                       char **debug_server_ptr, char **args_ptr,
                       char **compile_target_ptr)
{
    // ptr prompt free
    if (ptr_command_prompt && *ptr_command_prompt) {
        free(*ptr_command_prompt);
        *ptr_command_prompt = NULL;
    }
    // ptr command free
    if (ptr_command && *ptr_command) {
        free(*ptr_command);
        *ptr_command = NULL;
    }
    // title running info free
    if (title_running_info && *title_running_info) {
        free(*title_running_info);
        *title_running_info = NULL;
    }
    // size command ptr free
    if (size_command_ptr && *size_command_ptr) {
        free(*size_command_ptr);
        *size_command_ptr = NULL;
    }
    // platform free
    if (platform_ptr && *platform_ptr) {
        free(*platform_ptr);
        *platform_ptr = NULL;
    }
    // signal free
    if (signal_ptr && *signal_ptr) {
        free(*signal_ptr);
        *signal_ptr = NULL;
    }
    // debug server ptr free
    if (debug_server_ptr && *debug_server_ptr) {
        free(*debug_server_ptr);
        *debug_server_ptr = NULL;
    }
    // args ptr free
    if (args_ptr && *args_ptr) {
        free(*args_ptr);
        *args_ptr = NULL;
    }
    // compile target ptr free
    if (compile_target_ptr && *compile_target_ptr) {
        free(*compile_target_ptr);
        *compile_target_ptr = NULL;
    }
}

static
void unit_show_help(const char *cmd)
{
	if (strlen(cmd) == 0) {
	static const char *help_text =
	"Usage: help <command> | help sha1\n\n"
	"Commands:\n"
	"  exit @ exit from watchdogs | "
	"Usage: \"exit\" " DOG_COL_YELLOW "\n  ; Just type 'exit' and you're outta here!" DOG_COL_DEFAULT "\n"
	"  sha1 @ generate sha1 hash | "
	"Usage: \"sha1\" | [<args>] " DOG_COL_YELLOW "\n  ; Get that SHA1 hash for your text." DOG_COL_DEFAULT "\n"
	"  sha256 @ generate sha256 hash | "
	"Usage: \"sha256\" | [<args>] " DOG_COL_YELLOW "\n  ; Get that SHA256 hash for your text." DOG_COL_DEFAULT "\n"
	"  crc32 @ generate crc32 checksum | "
	"Usage: \"crc32\" | [<args>] " DOG_COL_YELLOW "\n  ; Quick CRC32 checksum generation." DOG_COL_DEFAULT "\n"
	"  djb2 @ generate djb2 hash file | "
	"Usage: \"djb2\" | [<args>] " DOG_COL_YELLOW "\n  ; djb2 hashing for your files." DOG_COL_DEFAULT "\n"
	"  pbkdf2 @ generate passphrase | "
	"Usage: \"pbkdf2\" | [<args>] " DOG_COL_YELLOW "\n  ; Password to Passphrase." DOG_COL_DEFAULT "\n"
    "  base64encode @ encode data to Base64 | "
    "Usage: \"base64encode\" | [<file/text>] " DOG_COL_YELLOW "\n  ; Convert file or plain text into Base64 string." DOG_COL_DEFAULT "\n"
    "  base64decode @ decode Base64 to text | "
    "Usage: \"base64decode\" | [<base64 text>] " DOG_COL_YELLOW "\n  ; Convert Base64 string back to readable text." DOG_COL_DEFAULT "\n"
    "  aesencrypt @ encrypt text using AES | "
    "Usage: \"aesencrypt\" | [<text>] " DOG_COL_YELLOW "\n  ; AES encryption (16-byte block)." DOG_COL_DEFAULT "\n"
    "  aesdecrypt @ decrypt text using AES | "
    "Usage: \"aesdecrypt\" | [<text>] " DOG_COL_YELLOW "\n  ; AES decryption (16-byte block)." DOG_COL_DEFAULT "\n"
	"  config @ re-write watchdogs.toml | "
	"Usage: \"config\" " DOG_COL_YELLOW "\n  ; Reset your config file to default settings." DOG_COL_DEFAULT "\n"
	"  replicate @ dependency installer | "
	"Usage: \"replicate\" " DOG_COL_YELLOW "\n  ; Downloads & Install Our Dependencies." DOG_COL_DEFAULT "\n"
	"  gamemode @ download SA-MP gamemode | "
	"Usage: \"gamemode\" " DOG_COL_YELLOW "\n  ; Grab some SA-MP gamemodes quickly." DOG_COL_DEFAULT "\n"
	"  pawncc @ download SA-MP pawncc | "
	"Usage: \"pawncc\" " DOG_COL_YELLOW "\n  ; Get the Pawn Compiler for SA-MP/open.mp." DOG_COL_DEFAULT "\n"
	"  debug @ debugging & logging server logs | "
	"Usage: \"debug\" " DOG_COL_YELLOW "\n  ; Keep an eye on your server logs." DOG_COL_DEFAULT "\n"
	"  compile @ compile your project | "
	"Usage: \"compile\" | [<args>] " DOG_COL_YELLOW "\n  ; Turn your code into something runnable!" DOG_COL_DEFAULT "\n"
	"  decompile @ de-compile your project | "
	"Usage: \"decompile\" | [<args>] " DOG_COL_YELLOW "\n  ; De-compile .amx into readable .asm." DOG_COL_DEFAULT "\n"
	"  running @ running your project | "
	"Usage: \"running\" | [<args>] " DOG_COL_YELLOW "\n  ; Fire up your project and see it in action." DOG_COL_DEFAULT "\n"
	"  compiles @ compile and running your project | "
	"Usage: \"compiles\" | [<args>] " DOG_COL_YELLOW "\n  ; Two-in-one: compile then run immediately!." DOG_COL_DEFAULT "\n"
	"  stop @ stopped server tasks | "
	"Usage: \"stop\" " DOG_COL_YELLOW "\n  ; Halt everything! Stop your server tasks." DOG_COL_DEFAULT "\n"
	"  restart @ re-start server tasks | "
	"Usage: \"restart\" " DOG_COL_YELLOW "\n  ; Fresh start! Restart your server." DOG_COL_DEFAULT "\n"
	"  tracker @ account tracking | "
	"Usage: \"tracker\" | [<args>] " DOG_COL_YELLOW "\n  ; Track accounts across platforms." DOG_COL_DEFAULT "\n"
	"  compress @ create a compressed archive | "
	"Usage: \"compress <input> <output>\" " DOG_COL_YELLOW "\n  ; Generates a compressed file (e.g., .zip/.tar.gz) from the specified source." DOG_COL_DEFAULT "\n";
	fwrite(help_text, 1, strlen(help_text), stdout);
	return;
	}

	static const struct {
		const char *cmd;
		const char *help;
	} cmd_help[] = {
		{"exit", "exit: exit from watchdogs. | Usage: \"exit\"\n\tJust type 'exit' and you're outta here!\n"},
		{"sha1", "sha1: generate sha1. | Usage: \"sha1\" | [<args>]\n\tGet that SHA1 hash for your text.\n"},
		{"sha256", "sha256: generate sha256. | Usage: \"sha256\" | [<args>]\n\tGet that SHA256 hash for your text.\n"},
		{"crc32", "crc32: generate crc32. | Usage: \"crc32\" | [<args>]\n\tQuick CRC32 checksum generation.\n"},
		{"djb2", "djb2: generate djb2 hash file. | Usage: \"djb2\" | [<args>]\n\tdjb2 hashing for your files.\n"},
		{"pbkdf2", "pbkdf2: generate passphrase. | Usage: \"pbkdf2\" | [<args>]\n\tPassword to Passphrase.\n"},
        {"base64encode", "base64encode: encode data to Base64. | Usage: \"base64encode\" | [<file/text>]\n\tConvert file or plain text into Base64 string.\n"},
        {"base64decode", "base64decode: decode Base64 string. | Usage: \"base64decode\" | [<base64 text>]\n\tConvert Base64 string back to readable text.\n"},
        {"aesencrypt", "aesencrypt: encrypt text using AES. | Usage: \"aesencrypt\" | [<text>]\n\tAES block encryption (16-byte block).\n"},
        {"aesdecrypt", "aesdecrypt: decrypt text using AES. | Usage: \"aesdecrypt\" | [<text>]\n\tAES block decryption (16-byte block).\n"},
		{"config", "config: re-write watchdogs.toml. | Usage: \"config\"\n\tReset your config file to default settings.\n"},
		{"replicate", "replicate: dependency installer. | Usage: \"replicate\"\n\tDownloads & Install Our Dependencies.\n"},
		{"gamemode", "gamemode: download SA-MP gamemode. | Usage: \"gamemode\"\n\tGrab some SA-MP gamemodes quickly.\n"},
		{"pawncc", "pawncc: download SA-MP pawncc. | Usage: \"pawncc\"\n\tGet the Pawn Compiler for SA-MP/open.mp.\n"},
		{"debug", "debug: debugging & logging server debug. | Usage: \"debug\"\n\tKeep an eye on your server logs.\n"},
		{"compile", "compile: compile your project. | Usage: \"compile\" | [<args>]\n\tTurn your code into something runnable!\n"},
		{"decompile", "decompile: decompile your project. | Usage: \"decompile\" | [<args>]\n\tDecompile .amx -> .asm\n"},
		{"running", "running: running your project. | Usage: \"running\" | [<args>]\n\tFire up your project and see it in action.\n"},
		{"compiles", "compiles: compile and running your project. | Usage: \"compiles\" | [<args>]\n\tTwo-in-one: compile then run immediately!\n"},
		{"stop", "stop: stopped server task. | Usage: \"stop\"\n\tHalt everything! Stop your server tasks.\n"},
		{"restart", "restart: re-start server task. | Usage: \"restart\"\n\tFresh start! Restart your server.\n"},
		{"tracker", "tracker: account tracking. | Usage: \"tracker\" | [<args>]\n\tTrack accounts across platforms.\n"},
		{"compress", "compress: create a compressed archive from a file or folder. | Usage: \"compress <input> <output>\"\n\t"
      "Generates a compressed file (e.g., .zip/.tar.gz) from the specified source.\n"}
	};

	for (size_t i = 0; i < sizeof(cmd_help) / sizeof(cmd_help[0]); i++) {
		if (strcmp(cmd, cmd_help[i].cmd) == 0) {
			print(cmd_help[i].help);
			return;
		}
	}

	print("help can't found for: '");
	pr_color(stdout, DOG_COL_YELLOW, "%s", cmd);
	print("'\n     Oops! That command doesn't exist. Try 'help' to see available commands.\n");
}

static
void unit_show_dog(void) {
	if (path_exists(".watchdogs/notice") == 0) {
        print(" type: touch .watchdogs/notice | type nul > .watchdogs/notice for hide this message.\n");
        #ifndef DOG_ANDROID
        static const char *dog_ascii =
            "\n                         \\/%%#z.     \\/.%%#z./   /,z#%%\\/\n"
            "                         \\X##k      /X#####X\\   /d##X/\n"
            "                         \\888\\   /888/ \\888\\   /888/\n"
            "                        `v88;  ;88v'   `v88;  ;88v'\n"
            "                         \\77xx77/       \\77xx77/\n"
            "                        `::::'         `::::'\n\n"
            "---------------------------------------------------------------------------------------------\n"
            "                                            -----------------------------------------        \n"
            "      ;printf(\"Hello, World\")               |  plugin installer                     |        \n"
            "                                            v          v                            |        \n"
            "pawncc | compile | gamemode | running | compiles | replicate | restart | stop       |        \n"
            "  ^        ^          ^          ^ -----------------------       ^         ^        v        \n"
            "  -------  ---------   ------------------                |       |         | compile n run  \n"
            "        v          |                    |                |       v         --------          \n"
            " install compiler  v                    v                v  restart server        |          \n"
            "               compile gamemode  install gamemode  running server             stop server    \n"
            "---------------------------------------------------------------------------------------------\n";
        #else
        static const char *dog_ascii =
            "\n          \\/%%#z.     \\/.%%#z./   /,z#%%\\/\n"
            "          \\X##k      /X#####X\\   /d##X/\n"
            "          \\888\\   /888/ \\888\\   /888/\n"
            "         `v88;  ;88v'   `v88;  ;88v'\n"
            "          \\77xx77/       \\77xx77/\n"
            "         `::::'         `::::'\n\n";
        #endif
        fwrite(dog_ascii, 1, strlen(dog_ascii), stdout);
        print("Use \"help\" for more.\n");
	}
}

static
void
checkout_unit_rule(void)
{
    if (compiling_gamemode == true) {
        compiling_gamemode = false;
        const char *argsc[] = { NULL, NULL, NULL,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL };
        pr_info(stdout,
            "After compiling the script, type "
            DOG_COL_YELLOW "running " DOG_COL_DEFAULT "to start your server..");
        dog_exec_compiler(argsc[0], argsc[1], argsc[2],
            argsc[3], argsc[4], argsc[5], argsc[6], argsc[7],
            argsc[8], argsc[9]);
    }
    static bool rate_stdlib = false;
    if (pawn_missing_stdlib == true &&
        rate_stdlib == false)
    {
        rate_stdlib = !rate_stdlib;
        print("\n");
        if (fet_server_env()==false) {
            pr_info(stdout,
                "can't found sa-mp stdlib.. installing...");
            pr_info(stdout,
                "select version:\n\t1: 0.3.DL-R1 | 2: 0.3.7-R2-1-1");
            char *version = readline("> ");
            if (version[0] == '\0' || version[0] == '2') {
                dog_install_depends(
                    "gskeleton/samp-stdlib",
                    "main",
                    NULL);
            } else {
                dog_install_depends(
                    "gskeleton/samp-stdlib",
                    "0.3.dl",
                    NULL);
            }
            dog_free(version);
        } else {
            pr_info(stdout,
                "can't found open.mp stdlib.. installing..");
            dog_install_depends(
                "openmultiplayer/omp-stdlib",
                "master",
                NULL);
        }
        unit_ret_main("compile");
    }
}

static
int
__command__(char *unit_pre_command)
{
    unit_debugging(0);
    
    memset(&cmd_start, 0, sizeof(cmd_start));
    memset(&cmd_end, 0, sizeof(cmd_end));

    char *ptr_command_prompt = NULL;
    size_t size_ptr_command = DOG_MAX_PATH + DOG_PATH_MAX;
    char *ptr_command = NULL;
    const char *command_similar = NULL;
    int dist = INT_MAX;
    int ret_code = -1;
    
    char *title_running_info = NULL;
    char *size_command = NULL;
    char *platform = NULL;
    char *pointer_signalA = NULL;
    char *debug_server = NULL;
    char *size_args = NULL;
    char *compile_target = NULL;

    checkout_unit_rule();

    ptr_command_prompt = dog_malloc(size_ptr_command);
    if (!ptr_command_prompt) {
        ret_code = -1;
        goto cleanup;
    }
    
    if (ptr_command) {
        free(ptr_command);
        ptr_command = NULL;
    }

    static bool unit_initial = false;
    if (!unit_initial) {
        unit_initial = true;
        using_history();
        unit_show_dog();
    }
    
    if (unit_pre_command && unit_pre_command[0] != '\0') {
        ptr_command = strdup(unit_pre_command);
        if (!ptr_command) {
            ret_code = -1;
            goto cleanup;
        }
        if (strfind(ptr_command, "812C397D", true) == 0) {
            printf("# %s\n", ptr_command);
        }
    } else {
        while (true) {
            snprintf(ptr_command_prompt, size_ptr_command, "# ");
            char *ptr_command_input = readline(ptr_command_prompt);
            fflush(stdout);
            if (!ptr_command_input) {
                ret_code = 2;
                goto cleanup;
            }
            
            if (ptr_command_input[0] == '\0') {
                free(ptr_command_input);
                continue;
            }
            
            ptr_command = strdup(ptr_command_input);
            free(ptr_command_input);
            
            if (!ptr_command) {
                ret_code = -1;
                goto cleanup;
            }
            break;
        }
    }
    
    if (ptr_command && ptr_command[0] != '\0' &&
        strfind(ptr_command, "812C397D", true) == false) {
        if (history_length > 0) {
            HIST_ENTRY *last
                = history_get(history_length - 1);
            if (!last || strcmp(last->line, ptr_command) != 0) {
                add_history(ptr_command);
            }
        } else {
            add_history(ptr_command);
        }
    }

    command_similar = dog_find_near_command(ptr_command,
        unit_command_list, unit_command_len, &dist);

    unit_debugging(0);
    clock_gettime(CLOCK_MONOTONIC, &cmd_start);
    
    if (strncmp(ptr_command, "help", strlen("help")) == 0) {
        dog_console_title("Watchdogs | @ help");
        char *args = ptr_command + strlen("help");
        while (*args == ' ') ++args;
        unit_show_help(args);
        ret_code = -1;
        goto cleanup;
        
    } else if (strcmp(ptr_command, "exit") == 0) {
        ret_code = 2;
        goto cleanup;
        
    } else if (strncmp(ptr_command, "sha1", strlen("sha1")) == 0) {
        char *args = ptr_command + strlen("sha1");
        while (*args == ' ') ++args;
        
        if (*args == '\0') {
            println(stdout, "Usage: sha1 [<words>]");
        } else {
            unsigned char digest[20];
            if (crypto_generate_sha1_hash(args, digest) == 1) {
                printf("        Crypto Input : " DOG_COL_YELLOW "%s\n", args);
                print_restore_color();
                printf("Crypto Output (sha1) : " DOG_COL_YELLOW);
                crypto_print_hex(digest, sizeof(digest), 1);
                print_restore_color();
            }
        }
        ret_code = -1;
        goto cleanup;
        
    } else if (strncmp(ptr_command, "sha256", strlen("sha256")) == 0) {
        char *args = ptr_command + strlen("sha256");
        while (*args == ' ') ++args;
        
        if (*args == '\0') {
            println(stdout, "Usage: sha256 [<words>]");
        } else {
            unsigned char digest[32];
            if (crypto_generate_sha256_hash(args, digest) == 1) {
                printf("          Crypto Input : " DOG_COL_YELLOW "%s\n", args);
                print_restore_color();
                printf("Crypto Output (SHA256) : " DOG_COL_YELLOW);
                crypto_print_hex(digest, sizeof(digest), 1);
                print_restore_color();
            }
        }
        ret_code = -1;
        goto cleanup;
        
    } else if (strncmp(ptr_command, "crc32", strlen("crc32")) == 0) {
        char *args = ptr_command + strlen("crc32");
        while (*args == ' ') ++args;
        
        if (*args == '\0') {
            println(stdout, "Usage: crc32 [<words>]");
        } else {
            uint32_t crc32_generate = crypto_generate_crc32(args, strlen(args));
            char crc_str[11];
            sprintf(crc_str, "%08X", crc32_generate);
            printf("         Crypto Input : " DOG_COL_YELLOW "%s\n", args);
            print_restore_color();
            printf("Crypto Output (CRC32) : " DOG_COL_YELLOW "%s\n", crc_str);
            print_restore_color();
        }
        ret_code = -1;
        goto cleanup;
        
    } else if (strncmp(ptr_command, "djb2", strlen("djb2")) == 0) {
        char *args = ptr_command + strlen("djb2");
        while (*args == ' ') ++args;
        
        if (*args == '\0') {
            println(stdout, "Usage: djb2 [<file>]");
        } else {
            if (path_exists(args) == 0) {
                pr_warning(stdout, "djb2: "
                    DOG_COL_CYAN "%s - No such file or directory", args);
                ret_code = -1;
                goto cleanup;
            }
            unsigned long djb2_generate = crypto_djb2_hash_file(args);
            if (djb2_generate) {
                printf("        Crypto Input : " DOG_COL_YELLOW "%s\n", args);
                print_restore_color();
                printf("Crypto Output (DJB2) : " DOG_COL_YELLOW "%#lx\n", djb2_generate);
                print_restore_color();
            }
        }
        ret_code = -1;
        goto cleanup;
        
    } else if (strncmp(ptr_command, "pbkdf2", strlen("pbkdf2")) == 0) {
        char *args = ptr_command + strlen("pbkdf2");
        while (*args == ' ') ++args;
        
        if (*args == '\0') {
            println(stdout, "Usage: pbkdf2 [<password>]");
        } else {
            unsigned char pbkdf_generate[32];
            unsigned char stored_salt[16];

            crypto_simple_rand_bytes(stored_salt, 16);

            int ret = crypto_derive_key_pbkdf2(args, stored_salt, 16, pbkdf_generate, 32);

            if (ret != 1) {
                print("PBKDF2 Error\n");
                goto pbkdf_done;
            }

            printf("        Crypto Input : " DOG_COL_YELLOW "%s\n", args);
            char *hex_output = NULL;
            crypto_convert_to_hex(pbkdf_generate, 32, &hex_output);
            print_restore_color();
            printf("Crypto Output (PBKDF2) : " DOG_COL_YELLOW "%s\n", hex_output);
            free(hex_output);
        }
        pbkdf_done:
        ret_code = -1;
        goto cleanup;
        
    } else if (strncmp(ptr_command, "base64encode", strlen("base64encode")) == 0) {
        char *args = ptr_command + strlen("base64encode");
        while (*args == ' ') ++args;
        
        if (*args == '\0') {
            println(stdout, "Usage: base64encode [<file/text>]");
        } else {
            if (path_access(args) == 1) {
                FILE *tmp_proc_file = fopen(args, "rb");
                fseek(tmp_proc_file, 0, SEEK_END);
                long size = ftell(tmp_proc_file);
                rewind(tmp_proc_file);
                unsigned char *buffer = dog_malloc(size);
                fread(buffer, 1, size, tmp_proc_file);
                fclose(tmp_proc_file);

                char *encoded = crypto_base64_encode(buffer, size);

                printf("        Crypto Input : " DOG_COL_YELLOW "%s\n", args);
                print_restore_color();
                printf("Crypto Output (base64) : " DOG_COL_YELLOW "%s\n", encoded);

                free(buffer);
                free(encoded);
            } else {
                char *encoded = crypto_base64_encode(
                    (const unsigned char *)args,
                    strlen(args)
                );
                if (encoded) {
                    printf("        Crypto Input : " DOG_COL_YELLOW "%s\n", args);
                    print_restore_color();
                    printf("Crypto Output (base64) : " DOG_COL_YELLOW "%s\n", encoded);
                }
            }
        }
        ret_code = -1;
        goto cleanup;
        
    } else if (strncmp(ptr_command, "base64decode", strlen("base64decode")) == 0) {
        char *args = ptr_command + strlen("base64decode");
        while (*args == ' ') ++args;

        if (*args == '\0') {
            println(stdout, "Usage: base64decode [<base64 text>]");
        } else {
            int decoded_len = 0;
            unsigned char *decoded = crypto_base64_decode(args, &decoded_len);
            if (!decoded) {
                println(stdout, "Invalid Base64 input!");
            } else {
                printf("        Crypto Input : " DOG_COL_YELLOW "%s\n", args);
                print_restore_color();
                printf("Crypto Output (text) : " DOG_COL_YELLOW "%.*s\n",
                    decoded_len, decoded);
                free(decoded);
            }
        }

        ret_code = -1;
        goto cleanup;
    } else if (strncmp(ptr_command, "aesencrypt", strlen("aesencrypt")) == 0) {
        char *args = ptr_command + strlen("aesencrypt");
        while (*args == ' ') ++args;

        if (*args == '\0') {
            println(stdout, "Usage: aesencrypt [<text>]");
        } else {
            AES_KEY key;
            uint8_t in[AES_BLOCK_SIZE] = {0};
            uint8_t out[AES_BLOCK_SIZE];
            
            size_t len = strlen(args);
            if (len > AES_BLOCK_SIZE)
                len = AES_BLOCK_SIZE;

            memcpy(in, args, len);

            crypto_aes_encrypt(in, out, &key);

            printf("        Crypto Input : " DOG_COL_YELLOW "%s\n", args);
            print_restore_color();
            printf("Crypto Output (hex)  : " DOG_COL_YELLOW);

            for (int i = 0; i < AES_BLOCK_SIZE; i++)
                printf("%02X", out[i]);

            printf("\n");
        }

        ret_code = -1;
        goto cleanup;
    } else if (strncmp(ptr_command, "aesdecrypt", strlen("aesdecrypt")) == 0) {
        char *args = ptr_command + strlen("aesdecrypt");
        while (*args == ' ') ++args;

        if (*args == '\0') {
            println(stdout, "Usage: aesdecrypt [<text>]");
        } else {
            AES_KEY key;
            uint8_t in[AES_BLOCK_SIZE] = {0};
            uint8_t out[AES_BLOCK_SIZE];

            int bytes = hex_to_bytes(args, in, AES_BLOCK_SIZE);
            if (bytes <= 0) {
                println(stdout, "Invalid hex input.");
                goto cleanup;
            }

            crypto_aes_decrypt(in, out, &key);

            printf("        Crypto Input : " DOG_COL_YELLOW "%s\n", args);
            print_restore_color();
            printf("Crypto Output        : " DOG_COL_YELLOW "%.*s\n",
                AES_BLOCK_SIZE, out);
        }

        ret_code = -1;
        goto cleanup;
    } else if (strcmp(ptr_command, "config") == 0) {
        if (path_access("watchdogs.toml"))
            remove("watchdogs.toml");
        unit_debugging(1);
        print(DOG_COL_B_BLUE "");
        dog_printfile("watchdogs.toml");
        print(DOG_COL_DEFAULT "\n");
        ret_code = -1;
        goto cleanup;
        
    } else if (strncmp(ptr_command, "replicate", strlen("replicate")) == 0) {
        dog_console_title("Watchdogs | @ replicate depends");
        char *args = ptr_command + strlen("replicate");
        while (*args == ' ') ++args;
        
        int is_null_args = (args[0] == '\0' || strlen(args) < 1) ? 1 : -1;
        
        size_args = strdup(args);
        if (!size_args) {
            ret_code = -1;
            goto cleanup;
        }
        
        char *store_branch = NULL;
        char *store_save = NULL;
        char *args2 = strtok(size_args, " ");
        if (!args2 || strcmp(args2, ".") == 0) is_null_args = 1;
        
        char *procure_args = strtok(args, " ");
        while (procure_args) {
            if (strcmp(procure_args, "--branch") == 0) {
                procure_args = strtok(NULL, " ");
                if (procure_args) store_branch = procure_args;
            } else if (strcmp(procure_args, "--save") == 0) {
                procure_args = strtok(NULL, " ");
                if (procure_args) store_save = procure_args;
            }
            procure_args = strtok(NULL, " ");
        }
        
        if (store_save && strcmp(store_save, ".") == 0) {
            static char *fet_pwd = NULL;
            fet_pwd = dog_procure_pwd();
            store_save = strdup(fet_pwd);
        }
        
        free(size_args);
        size_args = NULL;
        
        if (is_null_args != 1) {
            if (store_branch && store_save) dog_install_depends(args, store_branch, store_save);
            else if (store_branch) dog_install_depends(args, store_branch, NULL);
            else if (store_save) dog_install_depends(args, "main", store_save);
            else dog_install_depends(args, "main", NULL);
        } else {
            char errbuf[DOG_PATH_MAX];
            toml_table_t *dog_toml_server_config;
            FILE *tmp_proc_file = fopen("watchdogs.toml", "r");
            dog_toml_server_config = toml_parse_file(tmp_proc_file, errbuf, sizeof(errbuf));
            if (tmp_proc_file) fclose(tmp_proc_file);
            
            if (!dog_toml_server_config) {
                pr_error(stdout, "failed to parse the watchdogs.toml...: %s", errbuf);
                minimal_debugging();
                ret_code = 0;
                goto cleanup;
            }
            
            toml_table_t *dog_depends;
            dog_depends = toml_table_in(dog_toml_server_config, TOML_TABLE_DEPENDENCIES);
            char *expect = NULL;
            
            if (dog_depends) {
                toml_array_t *dog_toml_packages = toml_array_in(dog_depends, "packages");
                if (dog_toml_packages) {
                    int arr_sz = toml_array_nelem(dog_toml_packages);
                    for (int i = 0; i < arr_sz; i++) {
                        toml_datum_t val = toml_string_at(dog_toml_packages, i);
                        if (!val.ok) continue;
                        
                        if (!expect) {
                            expect = dog_realloc(NULL, strlen(val.u.s) + 1);
                            if (expect)
                                snprintf(expect, strlen(val.u.s) + 1, "%s", val.u.s);
                        } else {
                            char *tmp;
                            size_t old_len = strlen(expect);
                            size_t new_len = old_len + strlen(val.u.s) + 2;
                            
                            tmp = dog_realloc(expect, new_len);
                            if (tmp) {
                                expect = tmp;
                                snprintf(expect + old_len,
                                    new_len - old_len, " %s", val.u.s);
                            }
                        }
                        
                        dog_free(val.u.s);
                        val.u.s = NULL;
                    }
                }
            }
            
            if (!expect) expect = strdup("");
            
            dog_free(dogconfig.dog_toml_packages);
            dogconfig.dog_toml_packages = expect;
            
            printf("Trying to installing:\n   %s\n",
                dogconfig.dog_toml_packages);
            
            if (store_branch && store_save) dog_install_depends(dogconfig.dog_toml_packages, store_branch, store_save);
            else if (store_branch) dog_install_depends(dogconfig.dog_toml_packages, store_branch, NULL);
            else if (store_save) dog_install_depends(dogconfig.dog_toml_packages, "main", store_save);
            else dog_install_depends(dogconfig.dog_toml_packages, "main", NULL);
            
            toml_free(dog_toml_server_config);
        }
        
        ret_code = -1;
        goto cleanup;
        
    } else if (strcmp(ptr_command, "gamemode") == 0) {
        dog_console_title("Watchdogs | @ gamemode");
        
        unit_selection_stat = true;
        
        print("\033[1;33m== Select a Platform ==\033[0m\n");
        print("  \033[36m[l]\033[0m Linux\n");
        print("  \033[36m[w]\033[0m Windows\n"
               "  ^ \033[90m(Supported for: WSL/WSL2 ; not: Docker or Podman on WSL)\033[0m\n");
        print("  \033[36m[t]\033[0m Termux\n");
        
        platform = readline("==> ");
        if (!platform) {
            ret_code = -1;
            goto cleanup;
        }
        
        int platform_ret = -1;
        if (strfind(platform, "L", true)) {
            platform_ret = dog_install_server("linux");
        } else if (strfind(platform, "W", true)) {
            platform_ret = dog_install_server("windows");
        } else if (strfind(platform, "T", true)) {
            platform_ret = dog_install_server("termux");
        } else if (strfind(platform, "E", true)) {
            ret_code = -1;
            goto cleanup;
        } else {
            pr_error(stdout, "Invalid platform selection. Input 'E/e' to exit");
            ret_code = -1;
            goto cleanup;
        }
        
        free(platform);
        platform = NULL;
        
        if (platform_ret == 0) {
            ret_code = -1;
            goto cleanup;
        }
        
        ret_code = -1;
        goto cleanup;
        
    } else if (strcmp(ptr_command, "pawncc") == 0) {
        dog_console_title("Watchdogs | @ pawncc");
        
        unit_selection_stat = true;
        
        print("\033[1;33m== Select a Platform ==\033[0m\n");
        print("  \033[36m[l]\033[0m Linux\n");
        print("  \033[36m[w]\033[0m Windows\n"
               "  ^ \033[90m(Supported for: WSL/WSL2 ; not: Docker or Podman on WSL)\033[0m\n");
        print("  \033[36m[t]\033[0m Termux\n");
        
        platform = readline("==> ");
        if (!platform) {
            ret_code = -1;
            goto cleanup;
        }
        
        int platform_ret = -1;
        if (strfind(platform, "L", true)) {
            platform_ret = dog_install_pawncc("linux");
        } else if (strfind(platform, "W", true)) {
            platform_ret = dog_install_pawncc("windows");
        } else if (strfind(platform, "T", true)) {
            platform_ret = dog_install_pawncc("termux");
        } else if (strfind(platform, "E", true)) {
            ret_code = -1;
            goto cleanup;
        } else {
            pr_error(stdout, "Invalid platform selection. Input 'E/e' to exit");
            ret_code = -1;
            goto cleanup;
        }
        
        free(platform);
        platform = NULL;
        
        if (platform_ret == 0) {
            ret_code = -1;
            goto cleanup;
        }
        
        ret_code = -1;
        goto cleanup;
        
    } else if (strcmp(ptr_command, "debug") == 0) {
        dog_console_title("Watchdogs | @ debug");
        dog_stop_server_tasks();
        unit_ret_main("812C397D");
        ret_code = -1;
        goto cleanup;
        
    } else if (strcmp(ptr_command, "812C397D") == 0) {
        dog_server_crash_check();
        ret_code = 3;
        goto cleanup;
        
    } else if (strncmp(ptr_command, "compile", strlen("compile")) == 0 &&
               !isalpha((unsigned char)ptr_command[strlen("compile")])) {
        dog_console_title("Watchdogs | @ compile | logging file: .watchdogs/compiler.log");
        
        char *args = ptr_command + strlen("compile");
        while (*args == ' ') args++;
        
        char *compile_args = strtok(args, " ");
        char *second_arg = strtok(NULL, " ");
        char *four_arg = strtok(NULL, " ");
        char *five_arg = strtok(NULL, " ");
        char *six_arg = strtok(NULL, " ");
        char *seven_arg = strtok(NULL, " ");
        char *eight_arg = strtok(NULL, " ");
        char *nine_arg = strtok(NULL, " ");
        char *ten_arg = strtok(NULL, " ");
        
        dog_exec_compiler(args, compile_args, second_arg, four_arg,
                         five_arg, six_arg, seven_arg, eight_arg,
                         nine_arg, ten_arg);
        ret_code = -1;
        goto cleanup;
        
    } else if (strncmp(ptr_command, "decompile", strlen("decompile")) == 0) {
        dog_console_title("Watchdogs | @ decompile");

        char *args = ptr_command + strlen("decompile");
        while (*args == ' ') args++;
        if (*args == '\0') {
            println(stdout, "Usage: decompile [<file.amx>]");
            ret_code = -1;
            goto cleanup;
        }
        if (strfind(args, ".amx", true) == false) {
            println(stdout, "Usage: decompile [<file.amx>]");
            ret_code = -1;
            goto cleanup;
        }

        char *p;
        
        char *a_args = strdup(args);
        #ifdef DOG_LINUX
        for (p = a_args; *p; p++) {
                if (*p == _PATH_CHR_SEP_WIN32)
                    *p = _PATH_CHR_SEP_POSIX;
            }
        #else
        for (p = a_args; *p; p++) {
                if (*p == _PATH_CHR_SEP_POSIX)
                    *p = _PATH_CHR_SEP_WIN32;
            }
        #endif

        char *pawndisasm_ptr = NULL;
        int   ret_pawndisasm = 0;
        if (strcmp(dogconfig.dog_toml_os_type, OS_SIGNAL_WINDOWS) == 0) {
            pawndisasm_ptr = "pawndisasm.exe";
        } else if (strcmp(dogconfig.dog_toml_os_type, OS_SIGNAL_LINUX) == 0) {
            pawndisasm_ptr = "pawndisasm";
        }

        dog_sef_path_revert();

        if (dir_exists("pawno") != 0 && dir_exists("qawno") != 0) {
            ret_pawndisasm = dog_find_path("pawno", pawndisasm_ptr,
                NULL);
            if (ret_pawndisasm) {
                ;
            } else {
                ret_pawndisasm = dog_find_path("qawno",
                    pawndisasm_ptr, NULL);
                if (ret_pawndisasm < 1) {
                    ret_pawndisasm = dog_find_path(".",
                        pawndisasm_ptr, NULL);
                }
            }
        } else if (dir_exists("pawno") != 0) {
            ret_pawndisasm = dog_find_path("pawno", pawndisasm_ptr,
                NULL);
            if (ret_pawndisasm) {
                ;
            } else {
                ret_pawndisasm = dog_find_path(".",
                    pawndisasm_ptr, NULL);
            }
        } else if (dir_exists("qawno") != 0) {
            ret_pawndisasm = dog_find_path("qawno", pawndisasm_ptr,
                NULL);
            if (ret_pawndisasm) {
                ;
            } else {
                ret_pawndisasm = dog_find_path(".",
                    pawndisasm_ptr, NULL);
            }
        } else {
            ret_pawndisasm = dog_find_path(".", pawndisasm_ptr,
                NULL);
        }
        if (ret_pawndisasm) {

            if (binary_condition_check(dogconfig.dog_sef_found_list[0]) == false) {
                dog_free(a_args);
                ret_code = -1;
                goto cleanup;
            }

            char *args2 = strdup(a_args);
            char *dot_amx = strstr(args2, ".amx");
            if (dot_amx)
                {
                    *dot_amx = '\0';
                }
            char s_args[DOG_PATH_MAX];
            snprintf(s_args, sizeof(s_args), "%s.asm", args2);
            dog_free(args2);
            char s_argv[DOG_PATH_MAX * 3];
            #ifdef DOG_LINUX
                char *executor = "sh -c";
                snprintf(s_argv, sizeof(s_argv),
                    "%s '%s %s %s'", executor, dogconfig.dog_sef_found_list[0], a_args, s_args);
            #else
                char *executor = "cmd.exe /C";
                snprintf(s_argv, sizeof(s_argv),
                    "%s %s %s %s", executor, dogconfig.dog_sef_found_list[0], a_args, s_args);
            #endif
            char *argv[] = { s_argv, NULL };
            int ret = dog_exec_command(argv);
            if (!ret) println(stdout, "%s", s_args);
            dog_console_title(s_argv);
        } else {
            print("\033[1;31merror:\033[0m pawndisasm/pawncc (our compiler) not found\n"
                "  \033[2mhelp:\033[0m install it before continuing\n");
        }
        dog_free(a_args);

        ret_code = -1;
        goto cleanup;

    } else if (strcmp(ptr_command, "running") == 0) {
        dog_stop_server_tasks();
        
        sigint_handler = 0;

        if (!path_access(dogconfig.dog_toml_server_binary)) {
            pr_error(stdout, "can't locate sa-mp/open.mp binary file!");
            ret_code = -1;
            goto cleanup;
        }
        if (!path_access(dogconfig.dog_toml_server_config)) {
            pr_warning(stdout, "can't locate %s - config file!",
                dogconfig.dog_toml_server_config);
            ret_code = -1;
            goto cleanup;
        }
        if (path_exists(dogconfig.dog_toml_server_logs) == 1) {
            remove(dogconfig.dog_toml_server_logs);
        }
        if (dir_exists(".watchdogs") == 0) MKDIR(".watchdogs");
        
        char title_running_info[DOG_PATH_MAX];
        snprintf(title_running_info, DOG_PATH_MAX,
                "Watchdogs | @ running | config: %s | "
                "CTRL + C to stop. | \"debug\" to debugging",
                dogconfig.dog_toml_server_config);
        
    #ifdef DOG_ANDROID
        println(stdout, "%s", title_running_info);
    #else
        dog_console_title(title_running_info);
    #endif
        
        struct sigaction sa;
        if (path_access("announce") == 1)
            __set_default_access("announce");
        __set_default_access(dogconfig.dog_toml_server_binary);

        sa.sa_handler = unit_sigint_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        
        if (sigaction(SIGINT, &sa, NULL) == -1) {
            perror("sigaction");
            exit(EXIT_FAILURE);
        }
        
        #ifdef DOG_WINDOWS
            STARTUPINFOA
                _STARTUPINFO;
            PROCESS_INFORMATION
                _PROCESS_INFO;
            
            ZeroMemory(&_STARTUPINFO, sizeof(_STARTUPINFO));
            ZeroMemory(&_PROCESS_INFO, sizeof(_PROCESS_INFO));
            
            _STARTUPINFO.cb = sizeof(_STARTUPINFO);
            _STARTUPINFO.dwFlags = STARTF_USESTDHANDLES;
            
            _STARTUPINFO.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
            _STARTUPINFO.hStdError  = GetStdHandle(STD_ERROR_HANDLE);
            _STARTUPINFO.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

            tmp_buf[0] = '\0';
        
            snprintf(tmp_buf, DOG_PATH_MAX, "%s%s",
                _PATH_STR_EXEC, dogconfig.dog_toml_server_binary);
            
            if (!CreateProcessA(NULL, tmp_buf, NULL, NULL, TRUE, 0, NULL, NULL, &_STARTUPINFO, &_PROCESS_INFO)) {
                pr_error(stdout, "CreateProcessA failed!");
                minimal_debugging();
            } else {
                WaitForSingleObject(_PROCESS_INFO.hProcess, INFINITE);
                CloseHandle(_PROCESS_INFO.hProcess);
                CloseHandle(_PROCESS_INFO.hThread);
            }
        #else
            pid_t process_id;

            tmp_buf[0] = '\0';
        
            snprintf(tmp_buf, DOG_PATH_MAX, "%s%s%s",
                dog_procure_pwd(), _PATH_STR_SEP_POSIX,
                dogconfig.dog_toml_server_binary);
            
            if (binary_condition_check(tmp_buf) == false) {
                ret_code = -1;
                goto cleanup;
            }

            int stdout_pipe[2], stderr_pipe[2];
            
            if (pipe(stdout_pipe) == -1 || pipe(stderr_pipe) == -1) {
                perror("pipe");
                ret_code = -1;
                goto cleanup;
            }
            
            process_id = fork();
            if (process_id == 0) {
                chdir(dog_procure_pwd());
                
                close(stdout_pipe[0]);
                close(stderr_pipe[0]);
                
                dup2(stdout_pipe[1], STDOUT_FILENO);
                dup2(stderr_pipe[1], STDERR_FILENO);
                
                close(stdout_pipe[1]);
                close(stderr_pipe[1]);
                
                execl(tmp_buf, tmp_buf, (char *)NULL);
                
                perror("execl failed");
                fprintf(stderr, "errno = %d\n", errno);
        
                int status;
                waitpid(process_id, &status, 0);
                
                if (WIFEXITED(status)) {
                    printf("Child exited with code %d\n", WEXITSTATUS(status));
                } else if (WIFSIGNALED(status)) {
                    printf("Child killed by signal %d\n", WTERMSIG(status));
                }

                _exit(127);
            } else if (process_id > 0) {
                close(stdout_pipe[1]);
                close(stderr_pipe[1]);

                int stdout_fd;
                int stderr_fd;
                int max_fd;
                ssize_t br;

                stdout_fd = stdout_pipe[0];
                stderr_fd = stderr_pipe[0];
                max_fd = (stdout_fd > stderr_fd ? stdout_fd : stderr_fd) + 1;

                fd_set readfds;

                tmp_buf[0] = '\0';

                while (true) {

                    FD_ZERO(&readfds);
                    
                    if (stdout_fd >= 0)
                        FD_SET(stdout_fd, &readfds);
                    if (stderr_fd >= 0)
                        FD_SET(stderr_fd, &readfds);

                    if (select(max_fd, &readfds, NULL, NULL, NULL) < 0) {
                        perror("select failed");
                        minimal_debugging();
                        break;
                    }

                    if (stdout_fd >= 0 &&
                        FD_ISSET(stdout_fd, &readfds))
                    {
                        br = read(stdout_fd,
                                  tmp_buf, sizeof(tmp_buf)-1);
                        if (br <= 0) {
                            stdout_fd = -1;
                        } else {
                            tmp_buf[br] = '\0';
                            printf("%s", tmp_buf);
                        }
                    }

                    if (stderr_fd >= 0 &&
                        FD_ISSET(stderr_fd, &readfds))
                    {
                        br = read(stderr_fd,
                                  tmp_buf, sizeof(tmp_buf)-1);
                        if (br <= 0) {
                            stderr_fd = -1;
                        } else {
                            tmp_buf[br] = '\0';
                            fprintf(stderr, "%s", tmp_buf);
                        }
                    }

                    if (stdout_fd < 0 && stderr_fd < 0) break;
                }
                
                close(stdout_pipe[0]);
                close(stderr_pipe[0]);
            }
        #endif
        
        print(DOG_COL_DEFAULT "\n");
        
        print("\x1b[32m==> create debugging?\x1b[0m\n");
        debug_server = readline("   answer (y/n): ");
        if (debug_server && (debug_server[0] == '\0' ||
            strcmp(debug_server, "Y") == 0 ||
            strcmp(debug_server, "y") == 0)) {
            unit_ret_main("debug");
        }
        
        ret_code = -1;
        goto cleanup;
        
    } else if (strncmp(ptr_command, "compiles", strlen("compiles")) == 0) {
        dog_console_title("Watchdogs | @ compiles");
        
        char *args = ptr_command + strlen("compiles");
        while (*args == ' ') ++args;
        char *args2 = strtok(args, " ");
        
        if (!args2 || args2[0] == '\0' || args2[0] == '.') {
            const char *argsc[] = { NULL, ".", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
            dog_exec_compiler(argsc[0], argsc[1], argsc[2], argsc[3],
                argsc[4], argsc[5], argsc[6], argsc[7], argsc[8], argsc[9]);
            dog_configure_toml();
            
            if (!pawn_is_error) unit_ret_main("running");
        } else {
            const char *argsc[] = { NULL, args2, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
            dog_exec_compiler(argsc[0], argsc[1], argsc[2], argsc[3], argsc[4],
                argsc[5], argsc[6], argsc[7], argsc[8], argsc[6]);
            dog_configure_toml();
            
            if (!pawn_is_error) {
                unit_ret_main("running");
            }
        }
        
        ret_code = -1;
        goto cleanup;
        
    } else if (strcmp(ptr_command, "stop") == 0) {
        dog_console_title("Watchdogs | @ stop");
        dog_stop_server_tasks();
        ret_code = -1;
        goto cleanup;
        
    } else if (strcmp(ptr_command, "restart") == 0) {
        dog_console_title("Watchdogs | @ restart");
        dog_stop_server_tasks();
        unit_ret_main("running");
        ret_code = -1;
        goto cleanup;
        
    } else if (strncmp(ptr_command, "tracker", strlen("tracker")) == 0) {
        char *args = ptr_command + strlen("tracker");
        while (*args == ' ') ++args;
        
        if (*args == '\0') {
            println(stdout, "Usage: tracker [<name>]");
            ret_code = -1;
            goto cleanup;
        }
        
        CURL *curl;
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl = curl_easy_init();
        if (!curl) {
            fprintf(stderr, "Curl initialization failed!\n");
            ret_code = -1;
            goto cleanup;
        }
        
        int variation_count = 0;
        char variations[MAX_VARIATIONS][MAX_USERNAME_LEN];
        tracker_discrepancy(args, variations, &variation_count);
        
        printf("[TRACKER] Search base: %s\n", args);
        printf("[TRACKER] Generated %d Variations\n\n", variation_count);
        
        for (int i = 0; i < variation_count; i++) {
            printf("=== TRACKING ACCOUNTS: %s ===\n", variations[i]);
            tracking_username(curl, variations[i]);
            print("\n");
        }
        
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        ret_code = -1;
        goto cleanup;
        
    } else if (strncmp(ptr_command, "compress", strlen("compress")) == 0) {
        char *args = ptr_command + strlen("compress");
        while (*args == ' ') args++;
        
        if (*args == '\0') {
            print("Usage: compress --file <input> --output <output> --type <format>\n");
            print("Example:\n\tcompress --file myfile.txt --output myarchive.zip --type zip\n\t"
                   "compress --file myfolder/ --output myarchive.tar.gz --type gz\n");
            ret_code = -1;
            goto cleanup;
        }
        
        char *store_input = NULL, *store_output = NULL, *store_type = NULL;
        char *procure_args = strtok(args, " ");
        while (procure_args) {
            if (strcmp(procure_args, "--file") == 0) {
                procure_args = strtok(NULL, " ");
                if (procure_args) store_input = procure_args;
            } else if (strcmp(procure_args, "--output") == 0) {
                procure_args = strtok(NULL, " ");
                if (procure_args) store_output = procure_args;
            } else if (strcmp(procure_args, "--type") == 0) {
                procure_args = strtok(NULL, " ");
                if (procure_args) store_type = procure_args;
            }
            procure_args = strtok(NULL, " ");
        }
        
        if (!store_input || !store_output || !store_type) {
            print("Missing arguments!\n");
            print("Usage: compress --file <input> --output <output> --type <zip|tar|gz|bz2|xz>\n");
            print("Example:\n\tcompress --file myfile.txt --output myarchive.zip --type zip\n\t"
                   "compress --file myfolder/ --output myarchive.tar.gz --type gz\n");
            ret_code = -1;
            goto cleanup;
        }
        
        CompressionFormat fmt;
        if (strcmp(store_type, "zip") == 0) fmt = COMPRESS_ZIP;
        else if (strcmp(store_type, "tar") == 0) fmt = COMPRESS_TAR;
        else if (strcmp(store_type, "gz") == 0) fmt = COMPRESS_TAR_GZ;
        else if (strcmp(store_type, "bz2") == 0) fmt = COMPRESS_TAR_BZ2;
        else if (strcmp(store_type, "xz") == 0) fmt = COMPRESS_TAR_XZ;
        else {
            printf("Unknown type: %s\n", store_type);
            print("Supported: zip, tar, gz, bz2, xz\n");
            ret_code = -1;
            goto cleanup;
        }
        
        const char *procure_items[] = { store_input };
        int ret = compress_to_archive(store_output, procure_items, 1, fmt);
        if (ret == 0) {
            pr_info(stdout, "Converter file/folder to "
            "archive (Compression) successfully: %s\n", store_output);
        } else {
            pr_error(stdout, "Compression failed!\n");
            minimal_debugging();
        }
        
        ret_code = -1;
        goto cleanup;
        
    } else if (strcmp(ptr_command, "watchdogs") == 0 || strcmp(ptr_command, "dog") == 0) {
        unit_show_dog();
        ret_code = -1;
        goto cleanup;
        
    } else if (strcmp(ptr_command, command_similar) != 0 && dist <= 2) {
        dog_console_title("Watchdogs | @ undefined");
        println(stdout, "watchdogs: '%s' is not valid watchdogs command. See 'help'.", ptr_command);
        println(stdout, "   but did you mean '%s'?", command_similar);
        goto trying;
        
    } else {
    trying:
        size_t command_len = strlen(ptr_command) + DOG_PATH_MAX;
        char *command2 = dog_malloc(command_len);
        if (!command2) {
            ret_code = -1;
            goto cleanup;
        }
        
        if (path_access("/bin/sh") != 0) {
            snprintf(command2, command_len, "/bin/sh -c '%s'", ptr_command);
        } else if (path_access("~/.bashrc") != 0) {
            snprintf(command2, command_len, "bash -c '%s'", ptr_command);
        } else if (path_access("~/.zshrc") != 0) {
            snprintf(command2, command_len, "zsh -c '%s'", ptr_command);
        } else {
            snprintf(command2, command_len, "%s", ptr_command);
        }
        
        char *argv[32];
        int argc = 0;
        char *p = strtok(command2, " ");
        while (p && argc < sizeof(argv) - 1) {
            argv[argc++] = p;
            p = strtok(NULL, " ");
        }
        argv[argc] = NULL;
        
        int ret = dog_exec_command(argv);
        if (ret) dog_console_title("Watchdogs | @ command not found");
        
        dog_free(command2);

        if (strcmp(ptr_command, "clear") == 0 || strcmp(ptr_command, "cls") == 0) {
            ret_code = -2;
        } else {
            ret_code = -1;
        }
        goto cleanup;
    }

cleanup:
    cleanup_local_resources(&ptr_command_prompt, &ptr_command, &title_running_info,
                           &size_command, &platform, &pointer_signalA,
                           &debug_server, &size_args, &compile_target);
    return (ret_code);
}

void
unit_ret_main(void *unit_pre_command)
{
    int ret = -3;
    if (unit_pre_command != NULL) {
        char *procure_command_argv = strdup((char *)unit_pre_command);
        if (procure_command_argv) {
            ret = __command__(procure_command_argv);
            free(procure_command_argv);
        }
        clock_gettime(CLOCK_MONOTONIC, &cmd_end);
        if (ret == -2 || ret == 3) {
            return;
        }
        return;
    }

loop_main:
    ret = __command__(NULL);
    if (ret == -1) {
        clock_gettime(CLOCK_MONOTONIC, &cmd_end);
        command_dur = ((double)(cmd_end.tv_sec - cmd_start.tv_sec)) +
                     ((double)(cmd_end.tv_nsec - cmd_start.tv_nsec)) / 1e9;
        pr_color(stdout, DOG_COL_CYAN, " <I> (interactive) Finished At %.3fs\n", command_dur);
        goto loop_main;
    } else if (ret == 2) {
        clock_gettime(CLOCK_MONOTONIC, &cmd_end);
        dog_console_title("Terminal.");
        
        clear_history();
        
        if (dogconfig.dog_ptr_samp) { free(dogconfig.dog_ptr_samp); dogconfig.dog_ptr_samp = NULL; }
        if (dogconfig.dog_ptr_omp) { free(dogconfig.dog_ptr_omp); dogconfig.dog_ptr_omp = NULL; }
        if (dogconfig.dog_pawncc_path) { free(dogconfig.dog_pawncc_path); dogconfig.dog_pawncc_path = NULL; }
        if (dogconfig.dog_toml_os_type) { free(dogconfig.dog_toml_os_type); dogconfig.dog_toml_os_type = NULL; }
        if (dogconfig.dog_toml_server_binary) { free(dogconfig.dog_toml_server_binary); dogconfig.dog_toml_server_binary = NULL; }
        if (dogconfig.dog_toml_server_config) { free(dogconfig.dog_toml_server_config); dogconfig.dog_toml_server_config = NULL; }
        if (dogconfig.dog_toml_server_logs) { free(dogconfig.dog_toml_server_logs); dogconfig.dog_toml_server_logs = NULL; }
        if (dogconfig.dog_toml_all_flags) { free(dogconfig.dog_toml_all_flags); dogconfig.dog_toml_all_flags = NULL; }
        if (dogconfig.dog_toml_root_patterns) { free(dogconfig.dog_toml_root_patterns); dogconfig.dog_toml_root_patterns = NULL; }
        if (dogconfig.dog_toml_packages) { free(dogconfig.dog_toml_packages); dogconfig.dog_toml_packages = NULL; }
        if (dogconfig.dog_toml_serv_input) { free(dogconfig.dog_toml_serv_input); dogconfig.dog_toml_serv_input = NULL; }
        if (dogconfig.dog_toml_serv_output) { free(dogconfig.dog_toml_serv_output); dogconfig.dog_toml_serv_output = NULL; }
        if (pawn_full_includes) { free(pawn_full_includes); pawn_full_includes = NULL; }
        
        exit(EXIT_SUCCESS);
    } else if (ret == -2) {
        clock_gettime(CLOCK_MONOTONIC, &cmd_end);
        goto loop_main;
    } else if (ret == 3) {
        clock_gettime(CLOCK_MONOTONIC, &cmd_end);
    } else {
        goto basic_end;
    }

basic_end:
    clock_gettime(CLOCK_MONOTONIC, &cmd_end);
    command_dur = ((double)(cmd_end.tv_sec - cmd_start.tv_sec)) +
                 ((double)(cmd_end.tv_nsec - cmd_start.tv_nsec)) / 1e9;
    pr_color(stdout, DOG_COL_CYAN, " <I> (interactive) Finished At %.3fs\n", command_dur);
    goto loop_main;
}

int
main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc > 1) {
        int i;
        size_t unit_total_len = 0;

        for (i = 1; i < argc; ++i)
            unit_total_len += strlen(argv[i]) + 1;

        char *unit_size_prompt = dog_malloc(unit_total_len);
        if (!unit_size_prompt)
            return (0);

        char *ptr = unit_size_prompt;
        for (i = 1; i < argc; ++i) {
            if (i > 1)
                *ptr++ = ' ';
            size_t len = strlen(argv[i]);
            memcpy(ptr, argv[i], len);
            ptr += len;
        }
        *ptr = '\0';

        unit_ret_main(unit_size_prompt);

        dog_free(unit_size_prompt);
        unit_size_prompt = NULL;

        return (0);
    } else {
        unit_ret_main(NULL);
    }

    return (0);
}
