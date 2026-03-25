#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include  "utils.h"
#include  "crypto.h"
#include  "library.h"
#include  "archive.h"
#include  "curl.h"
#include  "process.h"
#include  "server.h"
#include  "compiler.h"
#include  "debug.h"
#include  "units.h"

#if defined(__W_VERSION__)
#define WATCHDOGS_RELEASE __W_VERSION__
#else
#define WATCHDOGS_RELEASE "WATCHDOGS"
#endif

const char *  watchdogs_release = WATCHDOGS_RELEASE;
_Bool      unit_selection_state = false;
static struct timespec cmd_start = { 0 };
static struct timespec cmd_end = { 0 };
static double command_dur;
static char pbuf[DOG_PATH_MAX * 2];

static void
cleanup_local_resources(char **ptr_command_prompt, char **ptr_command, 
             char **title,
             char **size_command_ptr,
             char **platform_ptr, char **signal_ptr,
             char **debug_server_ptr, char **args_ptr,
             char **compile_target_ptr)
{
  int freed_count = 0;

  // ptr prompt free
  if (ptr_command_prompt && *ptr_command_prompt) {
    free(*ptr_command_prompt);
    *ptr_command_prompt = NULL;
    freed_count++;
  } /* if */
  
  // ptr command free
  if (ptr_command && *ptr_command) {
    free(*ptr_command);
    *ptr_command = NULL;
    freed_count++;
  } /* if */
  
  // title running info free
  if (title && *title) {
    free(*title);
    *title = NULL;
    freed_count++;
  } /* if */
  
  // size command ptr free
  if (size_command_ptr && *size_command_ptr) {
    free(*size_command_ptr);
    *size_command_ptr = NULL;
    freed_count++;
  } /* if */
  
  // platform free
  if (platform_ptr && *platform_ptr) {
    free(*platform_ptr);
    *platform_ptr = NULL;
    freed_count++;
  } /* if */
  
  // signal free
  if (signal_ptr && *signal_ptr) {
    free(*signal_ptr);
    *signal_ptr = NULL;
    freed_count++;
  } /* if */
  
  // debug server ptr free
  if (debug_server_ptr && *debug_server_ptr) {
    free(*debug_server_ptr);
    *debug_server_ptr = NULL;
    freed_count++;
  } /* if */
  
  // args ptr free
  if (args_ptr && *args_ptr) {
    free(*args_ptr);
    *args_ptr = NULL;
    freed_count++;
  } /* if */
  
  // compile target ptr free
  if (compile_target_ptr && *compile_target_ptr) {
    free(*compile_target_ptr);
    *compile_target_ptr = NULL;
    freed_count++;
  } /* if */

#if defined(_DBG_PRINT)
  pr_info(stdout, "cleanup_local_resources: freed %d resources", freed_count);
#endif
} /* cleanup_local_resources */

static
void unit_show_help(const char *command)
{
  typedef struct {
    const char *name;
    const char *desc;
    const char *usage;
    const char *detail;
  } Help;

static const Help help_table[] = {
  { "exit", "exit from watchdogs",
  "exit",
  "Just type 'exit' and you're outta here!" },
  { "sha1", "generate sha1 hash",
  "sha1 [<args>]",
  "Get that SHA1 hash for your text." },
  { "sha256", "generate sha256 hash",
  "sha256 [<args>]",
  "Get that SHA256 hash for your text." },
  { "crc32", "generate crc32 checksum",
  "crc32 [<args>]",
  "Quick CRC32 checksum generation." },
  { "djb2", "generate djb2 hash file",
  "djb2 [<args>]",
  "djb2 hashing for your files." },
  { "pbkdf2", "generate passphrase",
  "pbkdf2 [<args>]",
  "Password to passphrase." },
  { "base64encode", "encode data to Base64",
  "base64encode [<file/text>]",
  "Convert file or plain text into Base64 string." },
  { "base64decode", "decode Base64 to text",
  "base64decode [<base64 text>]",
  "Convert Base64 string back to readable text." },
  { "aesencrypt", "encrypt text using AES",
  "aesencrypt [<text>]",
  "AES encryption (16-byte block)." },
  { "aesdecrypt", "decrypt text using AES",
  "aesdecrypt [<text>]",
  "AES decryption (16-byte block)." },
  { "config", "re-write watchdogs.toml",
  "config",
  "Reset your config file to default settings." },
  { "gamemode", "download SA-MP gamemode",
  "gamemode",
  "Grab some SA-MP gamemodes quickly." },
  { "pawncc", "download SA-MP pawncc",
  "pawncc",
  "Get the Pawn Compiler for SA-MP/open.mp." },
  { "debug", "debugging & logging server logs",
  "debug",
  "Keep an eye on your server logs." },
  { "compile", "compile your project",
  "compile [<args>]",
  "Turn your code into something runnable!" },
  { "decompile", "de-compile your project",
  "decompile [<args>]",
  "De-compile .amx into readable .asm." },
  { "running", "run your project",
  "running [<args>]",
  "Fire up your project and see it in action." },
  { "compiles", "compile and run your project",
  "compiles [<args>]",
  "Two-in-one: compile then run immediately!" },
  { "pawnruns", "run compiled Pawn bytecode (.amx)",
  "pawnruns <file.amx>",
  "Execute .amx output directly without SA-MP dependency." },
  { "stop", "stopped server tasks",
  "stop",
  "Halt everything! Stop your server tasks." },
  { "restart", "re-start server tasks",
  "restart",
  "Fresh start! Restart your server." },
  { "tracker", "account tracking",
  "tracker [<args>]",
  "Track accounts across platforms." },
  { "compress", "create a compressed archive",
  "compress <input> <output>",
  "Generate a compressed file (.zip/.tar.gz)." },
  { NULL, NULL, NULL, NULL }
};
  
  int i;

  /* Handle case with no specific command */
  if (command == NULL || *command == '\0') {
    puts("Usage: help <command>\n\n");
    puts("Commands:\n\n");

    for (i = 0; help_table[i].name; i++) {
      if (help_table[i].name != NULL) {
        printf("  %-12s @ %s\n",
          help_table[i].name,
          help_table[i].desc);
      } /* if */
    } /* for */

    puts("\nType 'help <command>' for detailed info.\n");
    return;
  } /* if */

  /* Search for specific command */
  for (i = 0; help_table[i].name; i++) {
    if (help_table[i].name != NULL && equals(command, help_table[i].name)) {
      printf("\n%sCommand:%s %s\n\n",
        LR_CYAN,
        LR_DEFAULT,
        help_table[i].name);
      printf("Description:\n  %s\n\n",
        help_table[i].desc ? help_table[i].desc : "(no description)");
      printf("Usage:\n  %s%s%s\n\n",
        LR_CYAN,
        help_table[i].usage ? help_table[i].usage : "(no usage)",
        LR_DEFAULT);
      printf("%s\n\n",
        help_table[i].detail ? help_table[i].detail : "(no details)");
      return;
    } /* if */
  } /* for */

  /* Command not found */
  puts("help can't found for: '");
  pr_color(stdout, LR_YELLOW, "%s", command);
  puts("'\n   Oops! That command doesn't exist. Try 'help' to see available commands.\n");
} /* unit_show_help */

static
void unit_show_dog(void) {
  /* Check if notice should be shown */
  if (path_exists(".watchdogs/notice") == 0) {
    puts(" type: touch .watchdogs/notice | type nul > .watchdogs/notice for hide this message.\n");
    
  #ifndef DOG_ANDROID
  static const char* dog_ascii =
    "\n             \\/%%#z.   \\/.%%#z./   /,z#%%\\/\n"
    "             \\X##k    /X#####X\\   /d##X/\n"
    "             \\888\\   /888/ \\888\\   /888/\n"
    "            `v88;  ;88v'   `v88;  ;88v'\n"
    "             \\77xx77/     \\77xx77/\n"
    "            `::::'     `::::'\n";
  #else
  static const char *dog_ascii =
    "\n      \\/%%#z.   \\/.%%#z./   /,z#%%\\/\n"
    "      \\X##k    /X#####X\\   /d##X/\n"
    "      \\888\\   /888/ \\888\\   /888/\n"
    "     `v88;  ;88v'   `v88;  ;88v'\n"
    "      \\77xx77/     \\77xx77/\n"
    "     `::::'     `::::'\n\n";
  #endif
    
    if (dog_ascii != NULL) {
      fwrite(dog_ascii, 1, strlen(dog_ascii), stdout);
    } /* if */
    
    puts("Use \"help\" for more.\n");
  } /* if */
} /* unit_show_dog */

static
void
checkout_unit_rule(void)
{
  /* Handle compilation completion */
  if (compiling_gamemode == true) {
    compiling_gamemode = !compiling_gamemode;
    pr_info(stdout,
      "After compiling the script, type "
      LR_YELLOW "running " LR_DEFAULT "or "
      LR_YELLOW "pawnruns " LR_DEFAULT "to start your amx..");
    dog_exec_compiler(NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL,
      NULL, NULL);
  } /* if */
} /* checkout_unit_rule */

static
int
__command__(char *unit_pre_command)
{
  unit_debugging(0);
  
  /* Initialize timing structures */
  memset(&cmd_start, 0, sizeof(cmd_start));
  memset(&cmd_end, 0, sizeof(cmd_end));

  char *ptr_command_prompt = NULL;
  size_t size_ptr_command = DOG_MAX_PATH + DOG_PATH_MAX;
  char *ptr_command = NULL;
  const char *command_similar = NULL;
  int dist = INT_MAX;
  int ret_code = -1;
  
  char *title = NULL;
  char *size_command = NULL;
  char *platform = NULL;
  char *pointer_signalA = NULL;
  char *debug_server = NULL;
  char *size_args = NULL;
  char *compile_target = NULL;
  
  int i;

  /* Check unit rules */
  checkout_unit_rule();

  /* Allocate command prompt buffer */
  ptr_command_prompt = dog_malloc(size_ptr_command);
  if (!ptr_command_prompt) {
    pr_error(stdout, "__command__: failed to allocate command prompt buffer");
    ret_code = -1;
    goto cleanup;
  } /* if */
  
  /* Free any existing command */
  if (ptr_command) {
    free(ptr_command);
    ptr_command = NULL;
  } /* if */

  /* Initialize history and display welcome */
  static _Bool unit_initial = false;
  if (!unit_initial) {
    unit_initial = true;
    using_history();
    unit_show_dog();
  } /* if */
  
  /* Handle pre-command if provided */
  if (unit_pre_command && unit_pre_command[0] != '\0') {
    ptr_command = strdup(unit_pre_command);
    if (!ptr_command) {
      pr_error(stdout, "__command__: failed to duplicate pre-command");
      ret_code = -1;
      goto cleanup;
    } /* if */
    
    if (_strfind(ptr_command, "812C397D", true) == 0) {
      printf("# %s\n", ptr_command);
    } /* if */
  } else {
    /* Interactive command input loop */
    while (true) {
      (void)snprintf(ptr_command_prompt, size_ptr_command, "# ");
      char *ptr_command_input = readline(ptr_command_prompt);
      fflush(stdout);
      
      if (!ptr_command_input) {
        pr_info(stdout, "__command__: readline returned NULL");
        ret_code = 2;
        goto cleanup;
      } /* if */
      
      if (ptr_command_input[0] == '\0') {
        free(ptr_command_input);
        continue;
      } /* if */
      
      ptr_command = strdup(ptr_command_input);
      free(ptr_command_input);
      
      if (!ptr_command) {
        pr_error(stdout, "__command__: failed to duplicate command input");
        ret_code = -1;
        goto cleanup;
      } /* if */
      break;
    } /* while */
  } /* if */
  
  /* Add command to history */
  if (ptr_command && ptr_command[0] != '\0' &&
    _strfind(ptr_command, "812C397D", true) == false) {
    if (history_length > 0) {
      HIST_ENTRY *last = history_get(history_length - 1);
      if (!last || strcmp(last->line, ptr_command) != 0) {
        add_history(ptr_command);
      } /* if */
    } else {
      add_history(ptr_command);
    } /* if */
  } /* if */

  /* Find similar command for suggestions */
  command_similar = dog_find_near_command(ptr_command,
    unit_command_list, unit_command_len, &dist);

  unit_debugging(0);
  clock_gettime(CLOCK_MONOTONIC, &cmd_start);
  
  /* Command processing - help */
  if (strncmp(ptr_command, "help", strlen("help")) == 0) {
    (void)console_title("Watchdogs | @ help");
    char *args = ptr_command + strlen("help");
    while (*args == ' ') ++args;
    unit_show_help(args);
    ret_code = -1;
    goto cleanup;
    
  /* Command processing - exit */
  } else if (strcmp(ptr_command, "exit") == 0) {
    pr_info(stdout, "__command__: exit command received");
    ret_code = 2;
    goto cleanup;
    
  /* Command processing - sha1 */
  } else if (strncmp(ptr_command, "sha1", strlen("sha1")) == 0) {
    char *args = ptr_command + strlen("sha1");
    while (*args == ' ') ++args;
    
    if (*args == '\0') {
      println(stdout, "Usage: sha1 [<words>]");
    } else {
      unsigned char digest[20];
      if (crypto_generate_sha1_hash(args, digest) == 1) {
        printf("    Crypto Input : " LR_YELLOW "%s\n", args);
        print_restore_color();
        printf("Crypto Output (sha1) : " LR_YELLOW);
        crypto_print_hex(digest, sizeof(digest), 1);
        print_restore_color();
      } else {
        pr_error(stdout, "__command__: sha1 hash generation failed");
      } /* if */
    }
    ret_code = -1;
    goto cleanup;
    
  /* Command processing - sha256 */
  } else if (strncmp(ptr_command, "sha256", strlen("sha256")) == 0) {
    char *args = ptr_command + strlen("sha256");
    while (*args == ' ') ++args;
    
    if (*args == '\0') {
      println(stdout, "Usage: sha256 [<words>]");
    } else {
      unsigned char digest[32];
      if (crypto_generate_sha256_hash(args, digest) == 1) {
        printf("      Crypto Input : " LR_YELLOW "%s\n", args);
        print_restore_color();
        printf("Crypto Output (SHA256) : " LR_YELLOW);
        crypto_print_hex(digest, sizeof(digest), 1);
        print_restore_color();
      } else {
        pr_error(stdout, "__command__: sha256 hash generation failed");
      } /* if */
    }
    ret_code = -1;
    goto cleanup;
    
  /* Command processing - crc32 */
  } else if (strncmp(ptr_command, "crc32", strlen("crc32")) == 0) {
    char *args = ptr_command + strlen("crc32");
    while (*args == ' ') ++args;
    
    if (*args == '\0') {
      println(stdout, "Usage: crc32 [<words>]");
    } else {
      uint32_t crc32_generate = crypto_generate_crc32(args, strlen(args));
      char crc_str[11] = {0};
      sprintf(crc_str, "%08X", crc32_generate);
      printf("     Crypto Input : " LR_YELLOW "%s\n", args);
      print_restore_color();
      printf("Crypto Output (CRC32) : " LR_YELLOW "%s\n", crc_str);
      print_restore_color();
    }
    ret_code = -1;
    goto cleanup;
    
  /* Command processing - djb2 */
  } else if (strncmp(ptr_command, "djb2", strlen("djb2")) == 0) {
    char *args = ptr_command + strlen("djb2");
    while (*args == ' ') ++args;
    
    if (*args == '\0') {
      println(stdout, "Usage: djb2 [<file>]");
    } else {
      if (path_exists(args) == 0) {
        pr_warning(stdout, "djb2: "
          LR_CYAN "%s - No such file or directory", args);
        ret_code = -1;
        goto cleanup;
      } /* if */
      
      unsigned long djb2_generate = crypto_djb2_hash_file(args);
      if (djb2_generate) {
        printf("    Crypto Input : " LR_YELLOW "%s\n", args);
        print_restore_color();
        printf("Crypto Output (DJB2) : " LR_YELLOW "%#lx\n", djb2_generate);
        print_restore_color();
      } else {
        pr_error(stdout, "__command__: djb2 hash generation failed");
      } /* if */
    }
    ret_code = -1;
    goto cleanup;
    
  /* Command processing - pbkdf2 */
  } else if (strncmp(ptr_command, "pbkdf2", strlen("pbkdf2")) == 0) {
    char *args = ptr_command + strlen("pbkdf2");
    while (*args == ' ') ++args;
    
    if (*args == '\0') {
      println(stdout, "Usage: pbkdf2 [<password>]");
    } else {
      unsigned char pbkdf_generate[32] = {0};
      unsigned char stored_salt[16] = {0};

      crypto_simple_rand_bytes(stored_salt, 16);

      int ret = crypto_derive_key_pbkdf2(args, stored_salt, 16, pbkdf_generate, 32);

      if (ret != 1) {
        printf("PBKDF2 Error\n");
        pr_error(stdout, "__command__: pbkdf2 derivation failed");
      } else {
        printf("    Crypto Input : " LR_YELLOW "%s\n", args);
        char *hex_output = NULL;
        crypto_convert_to_hex(pbkdf_generate, 32, &hex_output);
        print_restore_color();
        printf("Crypto Output (PBKDF2) : " LR_YELLOW "%s\n", hex_output);
        if (hex_output) free(hex_output);
      } /* if */
    }
    pbkdf_done:
    ret_code = -1;
    goto cleanup;
    
  /* Command processing - base64encode */
  } else if (strncmp(ptr_command, "base64encode", strlen("base64encode")) == 0) {
    char *args = ptr_command + strlen("base64encode");
    while (*args == ' ') ++args;
    
    if (*args == '\0') {
      println(stdout, "Usage: base64encode [<file/text>]");
    } else {
      /* Check if argument is a file */
      if (path_access(args) == 1) {
        FILE *fp = fopen(args, "rb");
        if (fp != NULL) {
          fseek(fp, 0, SEEK_END);
          long size = ftell(fp);
          rewind(fp);
          
          unsigned char *buffer = dog_malloc(size);
          if (buffer != NULL) {
            int r = fread(buffer, 1, size, fp);
            fclose(fp);

            char *encoded = crypto_base64_encode(buffer, size);
            if (encoded != NULL) {
              printf("    Crypto Input : " LR_YELLOW "%s\n", args);
              print_restore_color();
              printf("Crypto Output (base64) : " LR_YELLOW "%s\n", encoded);
              free(encoded);
            } /* if */
            
            free(buffer);
          } else {
            fclose(fp);
            pr_error(stdout, "__command__: failed to allocate buffer for file");
          } /* if */
        } else {
          pr_error(stdout, "__command__: failed to open file: %s", args);
        } /* if */
      } else {
        char *encoded = crypto_base64_encode(
          (const unsigned char *)args,
          strlen(args)
        );
        if (encoded) {
          printf("    Crypto Input : " LR_YELLOW "%s\n", args);
          print_restore_color();
          printf("Crypto Output (base64) : " LR_YELLOW "%s\n", encoded);
          free(encoded);
        } /* if */
      } /* if */
    }
    ret_code = -1;
    goto cleanup;
    
  /* Command processing - base64decode */
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
        pr_error(stdout, "__command__: invalid base64 input");
      } else {
        printf("    Crypto Input : " LR_YELLOW "%s\n", args);
        print_restore_color();
        printf("Crypto Output (text) : " LR_YELLOW "%.*s\n",
          decoded_len, decoded);
        free(decoded);
      } /* if */
    }

    ret_code = -1;
    goto cleanup;
    
  /* Command processing - aesencrypt */
  } else if (strncmp(ptr_command, "aesencrypt", strlen("aesencrypt")) == 0) {
    char *args = ptr_command + strlen("aesencrypt");
    while (*args == ' ') ++args;

    if (*args == '\0') {
      println(stdout, "Usage: aesencrypt [<text>]");
    } else {
      AES_KEY key;
      uint8_t in[AES_BLOCK_SIZE] = {0};
      uint8_t out[AES_BLOCK_SIZE] = {0};
      
      size_t len = strlen(args);
      if (len > AES_BLOCK_SIZE) {
        len = AES_BLOCK_SIZE;
        pr_info(stdout, "__command__: input truncated to %d bytes", AES_BLOCK_SIZE);
      } /* if */

      memcpy(in, args, len);

      crypto_aes_encrypt(in, out, &key);

      printf("    Crypto Input : " LR_YELLOW "%s\n", args);
      print_restore_color();
      printf("Crypto Output (hex)  : " LR_YELLOW);

      for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02X", out[i]);
      } /* for */

      (void)putchar('\n');
    }

    ret_code = -1;
    goto cleanup;
    
  /* Command processing - aesdecrypt */
  } else if (strncmp(ptr_command, "aesdecrypt", strlen("aesdecrypt")) == 0) {
    char *args = ptr_command + strlen("aesdecrypt");
    while (*args == ' ') ++args;

    if (*args == '\0') {
      println(stdout, "Usage: aesdecrypt [<text>]");
    } else {
      AES_KEY key;
      uint8_t in[AES_BLOCK_SIZE] = {0};
      uint8_t out[AES_BLOCK_SIZE] = {0};

      int bytes = hex_to_bytes(args, in, AES_BLOCK_SIZE);
      if (bytes <= 0) {
        println(stdout, "Invalid hex input.");
        pr_error(stdout, "__command__: invalid hex input for aesdecrypt");
        goto cleanup;
      } /* if */

      crypto_aes_decrypt(in, out, &key);

      printf("    Crypto Input : " LR_YELLOW "%s\n", args);
      print_restore_color();
      printf("Crypto Output    : " LR_YELLOW "%.*s\n",
        AES_BLOCK_SIZE, out);
    }

    ret_code = -1;
    goto cleanup;
    
  /* Command processing - config */
  } else if (strcmp(ptr_command, "config") == 0) {
    if (path_access("watchdogs.toml") == 1) {
      remove("watchdogs.toml");
      pr_info(stdout, "__command__: removed existing watchdogs.toml");
    } /* if */
    
    unit_debugging(1);
    fputs(LR_B_BLUE, stdout);
    print_file("watchdogs.toml");
    fputs(LR_DEFAULT "\n", stdout);
    
    ret_code = -1;
    goto cleanup;

  /* Command processing - gamemode */
  } else if (strcmp(ptr_command, "gamemode") == 0) {
    (void)console_title("Watchdogs | @ gamemode");
    
    unit_selection_state = true;
    
    printf("\033[1;33m== Select a Platform ==\033[0m\n");
    printf("  \033[36m[l]\033[0m Linux\n");
    printf("  \033[36m[w]\033[0m Windows\n"
         "  ^ \033[90m(Supported for: WSL/WSL2 ; not: Docker or Podman on WSL)\033[0m\n");
    printf("  \033[36m[t]\033[0m Termux\n");
    
    platform = readline("==> ");
    if (!platform) {
      pr_info(stdout, "__command__: no platform selected");
      ret_code = -1;
      goto cleanup;
    } /* if */
    
    int platform_ret = -1;
    if (_strfind(platform, "L", true)) {
      platform_ret = dog_install_server("linux");
    } else if (_strfind(platform, "W", true)) {
      platform_ret = dog_install_server("windows");
    } else if (_strfind(platform, "T", true)) {
      platform_ret = dog_install_server("termux");
    } else if (_strfind(platform, "E", true)) {
      ret_code = -1;
      goto cleanup;
    } else {
      pr_error(stdout, "Invalid platform selection. Input 'E/e' to exit");
      ret_code = -1;
      goto cleanup;
    } /* if */
    
    free(platform);
    platform = NULL;
    
    if (platform_ret == 0) {
      ret_code = -1;
      goto cleanup;
    } /* if */
    
    ret_code = -1;
    goto cleanup;
    
  /* Command processing - pawncc */
  } else if (strcmp(ptr_command, "pawncc") == 0) {
    (void)console_title("Watchdogs | @ pawncc");
    
    unit_selection_state = true;
    
    printf("\033[1;33m== Select a Platform ==\033[0m\n");
    printf("  \033[36m[l]\033[0m Linux\n");
    printf("  \033[36m[w]\033[0m Windows\n"
         "  ^ \033[90m(Supported for: WSL/WSL2 ; not: Docker or Podman on WSL)\033[0m\n");
    printf("  \033[36m[t]\033[0m Termux\n");
    
    platform = readline("==> ");
    if (!platform) {
      pr_info(stdout, "__command__: no platform selected");
      ret_code = -1;
      goto cleanup;
    } /* if */
    
    int platform_ret = -1;
    if (_strfind(platform, "L", true)) {
      platform_ret = dog_install_pawncc("linux");
    } else if (_strfind(platform, "W", true)) {
      platform_ret = dog_install_pawncc("windows");
    } else if (_strfind(platform, "T", true)) {
      platform_ret = dog_install_pawncc("termux");
    } else if (_strfind(platform, "E", true)) {
      ret_code = -1;
      goto cleanup;
    } else {
      pr_error(stdout, "Invalid platform selection. Input 'E/e' to exit");
      ret_code = -1;
      goto cleanup;
    } /* if */
    
    free(platform);
    platform = NULL;
    
    if (platform_ret == 0) {
      ret_code = -1;
      goto cleanup;
    } /* if */
    
    ret_code = -1;
    goto cleanup;
    
  /* Command processing - debug */
  } else if (strcmp(ptr_command, "debug") == 0) {
    (void)console_title("Watchdogs | @ debug");
    dog_stop_server_tasks();
    unit_ret_main("812C397D");
    ret_code = -1;
    goto cleanup;
    
  /* Command processing - 812C397D (internal) */
  } else if (strcmp(ptr_command, "812C397D") == 0) {
    dog_server_crash_check();
    ret_code = 3;
    goto cleanup;
    
  /* Command processing - compile */
  } else if (strncmp(ptr_command, "compile", strlen("compile")) == 0 &&
         !isalpha((unsigned char)ptr_command[strlen("compile")])) {
    (void)console_title("Watchdogs | @ compile | logging file: .watchdogs/compiler.log");
    
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
    
  /* Command processing - decompile */
  } else if (strncmp(ptr_command, "decompile", strlen("decompile")) == 0) {
    (void)console_title("Watchdogs | @ decompile");

    char *args = ptr_command + strlen("decompile");
    while (*args == ' ') args++;
    
    if (*args == '\0') {
      println(stdout, "Usage: decompile [<file.amx>]");
      ret_code = -1;
      goto cleanup;
    } /* if */
    
    if (_strfind(args, ".amx", true) == false) {
      println(stdout, "Usage: decompile [<file.amx>]");
      ret_code = -1;
      goto cleanup;
    } /* if */

    char *p = NULL;
    
    char *a_args = strdup(args);
    if (a_args == NULL) {
      pr_error(stdout, "__command__: failed to duplicate args for decompile");
      ret_code = -1;
      goto cleanup;
    } /* if */
    
    #ifdef DOG_LINUX
    path_sep_to_posix(a_args);
    #else
    path_sep_to_win32(a_args);
    #endif
    
    if (path_exists(a_args) == 0) {
      pr_warning(stdout, "decompile: "
        LR_CYAN "%s - No such file or directory", a_args);
      dog_free(a_args);
      ret_code = -1;
      goto cleanup;
    } /* if */

    char *ptr = NULL;
    int   ret = 0;
    
    if (strcmp(dogconfig.dog_toml_os_type, OSYS_WINDOWS) == 0) {
      ptr = "pawndisasm.exe";
    } else if (strcmp(dogconfig.dog_toml_os_type, OSYS_LINUX) == 0) {
      ptr = "pawndisasm";
    } else {
      pr_error(stdout, "__command__: unknown OS type for decompile");
      dog_free(a_args);
      ret_code = -1;
      goto cleanup;
    } /* if */

    _sef_restore();

    /* Find pawndisasm in various locations */
    if (dir_exists("pawno") != 0 && dir_exists("qawno") != 0) {
      ret = find_path("pawno", ptr, NULL);
      if (ret <= 0) {
        ret = find_path("qawno", ptr, NULL);
        if (ret < 1) {
          ret = find_path(".", ptr, NULL);
        } /* if */
      } /* if */
    } else if (dir_exists("pawno") != 0) {
      ret = find_path("pawno", ptr, NULL);
      if (ret <= 0) {
        ret = find_path(".", ptr, NULL);
      } /* if */
    } else if (dir_exists("qawno") != 0) {
      ret = find_path("qawno", ptr, NULL);
      if (ret <= 0) {
        ret = find_path(".", ptr, NULL);
      } /* if */
    } else {
      ret = find_path(".", ptr, NULL);
    } /* if */
    
    if (ret > 0) {

      char *args2 = strdup(a_args);
      if (args2 == NULL) {
        dog_free(a_args);
        ret_code = -1;
        goto cleanup;
      } /* if */
      
      char *dot_amx = strstr(args2, ".amx");
      if (dot_amx) {
        *dot_amx = '\0';
      } /* if */
      
      pbuf[0] = '\0';
      (void)snprintf(pbuf, sizeof(pbuf), "%s.asm", args2);
      dog_free(args2);
      
      char s_argv[DOG_PATH_MAX * 3] = {0};
      
      #ifdef DOG_LINUX
        char *executor = "sh -c";
        (void)snprintf(s_argv, sizeof(s_argv), "%s '%s %s %s'",
          executor,
          dogconfig.dog_sef_found_list[0],
          a_args, pbuf);
      #else
        char *executor = "cmd.exe /C";
        (void)snprintf(s_argv, sizeof(s_argv), "%s %s %s %s",
          executor,
          dogconfig.dog_sef_found_list[0],
          a_args, pbuf);
      #endif
      
      int sys_ret = system(s_argv);
      if (sys_ret == 0) {
        println(stdout, "%s", pbuf);
      } /* if */
      
      (void)console_title(s_argv);
    } else {
      printf("\033[1;31merror:\033[0m pawndisasm/pawncc (our compiler) not found\n"
        "  \033[2mhelp:\033[0m install it before continuing\n");
    } /* if */
    
    dog_free(a_args);
    ret_code = -1;
    goto cleanup;

  /* Command processing - pawnruns */
  } else if (strncmp(ptr_command, "pawnruns", strlen("pawnruns")) == 0) {
    (void)console_title("Watchdogs | @ pawnruns");

    _Bool empty_args = false;

    char *args = ptr_command + strlen("pawnruns");
    while (*args == ' ') args++;
    
    if (*args == '\0') {
      empty_args = !empty_args;
      goto pawnruns_empty_check;
    } /* if */
    
    if (_strfind(args, ".amx", true) == false) {
      println(stdout, "Usage: pawnruns [<file.amx>]");
      ret_code = -1;
      goto cleanup;
    } /* if */
  
    char *a_args = NULL;
    
  pawnruns_empty_check:
    if (empty_args) {
      if (path_exists(dogconfig.dog_toml_serv_output) == 1) {
        a_args = strdup(dogconfig.dog_toml_serv_output);
        if (a_args == NULL) {
          pr_error(stdout, "__command__: failed to duplicate output path");
          ret_code = -1;
          goto cleanup;
        } /* if */
        goto pawnruns_next;
      } else {
        println(stdout, "Usage: pawnruns [<file.amx>]");
        ret_code = -1;
        goto cleanup;
      } /* if */
    } /* if */
    
    a_args = strdup(args);
    if (a_args == NULL) {
      pr_error(stdout, "__command__: failed to duplicate args for pawnruns");
      ret_code = -1;
      goto cleanup;
    } /* if */
  
    char *p = NULL;
    
  pawnruns_next:
    #ifdef DOG_LINUX
    path_sep_to_posix(a_args);
    #else
    path_sep_to_win32(a_args);
    #endif

    if (path_exists(a_args) == 0) {
      pr_warning(stdout, "pawnruns: "
        LR_CYAN "%s - No such file or directory", a_args);
      dog_free(a_args);
      ret_code = -1;
      goto cleanup;
    } /* if */

    char *ptr = NULL;
    int   ret = 0;
    
    if (strcmp(dogconfig.dog_toml_os_type, OSYS_WINDOWS) == 0) {
      ptr = "pawnruns.exe";
    } else if (strcmp(dogconfig.dog_toml_os_type, OSYS_LINUX) == 0) {
      ptr = "pawnruns";
    } else {
      pr_error(stdout, "__command__: unknown OS type for pawnruns");
      dog_free(a_args);
      ret_code = -1;
      goto cleanup;
    } /* if */

    _sef_restore();

    /* Find pawnruns in various locations */
    if (dir_exists("pawno") != 0 && dir_exists("qawno") != 0) {
      ret = find_path("pawno", ptr, NULL);
      if (ret <= 0) {
        ret = find_path("qawno", ptr, NULL);
        if (ret < 1) {
          ret = find_path(".", ptr, NULL);
        } /* if */
      } /* if */
    } else if (dir_exists("pawno") != 0) {
      ret = find_path("pawno", ptr, NULL);
      if (ret <= 0) {
        ret = find_path(".", ptr, NULL);
      } /* if */
    } else if (dir_exists("qawno") != 0) {
      ret = find_path("qawno", ptr, NULL);
      if (ret <= 0) {
        ret = find_path(".", ptr, NULL);
      } /* if */
    } else {
      ret = find_path(".", ptr, NULL);
    } /* if */
    
    if (ret > 0) {

      pbuf[0] = '\0';
      
      #ifdef DOG_LINUX
        char *executor = "sh -c";
        (void)snprintf(pbuf, sizeof(pbuf), "%s '%s %s'",
          executor,
          dogconfig.dog_sef_found_list[0],
          a_args);
      #else
        char *executor = "cmd.exe /C";
        (void)snprintf(pbuf, sizeof(pbuf), "%s %s %s",
          executor,
          dogconfig.dog_sef_found_list[0],
          a_args);
      #endif
      
      int sys_ret = system(pbuf);
      (void)console_title(pbuf);
    } else {
      printf("\033[1;31merror:\033[0m pawnruns/pawncc (our compiler) not found\n"
        "  \033[2mhelp:\033[0m install it before continuing\n");
    } /* if */
    
    dog_free(a_args);
    ret_code = -1;
    goto cleanup;

  /* Command processing - running */
  } else if (strcmp(ptr_command, "running") == 0) {
    static _Bool init_load_cfg = false;
    sigint_handler = 0;
    dog_stop_server_tasks();
    
    char *binary = dogconfig.dog_toml_server_binary;
    char *config = dogconfig.dog_toml_server_config;

    if (!binary || path_access(binary) == 0) {
      pr_error(stdout, "can't locate SA-MP/open.mp binary file!");
      ret_code = -1;
      goto cleanup;
    } /* if */
    
    if (!config || path_access(config) == 0) {
      pr_warning(stdout, "can't locate %s - config file!",
        config ? config : "(null)");
      ret_code = -1;
      goto cleanup;
    } /* if */
    
    if (init_load_cfg == false) {
      init_load_cfg = true;
      print_file(config);
    } /* if */
    
    if (path_exists(dogconfig.dog_toml_server_logs) == 1) {
      remove(dogconfig.dog_toml_server_logs);
    } /* if */
    
    if (dir_exists(".watchdogs") == 0) {
      MKDIR(".watchdogs");
    } /* if */
    
    char title[DOG_PATH_MAX] = {0};
    (void)snprintf(title, DOG_PATH_MAX,
        "Watchdogs | @ running | config: %s | "
        "CTRL + C to stop. | \"debug\" to debugging",
        config);
    
    #ifdef DOG_ANDROID
      println(stdout, "%s", title);
    #else
      (void)console_title(title);
    #endif
    
    struct sigaction sa;
    
    if (path_access("announce") == 1) {
      __set_default_access("announce");
    } /* if */
    
    __set_default_access(binary);

    sa.sa_handler = unit_sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    
    if (sigaction(SIGINT, &sa, NULL) == -1) {
      perror("sigaction");
      exit(EXIT_FAILURE);
    } /* if */
    
    #ifdef DOG_WINDOWS
    dog_exec_windows_server(binary);
    #else
    dog_exec_linux_server(binary);
    #endif
    
    print_restore_color();
    putchar('\n');

    (void)signal(SIGINT, SIG_DFL);
    sigint_handler = !sigint_handler;

    fputs("\x1b[32m==> create debugging?\x1b[0m\n", stdout);
    debug_server = readline("   answer (y/n): ");
    
    if (debug_server) {
      if (debug_server[0] == '\0' ||
        strcmp(debug_server, "Y") == 0 ||
        strcmp(debug_server, "y") == 0) {
        unit_ret_main("debug");
      } /* if */
    } /* if */
    
    ret_code = -1;
    goto cleanup;
    
  /* Command processing - compiles */
  } else if (strncmp(ptr_command, "compiles", strlen("compiles")) == 0) {
    (void)console_title("Watchdogs | @ compiles");
    
    char *args = ptr_command + strlen("compiles");
    while (*args == ' ') ++args;
    char *args2 = strtok(args, " ");
    
    if (!args2 || args2[0] == '\0' || args2[0] == '.') {
      dog_exec_compiler(NULL, ".", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
      configure_toml();
      
      if (!pc_is_error) {
        unit_ret_main("running");
      } /* if */
    } else {
      dog_exec_compiler(NULL, args2, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
      configure_toml();
      
      if (!pc_is_error) {
        unit_ret_main("running");
      } /* if */
    } /* if */
    
    ret_code = -1;
    goto cleanup;
    
  /* Command processing - stop */
  } else if (strcmp(ptr_command, "stop") == 0) {
    (void)console_title("Watchdogs | @ stop");
    dog_stop_server_tasks();
    ret_code = -1;
    goto cleanup;
    
  /* Command processing - restart */
  } else if (strcmp(ptr_command, "restart") == 0) {
    (void)console_title("Watchdogs | @ restart");
    dog_stop_server_tasks();
    unit_ret_main("running");
    ret_code = -1;
    goto cleanup;
    
  /* Command processing - tracker */
  } else if (strncmp(ptr_command, "tracker", strlen("tracker")) == 0) {
    char *args = ptr_command + strlen("tracker");
    while (*args == ' ') ++args;
    
    if (*args == '\0') {
      println(stdout, "Usage: tracker [<name>]");
      ret_code = -1;
      goto cleanup;
    } /* if */
    
    CURL *curl;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    
    if (!curl) {
      fprintf(stderr, "Curl initialization failed!\n");
      ret_code = -1;
      goto cleanup;
    } /* if */
    
    int variation_count = 0;
    char variations[MAX_VARIATIONS][MAX_USERNAME_LEN] = {{0}};
    
    tracker_discrepancy(args, variations, &variation_count);
    
    printf("[TRACKER] Search base: %s\n", args);
    printf("[TRACKER] Generated %d Variations\n\n", variation_count);
    
    for (int i = 0; i < variation_count; i++) {
      if (variations[i][0] != '\0') {
        printf("=== TRACKING ACCOUNTS: %s ===\n", variations[i]);
        tracking_username(curl, variations[i]);
        (void)putchar('\n');
      } /* if */
    } /* for */
    
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    ret_code = -1;
    goto cleanup;
    
  /* Command processing - compress */
  } else if (strncmp(ptr_command, "compress", strlen("compress")) == 0) {
    char *args = ptr_command + strlen("compress");
    while (*args == ' ') args++;
    
    if (*args == '\0') {
      printf("Usage: compress --file <input> --output <output> --type <format>\n");
      printf("Example:\n\tcompress --file myfile.txt --output myarchive.zip --type zip\n\t"
           "compress --file myfolder/ --output myarchive.tar.gz --type gz\n");
      ret_code = -1;
      goto cleanup;
    } /* if */
    
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
      } /* if */
      procure_args = strtok(NULL, " ");
    } /* while */
    
    if (!store_input || !store_output || !store_type) {
      printf("Missing arguments!\n");
      printf("Usage: compress --file <input> --output <output> --type <zip|tar|gz|bz2|xz>\n");
      printf("Example:\n\tcompress --file myfile.txt --output myarchive.zip --type zip\n\t"
           "compress --file myfolder/ --output myarchive.tar.gz --type gz\n");
      ret_code = -1;
      goto cleanup;
    } /* if */
    
    CompressionFormat fmt;
    
    if (strcmp(store_type, "zip") == 0) {
      fmt = COMPRESS_ZIP;
    } else if (strcmp(store_type, "tar") == 0) {
      fmt = COMPRESS_TAR;
    } else if (strcmp(store_type, "gz") == 0) {
      fmt = COMPRESS_TAR_GZ;
    } else if (strcmp(store_type, "bz2") == 0) {
      fmt = COMPRESS_TAR_BZ2;
    } else if (strcmp(store_type, "xz") == 0) {
      fmt = COMPRESS_TAR_XZ;
    } else {
      printf("Unknown type: %s\n", store_type);
      printf("Supported: zip, tar, gz, bz2, xz\n");
      ret_code = -1;
      goto cleanup;
    } /* if */
    
    const char *procure_items[] = { store_input };
    int ret = compress_to_archive(store_output, procure_items, 1, fmt);
    
    if (ret == 0) {
      pr_info(stdout, "Converter file/folder to "
      "archive (Compression) successfully: %s\n", store_output);
    } else {
      pr_error(stdout, "Compression failed!\n");
      minimal_debugging();
    } /* if */
    
    ret_code = -1;
    goto cleanup;
    
  /* Command processing - watchdogs/dog */
  } else if (strcmp(ptr_command, "watchdogs") == 0 || strcmp(ptr_command, "dog") == 0) {
    unit_show_dog();
    ret_code = -1;
    goto cleanup;
    
  /* Command processing - similar command suggestion */
  } else if (command_similar != NULL && strcmp(ptr_command, command_similar) != 0 && dist <= 2) {
    (void)console_title("Watchdogs | @ undefined");
    println(stdout, "watchdogs: '%s' is not valid watchdogs command. See 'help'.", ptr_command);
    println(stdout, "   but did you mean '%s'?", command_similar);
    goto cleanup;

  } else {
    goto cleanup;
  } /* if */

cleanup:
  /* Clean up all allocated resources */
  cleanup_local_resources(&ptr_command_prompt, &ptr_command, &title,
               &size_command, &platform, &pointer_signalA,
               &debug_server, &size_args, &compile_target);

#if defined(_DBG_PRINT)
  pr_info(stdout, "__command__: returning with code %d", ret_code);
#endif
  return (ret_code);
} /* __command__ */

void
unit_ret_main(void *unit_pre_command)
{
  int ret = -3;

#if defined(_DBG_PRINT)
  pr_info(stdout, "unit_ret_main: entering with pre_command=%s", 
       unit_pre_command ? (char*)unit_pre_command : "NULL");
#endif
  /* Handle pre-command if provided */
  if (unit_pre_command != NULL) {
    char *procure_command_argv = strdup((char *)unit_pre_command);
    if (procure_command_argv) {
      ret = __command__(procure_command_argv);
      free(procure_command_argv);
    } else {
      pr_error(stdout, "unit_ret_main: failed to duplicate pre-command");
    } /* if */
    
    clock_gettime(CLOCK_MONOTONIC, &cmd_end);
    
    if (ret == -2 || ret == 3) {
      return;
    } /* if */
    
    return;
  } /* if */

  /* Main interactive loop */
loop_main:
  ret = __command__(NULL);
  
  if (ret == -1) {
    clock_gettime(CLOCK_MONOTONIC, &cmd_end);
    command_dur = ((double)(cmd_end.tv_sec - cmd_start.tv_sec)) +
            ((double)(cmd_end.tv_nsec - cmd_start.tv_nsec)) / 1e9;
    pr_color(stdout, LR_CYAN, " <I> (interactive) Finished At %.3fs\n", command_dur);
    goto loop_main;
    
  } else if (ret == 2) {
    clock_gettime(CLOCK_MONOTONIC, &cmd_end);
    (void)console_title("Terminal.");
    
    clear_history();
    
    /* Free all configuration resources */
    if (dogconfig.dog_ptr_samp) { free(dogconfig.dog_ptr_samp); dogconfig.dog_ptr_samp = NULL; }
    if (dogconfig.dog_ptr_omp) { free(dogconfig.dog_ptr_omp); dogconfig.dog_ptr_omp = NULL; }
    if (dogconfig.dog_pawncc_path) { free(dogconfig.dog_pawncc_path); dogconfig.dog_pawncc_path = NULL; }
    if (dogconfig.dog_toml_os_type) { free(dogconfig.dog_toml_os_type); dogconfig.dog_toml_os_type = NULL; }
    if (dogconfig.dog_toml_server_binary) { free(dogconfig.dog_toml_server_binary); dogconfig.dog_toml_server_binary = NULL; }
    if (dogconfig.dog_toml_server_config) { free(dogconfig.dog_toml_server_config); dogconfig.dog_toml_server_config = NULL; }
    if (dogconfig.dog_toml_server_logs) { free(dogconfig.dog_toml_server_logs); dogconfig.dog_toml_server_logs = NULL; }
    if (dogconfig.dog_toml_full_opt) { free(dogconfig.dog_toml_full_opt); dogconfig.dog_toml_full_opt = NULL; }
    if (dogconfig.dog_toml_serv_input) { free(dogconfig.dog_toml_serv_input); dogconfig.dog_toml_serv_input = NULL; }
    if (dogconfig.dog_toml_serv_output) { free(dogconfig.dog_toml_serv_output); dogconfig.dog_toml_serv_output = NULL; }
    if (pc_full_includes) { free(pc_full_includes); pc_full_includes = NULL; }
    
    exit(EXIT_SUCCESS);
    
  } else if (ret == -2) {
    clock_gettime(CLOCK_MONOTONIC, &cmd_end);
    goto loop_main;
    
  } else if (ret == 3) {
    clock_gettime(CLOCK_MONOTONIC, &cmd_end);
    
  } else {
    goto basic_end;
  } /* if */

basic_end:
  clock_gettime(CLOCK_MONOTONIC, &cmd_end);
  command_dur = ((double)(cmd_end.tv_sec - cmd_start.tv_sec)) +
         ((double)(cmd_end.tv_nsec - cmd_start.tv_nsec)) / 1e9;
  pr_color(stdout, LR_CYAN, " <I> (interactive) Finished At %.3fs\n", command_dur);
  goto loop_main;
} /* unit_ret_main */

int
main(int argc, char *argv[])
{
  int ret = 0;
  int i;
  
  /* Disable stdout buffering */
  setvbuf(stdout, NULL, _IONBF, 0);
  
  /* Handle command line arguments */
  if (argc > 1) {
    size_t unit_total_len = 0;

    /* Calculate total length needed for all arguments */
    for (i = 1; i < argc; ++i) {
      if (argv[i] != NULL) {
        unit_total_len += strlen(argv[i]) + 1;
      } /* if */
    } /* for */

    /* Allocate buffer for concatenated arguments */
    char *unit_size_prompt = dog_malloc(unit_total_len);
    if (!unit_size_prompt) {
      pr_error(stdout, "main: failed to allocate argument buffer");
      return (0);
    } /* if */

    /* Concatenate all arguments with spaces */
    char *ptr = unit_size_prompt;
    for (i = 1; i < argc; ++i) {
      if (argv[i] != NULL) {
        if (i > 1) {
          *ptr++ = ' ';
        } /* if */
        
        size_t len = strlen(argv[i]);
        memcpy(ptr, argv[i], len);
        ptr += len;
      } /* if */
    } /* for */
    
    *ptr = '\0';
    
    /* Execute with provided arguments */
    unit_ret_main(unit_size_prompt);

    /* Clean up */
    dog_free(unit_size_prompt);
    unit_size_prompt = NULL;

    return (0);
  } else {
    /* Interactive mode */
    unit_ret_main(NULL);
  } /* if */

  return (0);
} /* main */