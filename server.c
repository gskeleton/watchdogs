#include "units.h"
#include "utils.h"
#include "crypto.h"
#include "compiler.h"
#include "debug.h"
#include "server.h"

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
} /* unit_sigint_handler */

/**
 * Stop running server processes
 */
void
dog_stop_server_tasks(void)
{
  _Bool ret = false;
  
  pr_info(stdout, "dog_stop_server_tasks: stopping server tasks");
  
  ret = terminate_proc(dogconfig.dog_toml_server_binary);
  if (ret == false) {
    pr_info(stdout, "dog_stop_server_tasks: first kill attempt failed, retrying");
    terminate_proc(dogconfig.dog_toml_server_binary);
  } else {
    ;
  } /* if */
} /* dog_stop_server_tasks */

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

/**
 * Main server crash log analysis function
 */
void
dog_server_crash_check(void)
{
  FILE* fp = NULL;
  char buf[DOG_MAX_PATH] = {0};
  int line_count = 0;
  int error_count = 0;
  
  pr_info(stdout, "dog_server_crash_check: starting crash log analysis");

  /* Reset state variables */
  rate_sampvoice_server = 0;
  rate_problem_stat = 0;
  server_crashdetect = 0;
  server_rcon_pass = 0;
  
  if (sampvoice_port != NULL) {
    free(sampvoice_port);
    sampvoice_port = NULL;
  } /* if */

  /* Open log file */
  fp = fopen(dogconfig.dog_toml_server_logs, "rb");
  if (fp == NULL) {
    pr_error(stdout, "log file not found!.");
    minimal_debugging();
    return;
  } /* if */
  
  pr_info(stdout, "dog_server_crash_check: opened log file: %s", dogconfig.dog_toml_server_logs);

  /* Check for crashinfo.txt */
  if (path_exists("crashinfo.txt") == 1) {
    char* confirm = NULL;

    pr_info(stdout, "crashinfo.txt detected..");
    confirm = readline("-> show? ");
    
    if (confirm != NULL) {
      if (confirm[0] == '\0' || confirm[0] == 'Y' || confirm[0] == 'y') {
        print_file("crashinfo.txt");
        pr_info(stdout, "dog_server_crash_check: displayed crashinfo.txt");
      } /* if */
      dog_free(confirm);
    } /* if */
  } /* if */

  separator_print();

  /* Parse log file line by line */
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    line_count++;
    
    /* Remove trailing newline for cleaner output */
    size_t buf_len = strlen(buf);
    if (buf_len > 0 && buf[buf_len - 1] == '\n') {
      buf[buf_len - 1] = '\0';
    } /* if */
    
    /* Check for various error patterns */
    if (_strfind(buf, "Unable to load filterscript", 1)) {
      error_print("@ Unable to load filterscript detected", buf);
      error_count++;
      continue;
    } /* if */

    if (_strfind(buf, "Invalid index parameter (bad entry point)", 1)) {
      error_print("@ Invalid index parameter detected", buf);
      error_count++;
      continue;
    } /* if */

    if (_strfind(buf, "run time error", 1)) {
      runtime_error_check(buf);
      error_count++;
      continue;
    } /* if */

    if (_strfind(buf, "The script might need to be recompiled with the latest include file.", 1)) {
      recompile_check(buf);
      error_count++;
      continue;
    } /* if */

    if (_strfind(buf, "terminate called after throwing an instance of 'ghc::filesystem::filesystem_error", 1) ||
      _strfind(buf, "filesystem_error", 1)) {
      filesystem_error_check(buf);
      error_count++;
      continue;
    } /* if */

    if (_strfind(buf, "I couldn't load any gamemode scripts.", 1)) {
      gamemode_error_check(buf);
      error_count++;
      continue;
    } /* if */

    if (_strfind(buf, "0x", 1) || _strfind(buf, "address", 1) || _strfind(buf, "Address", 1)) {
      address_check(buf);
      error_count++;
      continue;
    } /* if */

    if (rate_problem_stat != 0) {
      if (crashdetect_check(buf) != 0) {
        error_count++;
        continue;
      } /* if */
      
      if (general_crash_check(buf) != 0) {
        error_count++;
        continue;
      } /* if */
    } /* if */

    if (_strfind(buf, "out of bounds", 1) || _strfind(buf, "out-of-bounds", 1)) {
      outofbounds_check(buf);
      error_count++;
      continue;
    } /* if */

    if (!fet_server_env() && _strfind(buf, "Your password must be changed from the default password", 1)) {
      server_rcon_pass++;
      error_count++;
      continue;
    } /* if */

    if (_strfind(buf, "It needs a gamemode0 buffer", 1)) {
      critical_check(buf);
      error_count++;
      continue;
    } /* if */

    if (_strfind(buf, "warning", 1)) {
      warning_check(buf);
      continue; /* Warnings don't count as errors */
    } /* if */

    if (_strfind(buf, "failed", 1)) {
      failure_check(buf);
      error_count++;
      continue;
    } /* if */

    if (_strfind(buf, "timeout", 1)) {
      timeout_check(buf);
      error_count++;
      continue;
    } /* if */

    if (_strfind(buf, "plugin", 1)) {
      plugin_check(buf);
      error_count++;
      continue;
    } /* if */

    if (_strfind(buf, "database", 1) || _strfind(buf, "mysql", 1)) {
      database_check(buf);
      error_count++;
      continue;
    } /* if */

    if (_strfind(buf, "out of memory", 1) || _strfind(buf, "memory allocation", 1)) {
      memory_check(buf);
      error_count++;
      continue;
    } /* if */

    if (_strfind(buf, "malloc", 1) || _strfind(buf, "free", 1) ||
      _strfind(buf, "realloc", 1) || _strfind(buf, "calloc", 1)) {
      alloc_check(buf);
      error_count++;
      continue;
    } /* if */

    if (_strfind(buf, "Info", 1)) {
      info_check(buf);
      continue;
    } /* if */

    /* Check for SampVoice port */
    sampvoice_port_detect(buf);
  } /* while */

  pr_info(stdout, "dog_server_crash_check: processed %d lines, found %d errors", line_count, error_count);
  
  fclose(fp);

  /* Post-analysis checks */
  sampvoice_port_check();
  rcon_password_check();

  if (sampvoice_port != NULL) {
    free(sampvoice_port);
    sampvoice_port = NULL;
  } /* if */

  puts("Done.\n");

  separator_print();
} /* dog_server_crash_check */

/**
 * Print separator line
 */
static void
separator_print(void)
{
  char out[64] = {0};
  int n = 0;

  n = snprintf(out, sizeof(out),
    "--------------------------------------------------------------\n");
  
  if (n > 0 && n < (int)sizeof(out)) {
    fwrite(out, 1, (size_t)n, stdout);
    fflush(stdout);
  } /* if */
} /* separator_print */

/**
 * Print error message with context
 */
static void
error_print(const char* msg, const char* buf)
{
  char out[DOG_MAX_PATH + 26] = {0};
  int n = 0;

  /* Validate input parameters */
  if (msg == NULL) {
    pr_error(stdout, "error_print: msg is NULL");
    return;
  } /* if */
  
  if (buf == NULL) {
    pr_error(stdout, "error_print: buf is NULL");
    return;
  } /* if */

  n = snprintf(out, sizeof(out), "%s\n\t", msg);
  
  if (n > 0 && n < (int)sizeof(out)) {
    fwrite(out, 1, (size_t)n, stdout);
    pr_color(stdout, LR_BLUE, "%s", buf);
    fflush(stdout);
  } /* if */
} /* error_print */

/**
 * Check for runtime errors
 */
static void
runtime_error_check(const char* buf)
{
  char out[512] = {0};
  int n = 0;
  size_t len = 0;

  /* Validate input */
  if (buf == NULL) {
    pr_error(stdout, "runtime_error_check: buf is NULL");
    return;
  } /* if */

  rate_problem_stat = 1;

  n = snprintf(out, sizeof(out), "@ Runtime error detected\n\t");
  len = (n < 0) ? 0 : (size_t)n;
  
  if (len > 0) {
    fwrite(out, 1, len, stdout);
    pr_color(stdout, LR_BLUE, "%s", buf);
    fflush(stdout);
  } /* if */

  /* Handle AMX version mismatch */
  if (_strfind(buf, "\"File is for a newer version of the AMX\"", 1)) {
    n = snprintf(out, sizeof(out),
      " * You need to open watchdogs.toml and "
      "change -O:2 to -O:1, then recompile your gamemode.\n");
    len = (n < 0) ? 0 : (size_t)n;
    
    if (len > 0) {
      fwrite(out, 1, len, stdout);
      fflush(stdout);
    } /* if */
  } /* if */
} /* runtime_error_check */

/**
 * Handle recompile suggestion
 */
static void
recompile_check(const char* buf)
{
  char* input = NULL;
  char out[512] = {0};
  int n = 0;
  size_t len = 0;

  /* Validate input */
  if (buf == NULL) {
    pr_error(stdout, "recompile_check: buf is NULL");
    return;
  } /* if */

  n = snprintf(out, sizeof(out), "@ Needed for recompiled\n\t");
  len = (n < 0) ? 0 : (size_t)n;
  
  if (len > 0) {
    fwrite(out, 1, len, stdout);
    pr_color(stdout, LR_BLUE, "%s", buf);
    fflush(stdout);
  } /* if */

  input = readline("Recompile now? ");
  if (input == NULL) {
    pr_info(stdout, "recompile_check: readline returned NULL");
    return;
  } /* if */

  if (input[0] == '\0' || !strcmp(input, "Y") || !strcmp(input, "y")) {
    dog_free(input);
    printf(LR_BCYAN
      "Please input the pawn file\n\t* (enter for %s - input E/e to exit):" LR_DEFAULT,
      dogconfig.dog_toml_serv_input ? dogconfig.dog_toml_serv_input : "default");
    input = readline(" ");

    if (input != NULL) {
      if (strlen(input) < 1) {
        dog_exec_compiler(NULL, ".", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
      } else if (strlen(input) > 0 && input[0] != 'E' && input[0] != 'e') {
        dog_exec_compiler(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
      } /* if */
      dog_free(input);
    } /* if */
  } else {
    dog_free(input);
  } /* if */
} /* recompile_check */

/**
 * Handle filesystem errors (especially WSL-related)
 */
static void
filesystem_error_check(const char* buf)
{
  char out[1024] = {0};
  int n = 0;
  size_t len = 0;

  /* Validate input */
  if (buf == NULL) {
    pr_error(stdout, "filesystem_error_check: buf is NULL");
    return;
  } /* if */

  n = snprintf(out, sizeof(out), "@ Filesystem C++ Error Detected\n\t");
  len = (n < 0) ? 0 : (size_t)n;
  
  if (len > 0) {
    fwrite(out, 1, len, stdout);
    pr_color(stdout, LR_BLUE, "%s", buf);
    fflush(stdout);
  } /* if */

  n = snprintf(out, sizeof(out),
    " * Are you currently using the WSL ecosystem?\n"
    " * You need to move the open.mp server folder from the /mnt area (your Windows directory) to \"~\" (your WSL HOME).\n"
    " * This is because open.mp C++ filesystem cannot properly read directories inside the /mnt area,\n"
    "   which isn't part of the directory model targeted by the Linux build.\n"
    " ** You must run it outside the /mnt area.\n");
  len = (n < 0) ? 0 : (size_t)n;
  
  if (len > 0) {
    fwrite(out, 1, len, stdout);
    fflush(stdout);
  } /* if */
} /* filesystem_error_check */

/**
 * Handle gamemode loading errors
 */
static void
gamemode_error_check(const char* buf)
{
  char out[1024] = {0};
  int n = 0;
  size_t len = 0;

  /* Validate input */
  if (buf == NULL) {
    pr_error(stdout, "gamemode_error_check: buf is NULL");
    return;
  } /* if */

  n = snprintf(out, sizeof(out), "@ Can't found gamemode detected\n\t");
  len = (n < 0) ? 0 : (size_t)n;
  
  if (len > 0) {
    fwrite(out, 1, len, stdout);
    pr_color(stdout, LR_BLUE, "%s", buf);
    fflush(stdout);
  } /* if */

  n = snprintf(out, sizeof(out),
    " * You need to ensure that the name specified "
    "   in the configuration file matches the one in the gamemodes/ folder,\n"
    " * and that the .amx file exists. For example, "
    " * if server.cfg contains\n"
    LR_CYAN "   gamemode0" LR_DEFAULT " main 1 or config.json" LR_CYAN " pawn.main_scripts [\"main 1\"]\n"
    LR_DEFAULT
    "  * then main.amx must be present in the gamemodes/ directory\n");
  len = (n < 0) ? 0 : (size_t)n;
  
  if (len > 0) {
    fwrite(out, 1, len, stdout);
    fflush(stdout);
  } /* if */
} /* gamemode_error_check */

/**
 * Handle memory address references
 */
static void
address_check(const char* buf)
{
  char out[128] = {0};

  /* Validate input */
  if (buf == NULL) {
    pr_error(stdout, "address_check: buf is NULL");
    return;
  } /* if */

  if (_strfind(buf, "0x", 1)) {
    snprintf(out, sizeof(out), "@ Hexadecimal address found\n\t");
    error_print(out, buf);
  } else {
    snprintf(out, sizeof(out), "@ Memory address reference found\n\t");
    error_print(out, buf);
  } /* if */
} /* address_check */

/**
 * Check for crashdetect plugin output
 */
static int
crashdetect_check(const char* buf)
{
  char out[256] = {0};
  int n = 0;
  size_t len = 0;
  int ret = 0;

  /* Validate input */
  if (buf == NULL) {
    pr_error(stdout, "crashdetect_check: buf is NULL");
    return 0;
  } /* if */

  if (!_strfind(buf, "[debug]", 1) && !_strfind(buf, "crashdetect", 1)) {
    return 0;
  } /* if */

  server_crashdetect++;
  ret = 1;

  snprintf(out, sizeof(out), "@ Crashdetect debug information found\n\t");
  error_print(out, buf);

  if (_strfind(buf, "AMX backtrace", 1)) {
    snprintf(out, sizeof(out), "@ Crashdetect: AMX backtrace detected\n\t");
    error_print(out, buf);
  } /* if */

  if (_strfind(buf, "native stack trace", 1)) {
    snprintf(out, sizeof(out), "@ Crashdetect: Native stack trace detected\n\t");
    error_print(out, buf);
  } /* if */

  if (_strfind(buf, "heap", 1)) {
    snprintf(out, sizeof(out), "@ Crashdetect: Heap issue detected\n\t");
    error_print(out, buf);
  } /* if */

  if (_strfind(buf, "[debug]", 1)) {
    snprintf(out, sizeof(out), "@ Crashdetect: Debug detected\n\t");
    error_print(out, buf);
  } /* if */

  /* Handle native backtrace with specific plugin conflicts */
  if (_strfind(buf, "Native backtrace", 1)) {
    char* input = NULL;
    char advice[2048] = {0};

    snprintf(out, sizeof(out), "@ Crashdetect: Native backtrace detected\n\t");
    error_print(out, buf);

    if (_strfind(buf, "sampvoice", 1) && _strfind(buf, "pawnraknet", 1)) {
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
      
      if (len > 0) {
        fwrite(advice, 1, len, stdout);
        fflush(stdout);
      } /* if */
    } /* if */
  } /* if */

  return ret;
} /* crashdetect_check */

/**
 * Check for general crash indicators
 */
static int
general_crash_check(const char* buf)
{
  char out[128] = {0};
  int ret = 0;

  /* Validate input */
  if (buf == NULL) {
    pr_error(stdout, "general_crash_check: buf is NULL");
    return 0;
  } /* if */

  if (_strfind(buf, "stack", 1)) {
    snprintf(out, sizeof(out), "@ Stack-related issue detected\n\t");
    error_print(out, buf);
    ret = 1;
  } /* if */

  if (_strfind(buf, "memory", 1)) {
    snprintf(out, sizeof(out), "@ Memory-related issue detected\n\t");
    error_print(out, buf);
    ret = 1;
  } /* if */

  if (_strfind(buf, "access violation", 1)) {
    snprintf(out, sizeof(out), "@ Access violation detected\n\t");
    error_print(out, buf);
    ret = 1;
  } /* if */

  if (_strfind(buf, "buffer overrun", 1) || _strfind(buf, "buffer overflow", 1)) {
    snprintf(out, sizeof(out), "@ Buffer overflow detected\n\t");
    error_print(out, buf);
    ret = 1;
  } /* if */

  if (_strfind(buf, "null pointer", 1)) {
    snprintf(out, sizeof(out), "@ Null pointer exception detected\n\t");
    error_print(out, buf);
    ret = 1;
  } /* if */

  return ret;
} /* general_crash_check */

/**
 * Handle out-of-bounds errors
 */
static void
outofbounds_check(const char* buf)
{
  char out[1024] = {0};
  int n = 0;
  size_t len = 0;

  /* Validate input */
  if (buf == NULL) {
    pr_error(stdout, "outofbounds_check: buf is NULL");
    return;
  } /* if */

  n = snprintf(out, sizeof(out), "@ out-of-bounds detected\n\t");
  len = (n < 0) ? 0 : (size_t)n;
  
  if (len > 0) {
    fwrite(out, 1, len, stdout);
    pr_color(stdout, LR_BLUE, "%s", buf);
    fflush(stdout);
  } /* if */

  /* Provide example of correct array handling */
  n = snprintf(out, sizeof(out),
    "  new array[3];\n"
    "  main() {\n"
    "  for (new i = 0; i < 4; i++) < potent 4 of 3\n"
    "            ^ sizeof(array)   for array[this] and array[this][]\n"
    "            ^ sizeof(array[]) for array[][this]\n"
    "            * instead of manual indexing..\n"
    "     array[i] = 0;\n"
    "  }\n");
  len = (n < 0) ? 0 : (size_t)n;
  
  if (len > 0) {
    fwrite(out, 1, len, stdout);
    fflush(stdout);
  } /* if */
} /* outofbounds_check */

/**
 * Handle critical errors
 */
static void
critical_check(const char* buf)
{
  char out[1024] = {0};
  int n = 0;
  size_t len = 0;

  /* Validate input */
  if (buf == NULL) {
    pr_error(stdout, "critical_check: buf is NULL");
    return;
  } /* if */

  n = snprintf(out, sizeof(out), "@ Critical message found\n\t");
  len = (n < 0) ? 0 : (size_t)n;
  
  if (len > 0) {
    fwrite(out, 1, len, stdout);
    pr_color(stdout, LR_BLUE, "%s", buf);
    fflush(stdout);
  } /* if */

  n = snprintf(out, sizeof(out),
    " * You need to ensure that the file name (.amx),\n"
    "   in your server.cfg under the parameter (gamemode0),\n"
    "   actually exists as a .amx file in the gamemodes/ folder.\n"
    " * If there's only a file with the corresponding name but it's only a single .pwn file,\n"
    "   you need to compile it.\n");
  len = (n < 0) ? 0 : (size_t)n;
  
  if (len > 0) {
    fwrite(out, 1, len, stdout);
    fflush(stdout);
  } /* if */
} /* critical_check */

/**
 * Handle warning messages
 */
static void
warning_check(const char* buf)
{
  char out[128] = {0};

  /* Validate input */
  if (buf == NULL) {
    pr_error(stdout, "warning_check: buf is NULL");
    return;
  } /* if */

  snprintf(out, sizeof(out), "@ Warning message found\n\t");
  error_print(out, buf);
} /* warning_check */

/**
 * Handle failure messages
 */
static void
failure_check(const char* buf)
{
  char out[1024] = {0};
  int n = 0;
  size_t len = 0;

  /* Validate input */
  if (buf == NULL) {
    pr_error(stdout, "failure_check: buf is NULL");
    return;
  } /* if */

  n = snprintf(out, sizeof(out), "@ Failure detected\n\t");
  len = (n < 0) ? 0 : (size_t)n;
  
  if (len > 0) {
    fwrite(out, 1, len, stdout);
    pr_color(stdout, LR_BLUE, "%s", buf);
    fflush(stdout);
  } /* if */

  n = snprintf(out, sizeof(out),
    " * Maybe the plugin failed to load? "
    " * You can try upgrading the failed plugin and, "
    " * if you're on Windows, make sure you have the Visual C++ Redistributable installed.\n\t");
  len = (n < 0) ? 0 : (size_t)n;
  
  if (len > 0) {
    fwrite(out, 1, len, stdout);
    fflush(stdout);
  } /* if */
} /* failure_check */

/**
 * Handle timeout messages
 */
static void
timeout_check(const char* buf)
{
  char out[128] = {0};

  /* Validate input */
  if (buf == NULL) {
    pr_error(stdout, "timeout_check: buf is NULL");
    return;
  } /* if */

  snprintf(out, sizeof(out), "@ Timeout detected\n\t");
  error_print(out, buf);
} /* timeout_check */

/**
 * Handle plugin-related messages
 */
static void
plugin_check(const char* buf)
{
  char out[1024] = {0};
  int n = 0;
  size_t len = 0;

  /* Validate input */
  if (buf == NULL) {
    pr_error(stdout, "plugin_check: buf is NULL");
    return;
  } /* if */

  if (_strfind(buf, "failed to load", 1) || _strfind(buf, "Failed.", 1)) {
    n = snprintf(out, sizeof(out), "@ Plugin load failure\n\t");
    len = (n < 0) ? 0 : (size_t)n;
    
    if (len > 0) {
      fwrite(out, 1, len, stdout);
      pr_color(stdout, LR_BLUE, "%s", buf);
      fflush(stdout);
    } /* if */

    n = snprintf(out, sizeof(out),
      " * If you need to reinstall a plugin that failed, you can use the command:\n"
      "\n"
      "   install user/repo:tags\n"
      "\n"
      " * Example:\n"
      "\n"
      "   install user/repo:tags\n"
      "\n"
      " * You can also recheck the username shown on the failed plugin using the command:\n"
      "\n"
      "   tracker username\n"
      "\n");
    len = (n < 0) ? 0 : (size_t)n;
    
    if (len > 0) {
      fwrite(out, 1, len, stdout);
      fflush(stdout);
    } /* if */
  } /* if */

  if (_strfind(buf, "unloaded", 1)) {
    n = snprintf(out, sizeof(out), "@ Plugin unloaded\n\t");
    len = (n < 0) ? 0 : (size_t)n;
    
    if (len > 0) {
      fwrite(out, 1, len, stdout);
      pr_color(stdout, LR_BLUE, "%s", buf);
      fflush(stdout);
    } /* if */

    n = snprintf(out, sizeof(out),
      " * LOADED (Active/In Use):\n"
      "   - Plugin is running, all features are available.\n"
      "   - Utilizing system memory and CPU (e.g., running background threads).\n"
      " * UNLOADED (Deactivated/Inactive):\n"
      "   - Plugin has been shut down and removed from memory.\n"
      "   - Features are no longer available; system resources (memory/CPU) are released.\n");
    len = (n < 0) ? 0 : (size_t)n;
    
    if (len > 0) {
      fwrite(out, 1, len, stdout);
      fflush(stdout);
    } /* if */
  } /* if */
} /* plugin_check */

/**
 * Handle database-related messages
 */
static void
database_check(const char* buf)
{
  char out[128] = {0};

  /* Validate input */
  if (buf == NULL) {
    pr_error(stdout, "database_check: buf is NULL");
    return;
  } /* if */

  if (_strfind(buf, "connection failed", 1) || _strfind(buf, "can't connect", 1)) {
    snprintf(out, sizeof(out), "@ Database connection failure\n\t");
    error_print(out, buf);
  } /* if */

  if (_strfind(buf, "error", 1) || _strfind(buf, "failed", 1)) {
    snprintf(out, sizeof(out), "@ Database error\n\t");
    error_print(out, buf);
  } /* if */
} /* database_check */

/**
 * Handle memory allocation errors
 */
static void
memory_check(const char* buf)
{
  char out[128] = {0};

  /* Validate input */
  if (buf == NULL) {
    pr_error(stdout, "memory_check: buf is NULL");
    return;
  } /* if */

  snprintf(out, sizeof(out), "@ Memory allocation failure\n\t");
  error_print(out, buf);
} /* memory_check */

/**
 * Handle memory function references
 */
static void
alloc_check(const char* buf)
{
  char out[128] = {0};

  /* Validate input */
  if (buf == NULL) {
    pr_error(stdout, "alloc_check: buf is NULL");
    return;
  } /* if */

  snprintf(out, sizeof(out), "@ Memory function referenced\n\t");
  error_print(out, buf);
} /* alloc_check */

/**
 * Handle info messages
 */
static void
info_check(const char* buf)
{
  char out[128] = {0};

  /* Validate input */
  if (buf == NULL) {
    pr_error(stdout, "info_check: buf is NULL");
    return;
  } /* if */

  snprintf(out, sizeof(out), "@ Info message found\n\t");
  error_print(out, buf);
} /* info_check */

/**
 * Detect SampVoice port from log
 */
static void
sampvoice_port_detect(const char* buf)
{
  int port = 0;

  /* Validate input */
  if (buf == NULL) {
    pr_error(stdout, "sampvoice_port_detect: buf is NULL");
    return;
  } /* if */

  if (!_strfind(buf, "voice server running on port", 1)) {
    return;
  } /* if */

  if (sscanf(buf, "%*[^v]voice server running on port %d", &port) != 1) {
    return;
  } /* if */

  rate_sampvoice_server++;
  
  if (sampvoice_port != NULL) {
    dog_free(sampvoice_port);
  } /* if */

  sampvoice_port = dog_malloc(16);
  if (sampvoice_port != NULL) {
    snprintf(sampvoice_port, 16, "%d", port);
    pr_info(stdout, "sampvoice_port_detect: detected port %d", port);
  } /* if */
} /* sampvoice_port_detect */

/**
 * Check SampVoice port configuration
 */
static void
sampvoice_port_check(void)
{
  FILE* fp = NULL;
  char buf[DOG_MAX_PATH] = {0};
  int cfg_port = 0;
  char cfg_port_str[16] = {0};

  if (rate_sampvoice_server == 0) {
    return;
  } /* if */

  if (path_access("server.cfg") != 1) {
    pr_info(stdout, "sampvoice_port_check: server.cfg not accessible");
    return;
  } /* if */

  if (sampvoice_port == NULL) {
    pr_info(stdout, "sampvoice_port_check: sampvoice_port is NULL");
    return;
  } /* if */

  fp = fopen("server.cfg", "rb");
  if (fp == NULL) {
    pr_error(stdout, "sampvoice_port_check: failed to open server.cfg");
    return;
  } /* if */

  cfg_port = 0;
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if (_strfind(buf, "sv_port", 1)) {
      if (sscanf(buf, "sv_port %d", &cfg_port) == 1) {
        break;
      } /* if */
    } /* if */
  } /* while */
  
  fclose(fp);

  if (cfg_port == 0) {
    pr_info(stdout, "sampvoice_port_check: no sv_port found in server.cfg");
    return;
  } /* if */

  snprintf(cfg_port_str, sizeof(cfg_port_str), "%d", cfg_port);

  if (strcmp(cfg_port_str, sampvoice_port) != 0) {
    char out[1024] = {0};
    int n = 0;
    size_t len = 0;

    n = snprintf(out, sizeof(out), "@ SampVoice Port Mismatch\n\t");
    len = (n < 0) ? 0 : (size_t)n;
    
    if (len > 0) {
      fwrite(out, 1, len, stdout);
    } /* if */

    n = snprintf(out, sizeof(out),
      " * server.cfg: %s, Log: %s\n"
      " * We have detected a mismatch between the sampvoice port in server.cfg\n"
      " * and the one loaded in the server log!\n"
      " ** Please make sure you have correctly set the port in server.cfg.\n",
      cfg_port_str, sampvoice_port);
    len = (n < 0) ? 0 : (size_t)n;
    
    if (len > 0) {
      fwrite(out, 1, len, stdout);
      fflush(stdout);
    } /* if */
    
    pr_info(stdout, "sampvoice_port_check: port mismatch - cfg: %s, log: %s", 
         cfg_port_str, sampvoice_port);
  } /* if */
} /* sampvoice_port_check */

/**
 * Check RCON password issues
 */
static void
rcon_password_check(void)
{
  char* input = NULL;
  char out[256] = {0};
  int n = 0;
  size_t len = 0;

  if (server_rcon_pass == 0) {
    return;
  } /* if */

  n = snprintf(out, sizeof(out),
    "@ Rcon Pass Error found\n\t* Error: Your password must be changed from the default password..\n");
  len = (n < 0) ? 0 : (size_t)n;
  
  if (len > 0) {
    fwrite(out, 1, len, stdout);
    fflush(stdout);
  } /* if */

  input = readline("Tree-fix? (Y/n): ");
  if (input != NULL) {
    if (input[0] == '\0' || input[0] == 'Y' || input[0] == 'y') {
      rcon_password_fix();
    } /* if */
    dog_free(input);
  } /* if */
} /* rcon_password_check */

/**
 * Fix default RCON password
 */
static void
rcon_password_fix(void)
{
  FILE* fp = NULL;
  char* content = NULL;
  char* new_content = NULL;
  char* pos = NULL;
  long size = 0;
  char rand_str[32] = {0};
  uint32_t crc = 0;
  char out[1024] = {0};
  int n = 0;
  size_t len = 0;

  if (path_access("server.cfg") != 1) {
    n = snprintf(out, sizeof(out), "server.cfg not accessible\n");
    len = (n < 0) ? 0 : (size_t)n;
    
    if (len > 0) {
      fwrite(out, 1, len, stdout);
    } /* if */
    return;
  } /* if */

  fp = fopen("server.cfg", "rb");
  if (fp == NULL) {
    pr_error(stdout, "rcon_password_fix: failed to open server.cfg");
    return;
  } /* if */

  fseek(fp, 0, SEEK_END);
  size = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  content = dog_malloc(size + 1);
  if (content == NULL) {
    pr_error(stdout, "rcon_password_fix: memory allocation failed");
    fclose(fp);
    return;
  } /* if */

  int r = fread(content, 1, size, fp);
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
    
    if (len > 0) {
      fwrite(out, 1, len, stdout);
    } /* if */
    
    dog_free(content);
    return;
  } /* if */

  /* Generate random password */
  srand((unsigned int)time(NULL) ^ (unsigned int)rand());
  snprintf(rand_str, sizeof(rand_str), "%d", rand() % 10000000);
  crc = crypto_generate_crc32(rand_str, strlen(rand_str));

  new_content = dog_malloc(size + 32);
  if (new_content == NULL) {
    pr_error(stdout, "rcon_password_fix: memory allocation for new_content failed");
    dog_free(content);
    return;
  } /* if */

  /* Replace password in config */
  strncpy(new_content, content, pos - content);
  new_content[pos - content] = '\0';

  snprintf(rand_str, sizeof(rand_str), "rcon_password %08X", crc);
  strcat(new_content, rand_str);
  strcat(new_content, pos + strlen("rcon_password changeme"));

  fp = fopen("server.cfg", "wb");
  if (fp != NULL) {
    fwrite(new_content, 1, strlen(new_content), fp);
    fclose(fp);
    
    n = snprintf(out, sizeof(out), "done! * server.cfg - rcon_password from changeme to %08X.\n", crc);
    len = (n < 0) ? 0 : (size_t)n;
    
    if (len > 0) {
      fwrite(out, 1, len, stdout);
      fflush(stdout);
    } /* if */
    
    pr_info(stdout, "rcon_password_fix: updated rcon_password to %08X", crc);
  } else {
    n = snprintf(out, sizeof(out), "Error: Cannot write to server.cfg\n");
    len = (n < 0) ? 0 : (size_t)n;
    
    if (len > 0) {
      fwrite(out, 1, len, stdout);
      fflush(stdout);
    } /* if */
    
    pr_error(stdout, "rcon_password_fix: failed to write to server.cfg");
  } /* if */

  dog_free(new_content);
  dog_free(content);
} /* rcon_password_fix */
