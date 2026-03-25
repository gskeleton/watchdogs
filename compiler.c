#include  "utils.h"
#include  "units.h"
#include  "library.h"
#include  "crypto.h"
#include  "cause.h"
#include  "debug.h"
#include  "process.h"
#include  "compiler.h"

static         io_compilers  dog_pc_sys;
io_compilers   all_pc_field;
io_compilers* pctx = &all_pc_field;

/* Timing variables for compilation duration */
struct timespec pre_start = { 0 }, post_end = { 0 };
static double  elapsed_time;
static FILE*   fp = NULL;
_Bool           pc_is_error = false;
static int     pc_retry_state = PC_RETRY_STATE_NONE;
_Bool           pc_input_info = false;
_Bool           pc_debug_options = false;
static _Bool    pc_time_issue = false;
char*          pc_full_includes = NULL;
static _Bool    init_applied_opt = false;
static char    pc_temp[DOG_PATH_MAX + 28] = { 0 };
static char    pbuf[DOG_MAX_PATH * 2];
static char    parsing[DOG_PATH_MAX] = { 0 };
char           pc_include_path[DOG_PATH_MAX] = { 0 };
static char*   server_path = NULL;
static char*   pc_back_slash = NULL;
static char*   pc_last_slash = NULL;
static char*   size_include_extra = NULL;
static char*   procure_string_pos = NULL;
_Bool           spawn_succeeded = false;

static void pc_show_tip(void) {
  static const char* tip_options =
  LR_BCYAN
  " o [--watchdogs/--detailed/-w] * Enable detailed watchdog output\n"
  LR_BCYAN
  " o [--debug/-d]                * Enable debugger options\n"
  LR_BCYAN
  " o [--prolix/-p]               * Enable verbose compilation\n"
  LR_BCYAN
  " o [--assembler/-a]            * Show assembler output\n"
  LR_BCYAN
  " o [--compact/-m]              * Use compact encoding\n"
  LR_BCYAN
  " o [--compat/-c]               * Active cross path separator\n"
  LR_BCYAN
  " o [--fast/-f]                 * Enable faster compilation mode\n"
  LR_BCYAN
  " o [--clean/-n]                * Enable safe mode or clean mode\n";
  
  /* Validate tip_options before writing */
  if (tip_options != NULL) {
    fwrite(tip_options, 1, strlen(tip_options), stdout);
  } /* if */
  
  print_restore_color();
  return;
} /* pc_show_tip */

static int configure_retry_stat(void) {
  int ret = 1;
  pbuf[0] = '\0';
  
  /* Configure based on retry state */
  switch (pc_retry_state) {
  case PC_RETRY_STATE_FIRST: {
    pctx->flag_compat = true;
    pctx->flag_fast = true;
    pctx->flag_detailed = true;

    static const char* SampPlayers = "MAX_PLAYERS=200";
    static const char* SampVehicles = "MAX_VEHICLES=1000";
    static const char* SampActors = "MAX_ACTORS=100";
    static const char* SampObjects = "MAX_OBJECTS=1000";
    
    (void)snprintf(pbuf, sizeof(pbuf), "%s %s %s %s %s",
      dogconfig.dog_toml_full_opt ? dogconfig.dog_toml_full_opt : "",
      SampPlayers, SampVehicles, SampActors, SampObjects);
    
    if (dogconfig.dog_toml_full_opt != NULL) {
      dog_free(dogconfig.dog_toml_full_opt);
    } /* if */
    
    dogconfig.dog_toml_full_opt = strdup(pbuf);
    
    ret = 0;
    break;
  } /* case PC_RETRY_STATE_FIRST */
  
  case PC_RETRY_STATE_FINAL: {
    static const char* SampPlayers = "MAX_PLAYERS=100";
    static const char* SampVehicles = "MAX_VEHICLES=1000";
    static const char* SampActors = "MAX_ACTORS=100";
    static const char* SampObjects = "MAX_OBJECTS=1000";
    
    (void)snprintf(pbuf, sizeof(pbuf), "%s %s %s %s",
      SampPlayers, SampVehicles, SampActors, SampObjects);
    
    if (dogconfig.dog_toml_full_opt != NULL) {
      dog_free(dogconfig.dog_toml_full_opt);
    } /* if */
    
    dogconfig.dog_toml_full_opt = strdup(pbuf);

    return 0;
  } /* case PC_RETRY_STATE_FINAL */
  
  default:
    break;
  } /* switch */
  
  /* Handle timeout issues with reduced limits */
  if (0 != pc_time_issue) {
    pctx->flag_compat = true;
    pctx->flag_fast = true;
    pctx->flag_detailed = true;

    static const char* SampPlayers = "MAX_PLAYERS=50";
    static const char* SampVehicles = "MAX_VEHICLES=100";
    static const char* SampActors = "MAX_ACTORS=20";
    static const char* SampObjects = "MAX_OBJECTS=1000";
    
    (void)snprintf(pbuf, sizeof(pbuf), "%s %s %s %s %s",
      dogconfig.dog_toml_full_opt ? dogconfig.dog_toml_full_opt : "",
      SampPlayers, SampVehicles, SampActors, SampObjects);
    
    if (dogconfig.dog_toml_full_opt != NULL) {
      dog_free(dogconfig.dog_toml_full_opt);
    } /* if */
    
    dogconfig.dog_toml_full_opt = strdup(pbuf);
    
    ret = 0;
  } /* if */
  
  return ret;
} /* configure_retry_stat */

static void collect_option_bitmask(void) {

  unsigned int __set_bit = 0;
  size_t  len = 0, extra_len = 0;
  char    *pos = NULL, *ptr = NULL, *options = NULL, *new_options = NULL;
  int     i = 0;

  /* Clear buffer */
  pbuf[0] = '\0';
  ptr = pbuf;

  /* Show tip if no flags specified */
  if (!(pctx->flag_detailed || pctx->flag_assembly || pctx->flag_compat ||
    pctx->flag_compact    || pctx->flag_prolix   || pctx->flag_debug  ||
    pctx->flag_clean      || pctx->flag_fast))
  {
    static _Bool notice = false;
    
    if (!notice) {
      notice = true;
      (void) putchar('\n');
      pc_show_tip();
      (void) putchar('\n');
    } /* if */
  } /* if */

  /* initialization of state */
  /* already ;| */
  if (init_applied_opt == 1)
    return;
  /* true */
  init_applied_opt = 1;

  /* applying a flag */
  int fd = 0;
  int fa = 0;
  int fc = 0;
  int fp = 0;
  int fm = 0;
  int ff = 0;

  if (pctx->flag_debug)
    fd = 1;
  if (pctx->flag_assembly)
    fa = 1;
  if (pctx->flag_compat)
    fc = 1;
  if (pctx->flag_prolix)
    fp = 1;
  if (pctx->flag_compact)
    fm = 1;
  if (pctx->flag_fast)
    ff = 1;

  if (1 == fd)
    __set_bit |= BIT_FLAG_DEBUG;
  if (1 == fa)
    __set_bit |= BIT_FLAG_ASSEMBLER;
  if (1 == fc)
    __set_bit |= BIT_FLAG_COMPAT;
  if (1 == fp)
    __set_bit |= BIT_FLAG_PROLIX;
  if (1 == fm)
    __set_bit |= BIT_FLAG_COMPACT;
  if (1 == ff)
    __set_bit |= BIT_FLAG_TIME;

  /* Handle debug flags */
  if (!pctx->flag_debug) {
    goto next;
  } /* if */

next:
  /* Compiler option flags mapping */
  static const CompilerOption object_opt[] = {
    {
    BIT_FLAG_DEBUG,     " -d:2 ", 5
    },
    {
    BIT_FLAG_ASSEMBLER, " -a ",   4
    },
    {
    BIT_FLAG_COMPAT,    " -Z:+ ", 5
    },
    {
    BIT_FLAG_PROLIX,    " -v:2 ", 5
    },
    {
    BIT_FLAG_COMPACT,   " -C:+ ", 5
    },
    {
    BIT_FLAG_TIME,      " -d:3 ", 5
    },
    { 0, NULL, 0 }
  };

  /* Append corresponding option strings */
  for (int i = 0; object_opt[i].option; i++) {
    if (!(__set_bit & object_opt[i].flag)) {
      continue;
    } /* if */

    /* Copy option to buffer */
    (void)memcpy(ptr, object_opt[i].option,
      object_opt[i].len);
    ptr += object_opt[i].len;
  } /* for */

  *ptr = '\0';

  /* Append collected flags to options */
  if (strlen(pbuf) > 0) {
    init_applied_opt = !init_applied_opt;

    len = strlen(dogconfig.dog_toml_full_opt);
    extra_len = strlen(pbuf);

    new_options = dog_realloc(dogconfig.dog_toml_full_opt,
                  len + extra_len + 1);

    if (!new_options) {
      pr_error(stdout,
        "Memory allocation failed");
      minimal_debugging();
      return;
    } /* if */

    dogconfig.dog_toml_full_opt = new_options;
    (void)strcat(dogconfig.dog_toml_full_opt, pbuf);
  } /* if */
} /* collect_option_bitmask */

static void normalize_path(char* path) {
  /* Validate input */
  if (path == NULL) {
    pr_error(stdout, "normalize_path: path is NULL");
    return;
  } /* if */
  
  if (path[0] == '\0') {
    pr_info(stdout, "normalize_path: path is empty");
    return;
  } /* if */

  char* p = NULL;
  
  #ifdef DOG_LINUX
  /* Convert Windows backslashes to POSIX forward slashes */
  path_sep_to_posix(path);
  #else
  /* Convert POSIX forward slashes to Windows backslashes */
  path_sep_to_win32(path);
  #endif

  return;
} /* normalize_path */

static void configure_parent_dir(char* path) {
  /* Validate input */
  if (path == NULL) {
    pr_error(stdout, "configure_parent_dir: path is NULL");
    return;
  } /* if */
  
  if (strlen(path) == 0) {
    pr_info(stdout, "configure_parent_dir: path is empty");
    return;
  } /* if */

  /* Check for parent directory references */
  if (strstr(path, "../") == NULL) {
    (void)snprintf(pc_include_path, sizeof(pc_include_path), " ");
    return;
  } /* if */

  _Bool  parent_path_found = false;
  char* tmp = NULL;
  size_t  i = 0, wpos = 0;

  tmp = strdup(path);
  if (tmp == NULL) {
    pr_error(stdout, "configure_parent_dir: strdup failed for path: %s", path);
    return;
  } /* if */

  /* Extract parent directory path */
  for (i = 0; tmp[i] != '\0'; i++) {
    /* Look for "../" pattern */
    if (strncmp(tmp + i, "../", 3) != 0) {
      continue;
    } /* if */

    parent_path_found = true;
    i += 3;

    /* Extract the path after "../" */
    while (tmp[i] != '\0'
      && tmp[i] != ' '
      && tmp[i] != '"') {
      
      if (wpos < sizeof(parsing) - 1) {
        parsing[wpos++] = tmp[i++];
      } else {
        pr_warning(stdout, "configure_parent_dir: parsing buffer overflow");
        break;
      } /* if */
    } /* while */

    /* Find last path separator */
    if (wpos > 0) {
      size_t  last_sep = 0;
      size_t  k;
      for (k = 0; k < wpos; k++) {
        if (parsing[k] == _PATH_CHR_SEP_POSIX ||
          parsing[k] == _PATH_CHR_SEP_WIN32)
          last_sep = k + 1;
      } /* for */
      
      if (last_sep > 0) {
        wpos = last_sep;
      } /* if */
    } /* if */

    break;
  } /* for */

  free(tmp);

  /* Handle case where no parent path was found */
  if (!parent_path_found && wpos == 0) {
    strlcpy(parsing, "../", sizeof(parsing));
    goto done;
  } /* if */

  /* Add ../ prefix */
  if (wpos + 3 < sizeof(parsing)) {
    #ifdef DOG_LINUX
    (void) bcopy(parsing, parsing + 3, wpos);
    #else
    (void) memmove(parsing, parsing + 3, wpos);
    #endif
    (void) memcpy(parsing, "../", 3);
    wpos += 3;
    parsing[wpos] = '\0';
  } else {
    ;
  } /* if */

  /* Ensure trailing separator */
  if (wpos > 0 && parsing[wpos - 1] != _PATH_CHR_SEP_POSIX
    && parsing[wpos - 1] != _PATH_CHR_SEP_WIN32) {
    
    if (wpos < sizeof(parsing) - 1) {
      parsing[wpos++] = '/';
      parsing[wpos] = '\0';
    } else {
      ;
    } /* if */
  } /* if */

done:
  /* Clear temp buffer */
  pc_temp[0] = '\0';
  (void)strcpy(pc_temp, parsing);

  /* Remove gamemodes suffix if present */
  if (_strfind(pc_temp, "gamemodes/", true) != false ||
    _strfind(pc_temp, "gamemodes\\", true) != false)
  {
    char* p = strstr(pc_temp, "gamemodes/");
    char* p2 = strstr(pc_temp, "gamemodes\\");
    
    if (p) {
      *p = '\0';
    } /* if */
    
    if (p2) {
      *p2 = '\0';
    } /* if */
  } /* if */

  /* Build include path string */
  if (!strstr(dogconfig.dog_toml_full_opt, "gamemodes/") &&
    !strstr(dogconfig.dog_toml_full_opt, "pawno/include/") &&
    !strstr(dogconfig.dog_toml_full_opt, "qawno/include/"))
  {
    /* Add multiple include paths */
    pbuf[0] = '\0';
    (void)snprintf(pbuf, sizeof(pbuf),
      "-i" "=\"%s\" "
      "-i" "=\"%s" "gamemodes/\" "
      "-i" "=\"%s" "pawno/include/\" "
      "-i" "=\"%s" "qawno/include/\" ",
      pc_temp, pc_temp, pc_temp, pc_temp);
  } else {
    /* Add single include path */
    pbuf[0] = '\0';
    (void)snprintf(pbuf, sizeof(pbuf),
      "-i" "=\"%s\"", pc_temp);
  } /* if */

  /* Copy to global include path */
  (void)strncpy(pc_include_path, pbuf, sizeof(pc_include_path) - 1);
  pc_include_path[sizeof(pc_include_path) - 1] = '\0';

  return;
} /* configure_parent_dir */

static void compiler_state_init(void) {
  
  /* Create .watchdogs directory if it doesn't exist */
  if (dir_exists(".watchdogs") == 0) {
    if (MKDIR(".watchdogs") != 0) {
      pr_warning(stdout, "compiler_state_init: failed to create .watchdogs directory");
    } else {
      pr_info(stdout, "compiler_state_init: created .watchdogs directory");
    } /* if */
  } /* if */

  print_restore_color();

  _sef_restore();

  /* Reset timing and state */
  pre_start = (struct timespec){ 0 };
  post_end = (struct timespec){ 0 };

  spawn_succeeded = false;
  pc_retry_state = PC_RETRY_STATE_NONE;

  fp = NULL;
  pc_last_slash = NULL;
  pc_back_slash = NULL;
  size_include_extra = NULL;
  procure_string_pos = NULL;

  /* Reset all flags */
  pctx->output = NULL;
  pctx->flag_detailed = false;
  pctx->flag_assembly = false;
  pctx->flag_compat = false;
  pctx->flag_compact = false;
  pctx->flag_prolix = false;
  pctx->flag_debug = false;
  pctx->flag_clean = false;
  pctx->flag_fast = false;

  init_applied_opt = false;

  /* Clear buffers */
  if (pctx->direct_path != NULL) {
    pctx->direct_path[0] = '\0';
  } /* if */
  
  if (pctx->file_name_buf != NULL) {
    pctx->file_name_buf[0] = '\0';
  } /* if */
  
  if (pctx->input_path != NULL) {
    pctx->input_path[0] = '\0';
  } /* if */
  
  if (pctx->temp_path != NULL) {
    pctx->temp_path[0] = '\0';
  } /* if */
  
  parsing[0] = '\0';
  pc_include_path[0] = '\0';
  pc_temp[0] = '\0';
  pbuf[0] = '\0';
  
} /* compiler_state_init */

int
dog_exec_compiler(const char* __UNUSED__  args, char* compile_args_val,
  const char* second_arg, const char* four_arg, const char* five_arg,
  const char* six_arg, const char* seven_arg, const char* eight_arg,
  const char* nine_arg, const char* ten_arg)
{
  size_t         fet_sef_ent = 0;
  int            len = 0;
  int            ret = 1;

  /* setenv for libpawnc.so (GNU/Linux) */
  configure_libpcc();
  
  /* Calculate SEF entries count */
  fet_sef_ent = sizeof(dogconfig.dog_sef_found_list) /
    sizeof(dogconfig.dog_sef_found_list[0]);

  /* Set OS-specific defines based on operating system */
  pbuf[0] = '\0';
  
  #ifdef DOG_WINDOWS // Windows
    (void)snprintf(pbuf, sizeof(pbuf),
      "%s WINDOWS=1 LINUX=0 ANDROID=0",
      dogconfig.dog_toml_full_opt ? dogconfig.dog_toml_full_opt : "");
  #else
  #ifdef DOG_ANDROID // Android
    (void)snprintf(pbuf, sizeof(pbuf),
      "%s WINDOWS=0 LINUX=0 ANDROID=1",
      dogconfig.dog_toml_full_opt ? dogconfig.dog_toml_full_opt : "");
  #else // Linux
    (void)snprintf(pbuf, sizeof(pbuf),
      "%s WINDOWS=0 LINUX=1 ANDROID=0",
      dogconfig.dog_toml_full_opt ? dogconfig.dog_toml_full_opt : "");
  #endif
  #endif
  
  /* Check for Windows Subsystem Linux (WSL) */
  if ((getenv("WSL_INTEROP") || getenv("WSL_DISTRO_NAME")) &&
    strcmp(dogconfig.dog_toml_os_type, OSYS_WINDOWS) == 0)
  {
    pr_info(stdout, "dog_exec_compiler: WSL detected, setting Windows mode");
    (void)snprintf(pbuf, sizeof(pbuf),
      "%s WINDOWS=1 LINUX=0 ANDROID=0",
      dogconfig.dog_toml_full_opt ? dogconfig.dog_toml_full_opt : "");
  } /* if */
  
  /* Update full options */
  if (dogconfig.dog_toml_full_opt != NULL) {
    dog_free(dogconfig.dog_toml_full_opt);
  } /* if */
  
  dogconfig.dog_toml_full_opt = strdup(pbuf);
  if (dogconfig.dog_toml_full_opt == NULL) {
    pr_error(stdout, "dog_exec_compiler: memory allocation failed for OS defines");
    return -1;
  } /* if */

  /* Handle NULL compile_args_val */
  if (compile_args_val == NULL) {
    compile_args_val = "";
  } /* if */

  /* Initialize compiler state */
  compiler_state_init();

  /* Build argument buffer */
  const char* argv_buf[] = {
    second_arg, four_arg, five_arg,
    six_arg, seven_arg, eight_arg, nine_arg, ten_arg
  };

  /* Map command line flags to context flags */
  OptionMap flag_map[] = {
    {"--detailed", "-w", &pctx->flag_detailed},
    {"--watchdogs", "-w", &pctx->flag_detailed},
    {"--debug", "-d", &pctx->flag_debug},
    {"--clean", "-n", &pctx->flag_clean},
    {"--assembler", "-a", &pctx->flag_assembly},
    {"--compat", "-c", &pctx->flag_compat},
    {"--compact", "-m", &pctx->flag_compact},
    {"--prolix", "-p", &pctx->flag_prolix},
    {"--fast", "-f", &pctx->flag_fast},
    {NULL, NULL, NULL}
  };

  /* Process command line arguments */
  for (int i = 0; i < 8 && argv_buf[i]; ++i) {
    const char* argv = argv_buf[i];
    
    if (argv == NULL) {
      pr_info(stdout, "dog_exec_compiler: argv_buf[%d] is NULL, skipping", i);
      continue;
    } /* if */
    
    if (*argv != '-') {
      pr_info(stdout, "dog_exec_compiler: argv[%d]='%s' not an option, skipping", i, argv);
      continue;
    } /* if */

    /* Match against known options */
    OptionMap* entry;
    for (entry = flag_map; entry->full_name; ++entry) {
      if (strcmp(argv, entry->full_name) == 0
        || strcmp(argv, entry->short_name) == 0)
      {
        *entry->flag_ptr = 1;
        break;
      } /* if */
    } /* for */
    
    /* Check if option was recognized */
    if (entry->full_name == NULL) {
      pr_info(stdout, "dog_exec_compiler: unknown option: %s", argv);
    } /* if */
  } /* for */

  /* Clean mode: clear all options */
  if (false != pctx->flag_clean)
  {
    pbuf[0] = '\0';
    (void)snprintf(pbuf, sizeof(pbuf), " ");
    
    if (dogconfig.dog_toml_full_opt != NULL) {
      dog_free(dogconfig.dog_toml_full_opt);
    } /* if */
    
    dogconfig.dog_toml_full_opt = strdup(pbuf);
    if (dogconfig.dog_toml_full_opt == NULL) {
      pr_error(stdout, "dog_exec_compiler: memory allocation failed for clean mode");
      return -1;
    } /* if */

    goto _pc_input_info;
  } /* if */

  /* Configure retry state */
  int _ret = configure_retry_stat();
  if (!_ret) {
    goto _pc_input_info;
  } /* if */

  /* Fast mode implies compact encoding */
  if (false != pctx->flag_fast) {
    pctx->flag_compact = true;
  } /* if */

_pc_retry_state:
  collect_option_bitmask();

_pc_input_info:
  if (pctx->flag_detailed) {
    pc_input_info = true;
  } /* if */
  
#if defined(_DBG_PRINT)
  pc_input_info = true;
#endif

  /* Skip parent directory configuration if no compile args */
  if (compile_args_val[0] == '\0') {
    goto skip_parent;
  } /* if */

  configure_parent_dir(compile_args_val);

skip_parent:
  /* Handle interactive file selection */
  if (*compile_args_val == '\0'
    || (compile_args_val[0] == '.'
      && compile_args_val[1] == '\0')) {
    if (compile_args_val[0] != '.') {
      fputs(LR_BYELLOW
        "          [COMPILER TARGET]\n", stdout);
      print_restore_color();
      puts(" -----------------------------");
      
      /* Clear buffer */
      pbuf[0] = '\0';
      
      /* Display prompt message */
      len = snprintf(pbuf, sizeof(pbuf),
        "  |- * You run the compiler command "
        "without any args: compile\n"
        "  |- * Do you want to compile for "
        LR_GREEN "%s " LR_DEFAULT
        "(enter), \n"
        "  |- * or do you want to compile for something else?\n",
        dogconfig.dog_toml_serv_input ? dogconfig.dog_toml_serv_input : "default");
      
      if (len > 0 && len < (int)sizeof(pbuf)) {
        fwrite(pbuf, 1, len, stdout);
        fflush(stdout);
      } /* if */
      goto manual_configure;
    } else {
      goto answer_done;
    } /* if */

    static _Bool listing_shown = false;
    
  manual_configure:
    /* Show file listing for manual selection */
    if (listing_shown) {
      goto input_path;
    } /* if */

    listing_shown = true;
    int tree_ret = -1;
    tree_ret = system("tree > /dev/null 2>&1");
    
    if (!tree_ret) {
      if (path_access(ANDROID_SHARED_DOWNLOADS_PATH) == 1) {
        if (system("tree -P \"*.p\" -P \"*.pawn\" -P \"*.pwn\" "
          ANDROID_SHARED_DOWNLOADS_PATH) == -1)
        {
          perror("system");
        }
      } else {
        if (system("tree -P \"*.p\" -P \"*.pawn\" -P \"*.pwn\" .") == -1) {
          perror("system");
        }
      } /* if */
    } else {
    #ifdef DOG_LINUX
      if (path_exists(ANDROID_SHARED_DOWNLOADS_PATH) == 1) {
        if (system("ls " ANDROID_SHARED_DOWNLOADS_PATH  " -R") == -1) {
          perror("system");
        }
      } else {
        if (system("ls . -R") == -1) {
          perror("system");
        }
      } /* if */
    #else
      if (system("dir . -s") == -1) {
        perror("system");
      }
    #endif
    } /* if */
    
  input_path:
    printf(
      " * Input examples such as:\n   bare.pwn main.pwn server.pwn\n"
      "  default: %s\n",
      dogconfig.dog_toml_serv_input ? dogconfig.dog_toml_serv_input : "none"
    );
    print_restore_color();
    fputs(LR_CYAN ">"
      LR_DEFAULT, stdout);
    fflush(stdout);
    
    char* pc_target = NULL;
    pc_target = readline(" ");
    
    if (pc_target != NULL && strlen(pc_target) > 0) {
      if (dogconfig.dog_toml_serv_input != NULL) {
        dog_free(dogconfig.dog_toml_serv_input);
      } /* if */
      
      if (path_access(pc_target) == 1) {
        dogconfig.dog_toml_serv_input = strdup(pc_target);
        goto pc_target_done;
      } /* if */
      
      if (_strfind(pc_target, "gamemodes", true) == true) {
        dogconfig.dog_toml_serv_input = strdup(pc_target);
      } else {
        pbuf[0] = '\0';
        (void)snprintf(pbuf, sizeof(pbuf),
          "gamemodes/%s", pc_target);
        dogconfig.dog_toml_serv_input = strdup(pbuf);
      } /* if */
    } /* if */
    
  pc_target_done:
    if (pc_target != NULL) {
      free(pc_target);
      pc_target = NULL;
    } /* if */
    
  answer_done:
    /* Build output filename */
    if (dogconfig.dog_toml_serv_input == NULL) {
      pr_error(stdout, "dog_exec_compiler: no input file selected");
      goto pc_end;
    } /* if */
    
    char* copy_input = strdup(dogconfig.dog_toml_serv_input);
    if (copy_input == NULL) {
      pr_error(stdout, "dog_exec_compiler: memory allocation failed for copy_input");
      goto pc_end;
    } /* if */
    
    char* ext = strrchr(copy_input, '.');
    if (ext) {
      *ext = '\0';
    } /* if */
    
    (void)snprintf(pbuf, MAX_SEF_PATH_SIZE + 28,
      "%s.amx", copy_input);
    
    if (dogconfig.dog_toml_serv_output != NULL) {
      dog_free(dogconfig.dog_toml_serv_output);
    } /* if */
    
    dogconfig.dog_toml_serv_output = strdup(pbuf);
    if (dogconfig.dog_toml_serv_output == NULL) {
      pr_error(stdout, "dog_exec_compiler: memory allocation failed for output");
      free(copy_input);
      goto pc_end;
    } /* if */
    
    free(copy_input);

    compile_args_val = dogconfig.dog_toml_serv_input;
    
    /* Normalize path */
    normalize_path(compile_args_val);
    
    /* Check if input file exists */
    if (path_exists(compile_args_val) == 0) {
      pbuf[0] = '\0';
      len = snprintf(pbuf, sizeof(pbuf),
        "Cannot locate input: " LR_CYAN
        "%s" LR_DEFAULT
        " - No such file or directory\n",
        compile_args_val);
      
      if (len > 0 && len < (int)sizeof(pbuf)) {
        fwrite(pbuf, 1, len, stdout);
        fflush(stdout);
      } /* if */
      
      goto pc_end;
    } /* if */

    configure_parent_dir(compile_args_val);

    /* Execute compiler */
    int _process = dog_exec_compiler_tasks(
      dogconfig.dog_pawncc_path,
      dogconfig.dog_toml_serv_input,
      dogconfig.dog_toml_serv_output);
    
    if (_process != 0) {
      pr_error(stdout, "dog_exec_compiler: compiler task failed with code: %d", _process);
      goto pc_end;
    } /* if */

    /* Process compiler output */
    if (path_exists(".watchdogs/compiler.log")) {
      (void)putchar('\n');
      
      char* ca = NULL;
      ca = dogconfig.dog_toml_serv_output;
      
      _Bool cb = 0;
      if (pc_debug_options) {
        cb = 1;
      } /* if */
      
      if (pctx->flag_detailed) {
        cause_pc_expl(
          ".watchdogs/compiler.log",
          ca, cb);
        print_restore_color();
        goto pc_done;
      } /* if */

      if (spawn_succeeded == false) {
        print_file(".watchdogs/compiler.log");
      } /* if */
    } /* if */
    
  pc_done:
    /* Check for compilation errors */
    fp = fopen(".watchdogs/compiler.log", "r");
    if (fp != NULL) {
      _Bool has_err = false;
      
      while (fgets(pbuf, sizeof(pbuf), fp)) {
        if (_strfind(pbuf, "error", true)) {
          has_err = true;
          break;
        } /* if */
      } /* while */
      
      fclose(fp);
      fp = NULL;
      
      if (has_err) {
        if (dogconfig.dog_toml_serv_output != NULL &&
          path_access(dogconfig.dog_toml_serv_output))
        {
          remove(dogconfig.dog_toml_serv_output);
        } /* if */
        pc_is_error = true;
      } else {
        pc_is_error = false;
      } /* if */
    } else {
      pr_error(stdout,
        "Failed to open .watchdogs/compiler.log");
      minimal_debugging();
    } /* if */

    /* Calculate and display compilation time */
    elapsed_time = ((double)(post_end.tv_sec - pre_start.tv_sec)) +
             ((double)(post_end.tv_nsec - pre_start.tv_nsec)) / 1e9;

    (void)putchar('\n');

    if (!pc_is_error) {
      puts("** Completed Tasks.\n");
    } /* if */
    
    fputs(LR_YELLOW " -----------------------------\n" LR_DEFAULT, stdout);

    pr_color(stdout, LR_CYAN,
      " <C> (compile-time) Complete At %.3fs (%.0f ms)\n",
      elapsed_time,
      elapsed_time * 1000.0);
    
    if (elapsed_time > 300) {
      pr_info(stdout, "dog_exec_compiler: compilation took >300s, checking timeout");
      goto _print_time;
    } /* if */
  }
  else {
    /* Validate file extension */
    if (_strfind(compile_args_val, ".pwn", true) == false &&
      _strfind(compile_args_val, ".pawn", true) == false &&
      _strfind(compile_args_val, ".p", true) == false)
    {
      pr_warning(stdout,
        "The compiler only accepts '.p' '.pawn' and '.pwn' files.");
      goto pc_end;
    } /* if */

    /* Parse path components */
    (void)strncpy(pctx->temp_path,
      compile_args_val,
      sizeof(pctx->temp_path) - 1);
    pctx->temp_path[sizeof(pctx->temp_path) - 1] = '\0';

    pc_last_slash = strrchr(pctx->temp_path, _PATH_CHR_SEP_POSIX);
    pc_back_slash = strrchr(pctx->temp_path, _PATH_CHR_SEP_WIN32);

    if (pc_back_slash && (!pc_last_slash || pc_back_slash > pc_last_slash))
    {
      pc_last_slash = pc_back_slash;
    } /* if */

    if (pc_last_slash) {
      /* Extract directory and filename */
      size_t pc_dir_len = (size_t)(pc_last_slash - pctx->temp_path);

      if (pc_dir_len >= sizeof(pctx->direct_path)) {
        pc_dir_len = sizeof(pctx->direct_path) - 1;
      } /* if */

      (void)memcpy(pctx->direct_path, pctx->temp_path, pc_dir_len);
      pctx->direct_path[pc_dir_len] = '\0';

      const char* pc_filename_start = pc_last_slash + 1;
      size_t pc_filename_len = strlen(pc_filename_start);

      if (pc_filename_len >= sizeof(pctx->file_name_buf)) {
        pc_filename_len = sizeof(pctx->file_name_buf) - 1;
      } /* if */

      (void)memcpy(pctx->file_name_buf, pc_filename_start, pc_filename_len);
      pctx->file_name_buf[pc_filename_len] = '\0';

      size_t total_needed = strlen(pctx->direct_path) + 1 + strlen(pctx->file_name_buf) + 1;

      if (total_needed > sizeof(pctx->input_path)) {
        (void)strncpy(pctx->direct_path, "gamemodes",
          sizeof(pctx->direct_path) - 1);
        pctx->direct_path[sizeof(pctx->direct_path) - 1] = '\0';

        size_t pc_max_size_file_name = sizeof(pctx->file_name_buf) - 1;

        if (pc_filename_len > pc_max_size_file_name) {
          (void)memcpy(pctx->file_name_buf,
            pc_filename_start,
            pc_max_size_file_name);
          pctx->file_name_buf[pc_max_size_file_name] = '\0';
        } /* if */
      } /* if */

      if (snprintf(pctx->input_path,
        sizeof(pctx->input_path),
        "%s/%s",
        pctx->direct_path,
        pctx->file_name_buf) >= (int)sizeof(pctx->input_path))
      {
        pctx->input_path[sizeof(pctx->input_path) - 1] = '\0';
      } /* if */
    }
    else {
      /* No directory separator, use current directory */
      (void)strncpy(pctx->file_name_buf,
        pctx->temp_path,
        sizeof(pctx->file_name_buf) - 1);
      pctx->file_name_buf[sizeof(pctx->file_name_buf) - 1] = '\0';

      (void)strncpy(pctx->direct_path,
        ".",
        sizeof(pctx->direct_path) - 1);
      pctx->direct_path[sizeof(pctx->direct_path) - 1] = '\0';

      if (snprintf(pctx->input_path,
        sizeof(pctx->input_path),
        "./%s",
        pctx->file_name_buf) >= (int)sizeof(pctx->input_path)) {
        pctx->input_path[sizeof(pctx->input_path) - 1] = '\0';
      } /* if */
    } /* if */

    /* Search for file in gamemodes directory if not found */
    int pc_finding_compile_args = 0;
    pc_finding_compile_args = find_path(
      pctx->direct_path,
      pctx->file_name_buf,
      NULL);

    if (!pc_finding_compile_args &&
      strcmp(pctx->direct_path, "gamemodes") != 0) {
      pc_finding_compile_args =
        find_path("gamemodes",
          pctx->file_name_buf,
          NULL);
      
      if (pc_finding_compile_args) {
        (void)strncpy(pctx->direct_path,
          "gamemodes",
          sizeof(pctx->direct_path) - 1);
        pctx->direct_path[sizeof(pctx->direct_path) - 1] = '\0';

        if (snprintf(pctx->input_path,
          sizeof(pctx->input_path),
          "gamemodes/%s",
          pctx->file_name_buf) >=
          (int)sizeof(pctx->input_path)) {
          pctx->input_path[sizeof(pctx->input_path) - 1] = '\0';
        } /* if */

        if (dogconfig.dog_sef_count > RATE_SEF_EMPTY)
        {
          (void)strncpy(dogconfig.dog_sef_found_list[
              dogconfig.dog_sef_count - 1],
            pctx->input_path,
            MAX_SEF_PATH_SIZE);
        } /* if */
      } /* if */
    } /* if */

    if (!pc_finding_compile_args &&
      !strcmp(pctx->direct_path, ".")) {
      pc_finding_compile_args =
        find_path("gamemodes",
          pctx->file_name_buf,
          NULL);
      
      if (pc_finding_compile_args) {
        (void)strncpy(pctx->direct_path,
          "gamemodes",
          sizeof(pctx->direct_path) - 1);
        pctx->direct_path[sizeof(pctx->direct_path) - 1] = '\0';

        if (snprintf(pctx->input_path,
          sizeof(pctx->input_path),
          "gamemodes/%s",
          pctx->file_name_buf) >=
          (int)sizeof(pctx->input_path)) {
          pctx->input_path[sizeof(pctx->input_path) - 1] = '\0';
        } /* if */

        if (dogconfig.dog_sef_count > RATE_SEF_EMPTY) {
          strncpy(dogconfig.dog_sef_found_list[
              dogconfig.dog_sef_count - 1],
            pctx->input_path,
            MAX_SEF_PATH_SIZE);
        } /* if */
      } /* if */
    } /* if */

    /* Find matching server path */
    for (int i = 0; i < (int)fet_sef_ent; i++) {
      if (_strfind(dogconfig.dog_sef_found_list[i],
        compile_args_val, true) == true)
      {
        pc_temp[0] = '\0';
        pbuf[0] = '\0';

        (void)snprintf(pc_temp,
          sizeof(pc_temp), "%s",
          dogconfig.dog_sef_found_list[i]);

        (void)snprintf(pbuf, sizeof(pbuf),
          "%s", pc_temp);
        
        if (server_path != NULL) {
          free(server_path);
          server_path = NULL;
        } /* if */

        server_path = strdup(pbuf);
        break;
      } /* if */
    } /* for */

#if defined(_DBG_PRINT)
    if (server_path != NULL) {
      pr_info(stdout, "server_path: %s", server_path);
    } /* if */
#endif
    
    /* Execute compilation if file exists */
    if (server_path != NULL && path_exists(server_path) == 1) {

      if (server_path[0] != '\0') {
        pc_temp[0] = '\0';
        strncpy(pc_temp, server_path,
          sizeof(pc_temp) - 1);
        pc_temp[sizeof(pc_temp) - 1] = '\0';
      } else {
        pc_temp[0] = '\0';
      } /* if */

      char* ext = strrchr(pc_temp, '.');
      if (ext) {
        *ext = '\0';
      } /* if */

      if (pctx->output != NULL) {
        free(pctx->output);
      } /* if */
      
      pctx->output = strdup(pc_temp);

      (void)snprintf(pc_temp, sizeof(pc_temp),
        "%s.amx", pctx->output);

      char* pc_temp2 = strdup(pc_temp);
      if (pc_temp2 == NULL) {
        pr_error(stdout, "dog_exec_compiler: memory allocation failed for pc_temp2");
        goto pc_end;
      } /* if */

      int _process = dog_exec_compiler_tasks(
        dogconfig.dog_pawncc_path,
        server_path,
        pc_temp2);
      
      if (_process != 0) {
        pr_error(stdout, "dog_exec_compiler: compilation failed with code: %d", _process);
        free(pc_temp2);
        goto pc_end;
      } /* if */
      
      if (server_path != NULL) {
        free(server_path);
        server_path = NULL;
      } /* if */

      /* Process compiler output */
      if (path_exists(".watchdogs/compiler.log")) {
        (void)putchar('\n');
        
        char* ca = pc_temp2;
        _Bool cb = 0;
        
        if (pc_debug_options) {
          cb = 1;
        } /* if */
        
        if (pctx->flag_detailed) {
          cause_pc_expl(
            ".watchdogs/compiler.log",
            ca, cb);
          print_restore_color();
          goto pc_done2;
        } /* if */

        if (spawn_succeeded == false) {
          print_file(".watchdogs/compiler.log");
        } /* if */
      } /* if */

    pc_done2:
      /* Check for compilation errors */
      fp = fopen(".watchdogs/compiler.log", "r");
      pbuf[0] = '\0';
      
      if (fp != NULL) {
        _Bool has_err = false;
        
        while (fgets(pbuf, sizeof(pbuf), fp)) {
          if (_strfind(pbuf, "error", true)) {
            has_err = true;
            break;
          } /* if */
        } /* while */
        
        fclose(fp);
        fp = NULL;
        
        if (has_err) {
          if (pc_temp2 && path_access(pc_temp2)) {
            remove(pc_temp2);
          } /* if */
          pc_is_error = true;
        } else {
          pc_is_error = false;
        } /* if */
      } else {
        pr_error(stdout,
          "Failed to open .watchdogs/compiler.log");
        minimal_debugging();
      } /* if */

      if (pc_temp2 != NULL) {
        free(pc_temp2);
        pc_temp2 = NULL;
      } /* if */

      /* Calculate and display compilation time */
      elapsed_time = ((double)(post_end.tv_sec - pre_start.tv_sec)) +
               ((double)(post_end.tv_nsec - pre_start.tv_nsec)) / 1e9;

      (void)putchar('\n');

      if (!pc_is_error) {
        puts("** Completed Tasks.\n");
      } /* if */
      
      fputs(LR_YELLOW " -----------------------------\n" LR_DEFAULT, stdout);

      pr_color(stdout, LR_CYAN,
        " <C> (compile-time) Complete At %.3fs (%.0f ms)\n",
        elapsed_time,
        elapsed_time * 1000.0);
      
      if (elapsed_time > 300) {
        pr_info(stdout, "dog_exec_compiler: compilation took >300s, checking timeout");
        goto _print_time;
      } /* if */
    } else {
      /* File not found */
      pbuf[0] = '\0';
      len = snprintf(pbuf, sizeof(pbuf),
        "Cannot locate input: " LR_CYAN
        "%s" LR_DEFAULT
        " - No such file or directory\n",
        compile_args_val ? compile_args_val : "(null)");
      
      if (len > 0 && len < (int)sizeof(pbuf)) {
        fwrite(pbuf, 1, len, stdout);
        fflush(stdout);
      } /* if */
      
      goto pc_end;
    } /* if */
  } /* if */

  /* Close log file if open */
  if (fp != NULL) {
    fclose(fp);
    fp = NULL;
  } /* if */

  pbuf[0] = '\0';

  /* Open compiler log for error checking */
  fp = fopen(".watchdogs/compiler.log", "rb");

  if (!fp) {
    pr_info(stdout, "dog_exec_compiler: no compiler.log found");
    goto pc_end;
  } /* if */
  
  if (pc_time_issue) {
    pr_info(stdout, "dog_exec_compiler: time issue detected, skipping error check");
    goto pc_end;
  } /* if */

  while (fgets(pbuf, sizeof(pbuf), fp) != NULL) {
    if (_strfind(pbuf, "error", true) != false) {
      switch (pc_retry_state)
      {
      case PC_RETRY_STATE_NONE:
        pc_retry_state = PC_RETRY_STATE_FIRST;
        pbuf[0] = '\0';
        len = snprintf(pbuf, sizeof(pbuf),
          LR_BCYAN
          "** Compilation Process Exit with Failed. "
          "recompiling: "
          "%d/2\n"
          LR_DEFAULT, pc_retry_state);
        
        if (len > 0 && len < (int)sizeof(pbuf)) {
          fwrite(pbuf, 1, len, stdout);
          fflush(stdout);
        } /* if */
        
        if (fp != NULL) {
          fclose(fp);
          fp = NULL;
        } /* if */
        
        goto _pc_retry_state;
        
      case PC_RETRY_STATE_FIRST:
        pc_retry_state = PC_RETRY_STATE_FINAL;
        pbuf[0] = '\0';
        len = snprintf(pbuf, sizeof(pbuf),
          LR_BCYAN
          "** Compilation Process Exit with Failed. "
          "recompiling: "
          "%d/2\n"
          LR_DEFAULT, pc_retry_state);
        
        if (len > 0 && len < (int)sizeof(pbuf)) {
          fwrite(pbuf, 1, len, stdout);
          fflush(stdout);
        } /* if */
        
        if (fp != NULL) {
          fclose(fp);
          fp = NULL;
        } /* if */
        
        goto _pc_retry_state;
        
      default:
        break;
      } /* switch */
    } /* if */
  } /* while */

  if (fp != NULL) {
    fclose(fp);
    fp = NULL;
  } /* if */

  goto pc_end;

pc_end:
  /* Cleanup temporary files */
  if (find_path(".watchdogs", "*_temp", NULL) > 0) {
    for (int i = 0; i < (int)fet_sef_ent; i++) {
      if (dogconfig.dog_sef_found_list[i][0] != '\0') {
        remove(dogconfig.dog_sef_found_list[i]);
      } /* if */
    } /* for */
    
    _sef_restore();
  } /* if
  
  /* Clean up server_path if still allocated */
  if (server_path) {
    free(server_path);
    server_path = NULL;
  } /* if */
  
  return ret;
  
_print_time:
  static const char *prtm_msg = "** Process is taking a while..";
  puts(prtm_msg);

  if (pc_time_issue == 0) {
    pr_info(stdout, "Retrying..");
    pc_time_issue = true;
    
    if (fp != NULL) {
      fclose(fp);
      fp = NULL;
    } /* if */
    
    goto _pc_retry_state;
  } /* if */
  
  return ret;
} /* dog_exec_compiler */