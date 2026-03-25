#include "utils.h"
#include "debug.h"
#include "compiler.h"
#include "process.h"

static char*   pc_unix_args[DOG_MAX_PATH] = { NULL };
static char  pbuf[DOG_PATH_MAX + 28] = { 0 };
static char  pc_input[DOG_MAX_PATH] = { 0 };
static char*   pc_unix_token = NULL;
#ifdef DOG_WINDOWS
static PROCESS_INFORMATION _PROCESS_INFO = { 0 };
static STARTUPINFO     _STARTUPINFO = { 0 };
static SECURITY_ATTRIBUTES _ATTRIBUTES = { 0 };
#endif
#ifdef DOG_WINDOWS
#define COMPILER_LOG ".watchdogs\\compiler.log"
#else
#define COMPILER_LOG ".watchdogs/compiler.log"
#endif

static
long pc_get_milisec(void) {
  struct timespec ts;
  long result = 0;
  
  /* Validate timespec structure */
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    pr_error(stdout, "pc_get_milisec: clock_gettime failed: %s", strerror(errno));
    return 0;
  } /* if */
  
  result = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
  return result;
} /* pc_get_milisec */

static
void pc_stage_trying(const char* stage, int ms) {
  long start;
  int i;
  
  /* Validate input parameters */
  if (stage == NULL) {
    pr_error(stdout, "pc_stage_trying: stage is NULL");
    return;
  } /* if */
  
  if (ms <= 0) {
    pr_warning(stdout, "pc_stage_trying: ms %d is invalid, using default", ms);
    ms = 60;
  } /* if */
  
  start = pc_get_milisec();
  
  /* Animated progress indicator */
  while (pc_get_milisec() - start < ms) {
    char buf[128] = {0};
    int len = snprintf(buf, sizeof(buf), "\r%s....", stage);
    
    if (len > 0 && len < (int)sizeof(buf)) {
      fwrite(buf, 1, len, stdout);
      fflush(stdout);
    } /* if */
    
    /* Small delay to prevent excessive CPU usage */
    usleep(50000); /* 50ms */
  } /* while */
  
  /* Handle user's script stage specially */
  if (_strfind(stage, ".. user's script", true) == true) {
    fputs("\r\033[2K", stdout);

    static const char* stage_lines[] = {
      "  o implicit include file\n"
      "   o user include file(s)\n"
      "   o user's script\n"
      LR_DEFAULT
      "\n** Preparing all tasks..\n",
      NULL
    };

    fputs(LR_BCYAN, stdout);
    
    /* Display all stage lines */
    for (i = 0; stage_lines[i]; ++i) {
      if (stage_lines[i] != NULL) {
        fputs(stage_lines[i], stdout);
      } /* if */
    } /* for */
    
    print_restore_color();
  } /* if */
} /* pc_stage_trying */

static
void dog_serv_init(char* input_path, char* pawncc_path) {
  int i;
  
  /* Validate input parameters */
  if (input_path == NULL) {
    pr_error(stdout, "dog_serv_init: input_path is NULL");
    return;
  } /* if */
  
  if (pawncc_path == NULL) {
    pr_error(stdout, "dog_serv_init: pawncc_path is NULL");
    return;
  } /* if */

  static _Bool permissions_initialized = false;
  
  /* Initialize permissions on first call */
  if (permissions_initialized == false) {
    if (path_exists("gamemodes") == 1) {
      __set_default_access("gamemodes");
    } /* if */
    
    if (path_exists("pawno") == 1)
    {
      __set_default_access("pawno");
      if (path_exists("pawno/include") == 1) {
        __set_default_access("pawno/include");
      } /* if */
    } /* if */
    
    if (path_exists("qawno") == 1)
    {
      __set_default_access("qawno");
      
      if (path_exists("qawno/include") == 1) {
        __set_default_access("qawno/include");
      } /* if */
    } /* if */
    
    __set_default_access(pawncc_path);
    __set_default_access(input_path);
    permissions_initialized = true;
  } /* if */

  puts("** Thinking all tasks..\n");
  
  static _Bool pc_pipe_info = false;
  
  if (pc_pipe_info == false) {
    pc_pipe_info = true;
    
    /* Display animated stages */
    pc_stage_trying(".. implicit include file", 60);
    pc_stage_trying(".. user include file(s)", 60);
    pc_stage_trying(".. user's script", 60);
  } else {
    static const char* stage_lines[] = {
      "  o implicit include file\n"
      "   o user include file(s)\n"
      "   o user's script\n"
      LR_DEFAULT
      "\n** Preparing all tasks..\n",
      NULL
    };

    fputs(LR_BCYAN, stdout);
    
    /* Display static stages */
    for (i = 0; stage_lines[i]; ++i) {
      if (stage_lines[i] != NULL) {
        fputs(stage_lines[i], stdout);
      } /* if */
    } /* for */
    
    print_restore_color();
  } /* if */
} /* dog_serv_init */

#ifdef DOG_LINUX
static
void configure_line_parsing(io_compilers* pctx) {
  char  token[DOG_MAX_PATH] = { 0 };
  int   cnt = 0, pos = 0, inside = 0;
  char* p = pc_input;
  
  /* Parse command line respecting quoted strings */
  while (*p) {
    /* Toggle quoted state on double quote */
    if (*p == '"') {
      inside = !inside;
      token[pos++] = *p;
      p++;
      continue;
    } /* if */
    
    /* Handle spaces outside quotes as delimiters */
    if (*p == ' ' && !inside) {
      if (pos > 0) {
        token[pos] = '\0';
        pc_unix_args[cnt++] = strdup(token);
        if (pctx->flag_detailed)
          pr_info(stdout, "configure_line_parsing: arg[%d] = %s", cnt-1, token);
        pos = 0;
      } /* if */
      p++;
      continue;
    } /* if */
    
    /* Add character to current token */
    token[pos++] = *p++;
  } /* while */
  
  /* Add final token if any */
  if (pos > 0) {
    token[pos] = '\0';
    pc_unix_args[cnt++] = strdup(token);
    if (pctx->flag_detailed)
      pr_info(stdout, "configure_line_parsing: arg[%d] = %s", cnt-1, token);
  } /* if */
  
  pc_unix_args[cnt] = NULL;
} /* configure_line_parsing */
#endif

#ifdef DOG_WINDOWS
// Thread function for fast compilation using _beginthreadex
static unsigned __stdcall
pc_thread_func(void* arg) {
  pc_thread_data_t* data = (pc_thread_data_t*)arg;
  BOOL win32_process_success;
  DWORD err = 0;
  DWORD waitResult = 0;
  DWORD proc_exit_code = 0;
  
  /* Validate thread data */
  if (data == NULL) {
    pr_error(stdout, "pc_thread_func: thread data is NULL");
    return 1;
  } /* if */

  /* Create Windows process for compiler execution */
  win32_process_success = CreateProcessA(
    NULL, data->pc_input,
    NULL, NULL,
    TRUE,
    CREATE_NO_WINDOW |
    ABOVE_NORMAL_PRIORITY_CLASS |
    CREATE_BREAKAWAY_FROM_JOB,
    NULL, NULL,
    data->startup_info, data->process_info);

  err = GetLastError();

  /* Set handle inheritance if file handle is valid */
  if (data->hFile != INVALID_HANDLE_VALUE) {
    SetHandleInformation(data->hFile,
      HANDLE_FLAG_INHERIT, 0);
  } /* if */

  if (win32_process_success == TRUE) {
    /* Set thread priority */
    SetThreadPriority(
      data->process_info->hThread,
      THREAD_PRIORITY_ABOVE_NORMAL);

    /* Set process affinity */
    DWORD_PTR procMask, sysMask;
    GetProcessAffinityMask(
      GetCurrentProcess(),
      &procMask, &sysMask);
    SetProcessAffinityMask(
      data->process_info->hProcess,
      procMask & ~1);

    /* Record start time */
    clock_gettime(CLOCK_MONOTONIC,
      data->pre_start);
      
    /* Wait for process with timeout */
    waitResult = WaitForSingleObject(
      data->process_info->hProcess,
      4096);
      
    switch (waitResult) {
    case WAIT_TIMEOUT:
      pr_warning(stdout, "pc_thread_func: process timeout, terminating");
      TerminateProcess(
        data->process_info->hProcess, 1);
      WaitForSingleObject(
        data->process_info->hProcess,
        5000);
      break;
    case WAIT_OBJECT_0:
      break;
    case WAIT_FAILED:
      pr_error(stdout, "pc_thread_func: WaitForSingleObject failed: %lu", GetLastError());
      break;
    default:
      break;
    } /* switch */
    
    /* Record end time */
    clock_gettime(CLOCK_MONOTONIC,
      data->post_end);

    /* Retrieve process exit code */
    GetExitCodeProcess(
      data->process_info->hProcess,
      &proc_exit_code);
    
#if defined(_DBG_PRINT)
    pr_info(stdout, "pc_thread_func: process exit code: %lu", proc_exit_code);

    if (proc_exit_code == 3221225781)
    {
      pr_info(stdout, data->windows_redist_err);
      if (data->windows_redist_err2 != NULL) {
        char pbuf[strlen(data->windows_redist_err2) + 1];
        int len = snprintf(pbuf, sizeof(pbuf),
          "%s", data->windows_redist_err2);
        if (len > 0 && len < (int)sizeof(pbuf)) {
          fwrite(pbuf, 1, len, stdout);
          fflush(stdout);
        } /* if */
      } /* if */
    } /* if */
#endif

    /* Clean up handles */
    CloseHandle(data->process_info->hThread);
    CloseHandle(data->process_info->hProcess);

    /* Close output handles if needed */
    if (data->startup_info->hStdOutput != NULL &&
      data->startup_info->hStdOutput != data->hFile) {
      CloseHandle(data->startup_info->hStdOutput);
    } /* if */
    
    if (data->startup_info->hStdError != NULL &&
      data->startup_info->hStdError != data->hFile) {
      CloseHandle(data->startup_info->hStdError);
    } /* if */
  } else {
    pr_error(stdout, "CreateProcess failed! (%lu)", err);
    
    /* Provide helpful error messages */
    if (_strfind(strerror(err), "The system cannot find the file specified", true)) {
      pr_error(stdout, "^ The compiler executable does not exist.");
    } /* if */
    
    if (_strfind(strerror(err), "Access is denied", true)) {
      pr_error(stdout, "^ You do not have permission to execute the compiler executable.");
    } /* if */
    
    if (_strfind(strerror(err), "The directory name is invalid", true)) {
      pr_error(stdout, "^ The compiler executable is not a directory.");
    } /* if */
    
    if (_strfind(strerror(err), "The system cannot find the path specified", true)) {
      pr_error(stdout, "^ The compiler executable does not exist.");
    } /* if */
    
    minimal_debugging();
  } /* if */

  return (0);
} /* pc_thread_func */
#endif

static int build_compiler_command(char* pawncc_path, char* input_path,
  char* output_path, char* options) {
  int result = 0;
  
  /* Validate input parameters */
  if (pawncc_path == NULL) {
    pr_error(stdout, "build_compiler_command: pawncc_path is NULL");
    return -1;
  } /* if */
  
  if (input_path == NULL) {
    pr_error(stdout, "build_compiler_command: input_path is NULL");
    return -1;
  } /* if */
  
  if (output_path == NULL) {
    pr_error(stdout, "build_compiler_command: output_path is NULL");
    return -1;
  } /* if */
  
  if (options == NULL) {
    pr_warning(stdout, "build_compiler_command: options is NULL, using empty string");
    options = "";
  } /* if */
  
  result = snprintf(pc_input, sizeof(pc_input),
    "%s %s -o%s %s %s %s",
    pawncc_path, input_path, output_path,
    options, pc_full_includes ? pc_full_includes : "", 
    pc_include_path ? pc_include_path : "");
    
  if (result < 0 || result >= (int)sizeof(pc_input)) {
    pr_error(stdout, "build_compiler_command: command too long (needed %d bytes)", result);
    return -1;
  } /* if */
  
  return result;
} /* build_compiler_command */

static void display_compiler_command(void) {
  if (pc_input_info == true) {
#ifdef DOG_ANDROID
    println(stdout, "** %s", pc_input);
#else
    (void)console_title(pc_input);
    println(stdout, "** %s", pc_input);
#endif
  } /* if */
} /* display_compiler_command */

#ifdef DOG_WINDOWS
// Windows-specific: Create log file handle
static HANDLE create_windows_log_file(void) {
  HANDLE hFile = INVALID_HANDLE_VALUE;
  
  hFile = CreateFileA(
    COMPILER_LOG,
    GENERIC_WRITE,
    FILE_SHARE_READ,
    &_ATTRIBUTES,
    CREATE_ALWAYS,
    FILE_ATTRIBUTE_NORMAL |
    FILE_FLAG_SEQUENTIAL_SCAN |
    FILE_ATTRIBUTE_TEMPORARY,
    NULL);
    
  if (hFile == INVALID_HANDLE_VALUE) {
    pr_error(stdout, "create_windows_log_file: failed to create log file: %lu", GetLastError());
  } else {
    ;
  } /* if */
  
  return hFile;
} /* create_windows_log_file */

// Windows-specific: Initialize startup info
static void init_windows_startup_info(HANDLE hFile) {
  
  _STARTUPINFO.cb = sizeof(_STARTUPINFO);
  _STARTUPINFO.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  _STARTUPINFO.wShowWindow = SW_HIDE;

  if (hFile != INVALID_HANDLE_VALUE) {
    _STARTUPINFO.hStdOutput = hFile;
    _STARTUPINFO.hStdError = hFile;
  } /* if */
  
  _STARTUPINFO.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
} /* init_windows_startup_info */

// Windows-specific: Execute compiler with CreateProcess
static int execute_windows_compiler_standard(HANDLE hFile, io_compilers* pctx,
  const char* windows_redist_err,
  const char* windows_redist_err2) {
  BOOL win32_process_success;
  DWORD err = 0;
  DWORD waitResult = 0;
  DWORD proc_exit_code = 0;

  win32_process_success = CreateProcessA(
    NULL, pc_input,
    NULL, NULL,
    TRUE,
    CREATE_NO_WINDOW |
    ABOVE_NORMAL_PRIORITY_CLASS |
    CREATE_BREAKAWAY_FROM_JOB,
    NULL, NULL,
    &_STARTUPINFO, &_PROCESS_INFO);

  err = GetLastError();

  if (hFile != INVALID_HANDLE_VALUE) {
    SetHandleInformation(hFile, HANDLE_FLAG_INHERIT, 0);
  } /* if */

  if (win32_process_success == TRUE) {
    /* Set thread priority */
    SetThreadPriority(_PROCESS_INFO.hThread, THREAD_PRIORITY_ABOVE_NORMAL);

    /* Set process affinity */
    DWORD_PTR procMask, sysMask;
    GetProcessAffinityMask(GetCurrentProcess(), &procMask, &sysMask);
    SetProcessAffinityMask(_PROCESS_INFO.hProcess, procMask & ~1);

    /* Record start time */
    clock_gettime(CLOCK_MONOTONIC, &pre_start);
    
    /* Wait for process with timeout */
    waitResult = WaitForSingleObject(_PROCESS_INFO.hProcess, 4096);

    switch (waitResult) {
    case WAIT_TIMEOUT:
      pr_warning(stdout, "execute_windows_compiler_standard: process timeout");
      TerminateProcess(_PROCESS_INFO.hProcess, 1);
      WaitForSingleObject(_PROCESS_INFO.hProcess, 5000);
      break;
    case WAIT_OBJECT_0:
      break;
    default:
      pr_error(stdout, "execute_windows_compiler_standard: wait failed: %lu", waitResult);
      break;
    } /* switch */
    
    /* Record end time */
    clock_gettime(CLOCK_MONOTONIC, &post_end);

    /* Get exit code */
    GetExitCodeProcess(_PROCESS_INFO.hProcess, &proc_exit_code);

#if defined(_DBG_PRINT)
    pr_info(stdout, "execute_windows_compiler_standard: exit code: %lu", proc_exit_code);

    if (proc_exit_code == 3221225781) {
      pr_info(stdout, windows_redist_err);
      if (windows_redist_err2 != NULL) {
        char pbuf[strlen(windows_redist_err2) + 1];
        int len = snprintf(pbuf, sizeof(pbuf), "%s", windows_redist_err2);
        if (len > 0 && len < (int)sizeof(pbuf)) {
          fwrite(pbuf, 1, len, stdout);
          fflush(stdout);
        } /* if */
      } /* if */
    } /* if */
#endif

    /* Clean up handles */
    CloseHandle(_PROCESS_INFO.hThread);
    CloseHandle(_PROCESS_INFO.hProcess);

    /* Close output handles if needed */
    if (_STARTUPINFO.hStdOutput != NULL && _STARTUPINFO.hStdOutput != hFile) {
      CloseHandle(_STARTUPINFO.hStdOutput);
    } /* if */
    
    if (_STARTUPINFO.hStdError != NULL && _STARTUPINFO.hStdError != hFile) {
      CloseHandle(_STARTUPINFO.hStdError);
    } /* if */
  } else {
    pr_error(stdout, "CreateProcess failed! (%lu)", err);
    
    /* Provide helpful error messages */
    if (_strfind(strerror(err), "The system cannot find the file specified", true)) {
      pr_error(stdout, "^ The compiler executable does not exist.");
    } /* if */
    
    if (_strfind(strerror(err), "Access is denied", true)) {
      pr_error(stdout, "^ You do not have permission to execute the compiler executable.");
    } /* if */
    
    if (_strfind(strerror(err), "The directory name is invalid", true)) {
      pr_error(stdout, "^ The compiler executable is not a directory.");
    } /* if */
    
    if (_strfind(strerror(err), "The system cannot find the path specified", true)) {
      pr_error(stdout, "^ The compiler executable does not exist.");
    } /* if */
    
    minimal_debugging();
  } /* if */

  return 0;
} /* execute_windows_compiler_standard */

// Windows-specific: Execute compiler with thread (fast mode)
static int execute_windows_compiler_fast(HANDLE hFile, io_compilers* pctx,
  const char* windows_redist_err,
  const char* windows_redist_err2) {
  pc_thread_data_t thread_data;
  HANDLE thread_handle = NULL;
  unsigned thread_id = 0;

  /* Initialize thread data */
  thread_data.pc_input = pc_input;
  thread_data.startup_info = &_STARTUPINFO;
  thread_data.process_info = &_PROCESS_INFO;
  thread_data.hFile = hFile;
  thread_data.pre_start = &pre_start;
  thread_data.post_end = &post_end;
  thread_data.windows_redist_err = windows_redist_err;
  thread_data.windows_redist_err2 = windows_redist_err2;

  /* Create thread */
  thread_handle = (HANDLE)_beginthreadex(NULL, 0, pc_thread_func, &thread_data, 0, &thread_id);

  if (thread_handle == NULL) {
    pr_error(stdout, "_beginthreadex failed!");
    minimal_debugging();
    return -1;
  } else {
    WaitForSingleObject(thread_handle, INFINITE);
    CloseHandle(thread_handle);
  } /* if */

  return 0;
} /* execute_windows_compiler_fast */

// Windows-specific: Execute compiler task
static int execute_windows_compiler(io_compilers* pctx) {
  const char* windows_redist_err =
    "Have you made sure to install the Visual CPP (C++) Redist All-in-One?";
  const char* windows_redist_err2 =
    "   - install first: https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/\n";
  
  HANDLE hFile = INVALID_HANDLE_VALUE;
  int result = 0;

  /* Initialize security attributes */
  _ATTRIBUTES.nLength = sizeof(_ATTRIBUTES);
  _ATTRIBUTES.bInheritHandle = TRUE;
  _ATTRIBUTES.lpSecurityDescriptor = NULL;

  /* Create log file */
  hFile = create_windows_log_file();
  
  /* Initialize startup info */
  init_windows_startup_info(hFile);

  /* Display compiler command */
  display_compiler_command();

  /* Execute based on fast flag */
  if (pctx->flag_fast == true) {
    result = execute_windows_compiler_fast(hFile, pctx, windows_redist_err, windows_redist_err2);
  } else {
    result = execute_windows_compiler_standard(hFile, pctx, windows_redist_err, windows_redist_err2);
  } /* if */

  /* Close log file handle */
  if (hFile != INVALID_HANDLE_VALUE) {
    CloseHandle(hFile);
  } /* if */

  return result;
} /* execute_windows_compiler */
#endif /* DOG_WINDOWS */

#ifdef DOG_LINUX
// Linux-specific: Free unix args
static void free_unix_args(void) {
  int freed_count = 0;
  
  for (int i = 0; pc_unix_args[i]; i++) {
    if (pc_unix_args[i] != NULL) {
      free(pc_unix_args[i]);
      pc_unix_args[i] = NULL;
      freed_count++;
    } /* if */
  } /* for */

} /* free_unix_args */

#if defined (IS_POSIX)

#ifdef DOG_ANDROID
// Android-specific: Execute compiler using fork/vfork
static int execute_android_compiler(io_compilers* pctx) {
  static _Bool vfork_mode = false;
  pid_t pc_process_id = -1;
  int process_status = 0;
  int process_timeout_occurred = 0;
  int k;

  /* Determine fork mode based on fast flag */
  if (pctx->flag_fast == 1) {
    vfork_mode = true;
  } else {
    ;
  } /* if */

  /* Create child process */
  if (vfork_mode == false) {
    pc_process_id = fork();
  } else {
    pc_process_id = vfork();
  } /* if */

  if (pc_process_id == 0) {
    /* Child process */
    int logging_file = open(COMPILER_LOG, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    
    if (logging_file != -1) {
      dup2(logging_file, STDOUT_FILENO);
      dup2(logging_file, STDERR_FILENO);
      close(logging_file);
    } else {
      pr_error(stdout, "execute_android_compiler: child failed to open log: %s", strerror(errno));
    } /* if */
    
    execv(pc_unix_args[0], pc_unix_args);
    fprintf(stderr, "execv failed: %s\n", strerror(errno));
    _exit(127);
  } else if (pc_process_id > 0) {
    /* Parent process */
    clock_gettime(CLOCK_MONOTONIC, &pre_start);

    /* Poll for process completion with timeout */
    for (k = 0; k < 4096; k++) {
      int proc_result = waitpid(pc_process_id, &process_status, WNOHANG);
      
      if (proc_result == 0) {
        /* Process still running */
        usleep(100000); /* 100ms sleep between polls */
      } else if (proc_result == pc_process_id) {
        break;
      } else {
        pr_error(stdout, "execute_android_compiler: waitpid error: %s", strerror(errno));
        minimal_debugging();
        break;
      } /* if */

      /* Handle timeout */
      if (k == 4096 - 1) {
        pr_warning(stdout, "execute_android_compiler: process timeout, terminating");
        kill(pc_process_id, SIGTERM);
        sleep(2);
        kill(pc_process_id, SIGKILL);
        pr_error(stdout, "process execution timeout! (%d seconds)", 4096);
        minimal_debugging();
        waitpid(pc_process_id, &process_status, 0);
        process_timeout_occurred = 1;
      } /* if */
    } /* for */

    clock_gettime(CLOCK_MONOTONIC, &post_end);

    /* Process exit status */
    if (!process_timeout_occurred) {
      if (WIFEXITED(process_status)) {
        int proc_exit_code = WEXITSTATUS(process_status);
#if defined(_DBG_PRINT)
        pr_info(stdout, "execute_android_compiler: process exited with code %d", proc_exit_code);
#endif
        if (proc_exit_code != 0 && proc_exit_code != 1) {
          pr_error(stdout, "compiler process exited with code (%d)", proc_exit_code);
          minimal_debugging();
        } /* if */
      } else if (WIFSIGNALED(process_status)) {
        pr_error(stdout, "compiler process terminated by signal (%d)", WTERMSIG(process_status));
        minimal_debugging();
      } /* if */
    } /* if */
  } else {
    pr_error(stdout, "process creation failed: %s", strerror(errno));
    minimal_debugging();
  } /* if */

  return 0;
} /* execute_android_compiler */
#else /* !DOG_ANDROID */
// Linux (non-Android)-specific: Execute compiler using posix_spawn
static int execute_linux_compiler_posix(io_compilers* pctx,
  const char* windows_redist_err,
  const char* windows_redist_err2) {
  posix_spawn_file_actions_t process_file_actions;
  posix_spawnattr_t spc_attr;
  sigset_t sigmask, sigdefault;
  pid_t pc_process_id = -1;
  int process_spc_result = 0;
  int posix_logging_file = -1;
  int process_status = 0;
  int process_timeout_occurred = 0;
  int k;

  /* Initialize file actions */
  posix_spawn_file_actions_init(&process_file_actions);

  /* Open log file */
  posix_logging_file = open(COMPILER_LOG, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (posix_logging_file != -1) {
    posix_spawn_file_actions_adddup2(&process_file_actions, posix_logging_file, STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&process_file_actions, posix_logging_file, STDERR_FILENO);
    posix_spawn_file_actions_addclose(&process_file_actions, posix_logging_file);
  } else {
    pr_error(stdout, "execute_linux_compiler_posix: failed to open log file: %s", strerror(errno));
  } /* if */

  /* Initialize spawn attributes */
  posix_spawnattr_init(&spc_attr);

  /* Set signal mask */
  sigemptyset(&sigmask);
  sigaddset(&sigmask, SIGCHLD);
  posix_spawnattr_setsigmask(&spc_attr, &sigmask);

  /* Set default signals */
  sigemptyset(&sigdefault);
  sigaddset(&sigdefault, SIGPIPE);
  sigaddset(&sigdefault, SIGINT);
  sigaddset(&sigdefault, SIGTERM);
  posix_spawnattr_setsigdefault(&spc_attr, &sigdefault);

  /* Set flags */
  short flags = POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
  posix_spawnattr_setflags(&spc_attr, flags);

  /* Spawn process */
  process_spc_result = posix_spawn(&pc_process_id, pc_unix_args[0],
    &process_file_actions, &spc_attr,
    pc_unix_args, environ);

  /* Close log file in parent */
  if (posix_logging_file != -1) {
    close(posix_logging_file);
  } /* if */

  /* Clean up spawn attributes and file actions */
  posix_spawnattr_destroy(&spc_attr);
  posix_spawn_file_actions_destroy(&process_file_actions);

  if (process_spc_result == 0) {
    clock_gettime(CLOCK_MONOTONIC, &pre_start);

    /* Poll for process completion with timeout */
    for (k = 0; k < 4096; k++) {
      int proc_result = waitpid(pc_process_id, &process_status, WNOHANG);
      
      if (proc_result == 0) {
        usleep(50000); /* 50ms sleep between polls */
      } else if (proc_result == pc_process_id) {
        break;
      } else {
        pr_error(stdout, "execute_linux_compiler_posix: waitpid error: %s", strerror(errno));
        minimal_debugging();
        break;
      } /* if */

      /* Handle timeout */
      if (k == 4096 - 1) {
        pr_warning(stdout, "execute_linux_compiler_posix: process timeout, terminating");
        kill(pc_process_id, SIGTERM);
        sleep(2);
        kill(pc_process_id, SIGKILL);
        pr_error(stdout, "posix_spawn process execution timeout! (%d seconds)", 4096);
        minimal_debugging();
        waitpid(pc_process_id, &process_status, 0);
        process_timeout_occurred = 1;
      } /* if */
    } /* for */

    clock_gettime(CLOCK_MONOTONIC, &post_end);

    /* Process exit status */
    if (!process_timeout_occurred) {
      if (WIFEXITED(process_status)) {
        int proc_exit_code = WEXITSTATUS(process_status);
#if defined(_DBG_PRINT)
        pr_info(stdout, "execute_android_compiler: process exited with code %d", proc_exit_code);
#endif
        if (proc_exit_code != 0 && proc_exit_code != 1) {
          pr_error(stdout, "compiler process exited with code (%d)", proc_exit_code);
          
          /* Check for WSL-specific errors */
          if (getenv("WSL_DISTRO_NAME") &&
            strcmp(dogconfig.dog_toml_os_type, OSYS_WINDOWS) == 0 &&
            proc_exit_code == 53) {
            pr_info(stdout, windows_redist_err);
            if (windows_redist_err2 != NULL) {
              char pbuf[strlen(windows_redist_err2) + 1];
              int len = snprintf(pbuf, sizeof(pbuf), "%s", windows_redist_err2);
              if (len > 0 && len < (int)sizeof(pbuf)) {
                fwrite(pbuf, 1, len, stdout);
                fflush(stdout);
              } /* if */
            } /* if */
          } /* if */
          
          minimal_debugging();
        } /* if */
      } else if (WIFSIGNALED(process_status)) {
        pr_error(stdout, "compiler process terminated by signal (%d)", WTERMSIG(process_status));
        minimal_debugging();
      } /* if */
    } /* if */
  } else {
    pr_error(stdout, "posix_spawn failed: %s", strerror(process_spc_result));
    
    /* Provide helpful error messages */
    if (_strfind(strerror(process_spc_result), "Exec format error", true)) {
      pr_error(stdout, "^ The compiler executable is not compatible with your system.");
    } /* if */
    
    if (_strfind(strerror(process_spc_result), "Permission denied", true)) {
      pr_error(stdout, "^ You do not have permission to execute the compiler executable.");
    } /* if */
    
    if (_strfind(strerror(process_spc_result), "No such file or directory", true)) {
      pr_error(stdout, "^ The compiler executable does not exist.");
    } /* if */
    
    if (_strfind(strerror(process_spc_result), "Not a directory", true)) {
      pr_error(stdout, "^ The compiler executable is not a directory.");
    } /* if */
    
    if (_strfind(strerror(process_spc_result), "Is a directory", true)) {
      pr_error(stdout, "^ The compiler executable is a directory.");
    } /* if */
    
    minimal_debugging();
  } /* if */

  return 0;
} /* execute_linux_compiler_posix */
#endif /* !DOG_ANDROID */
#endif /* DOG_LINUX */

// Linux-specific: Execute compiler task
static int execute_linux_compiler(io_compilers* pctx) {
  const char* windows_redist_err =
    "Have you made sure to install the Visual CPP (C++) Redist All-in-One?";
  const char* windows_redist_err2 =
    "   - install first: https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/\n";
  int result = 0;

  /* Parse command line into arguments */
  configure_line_parsing(pctx);
  
  /* Display compiler command */
  display_compiler_command();

  /* Execute based on platform */
#ifdef DOG_ANDROID
  result = execute_android_compiler(pctx);
#else
  result = execute_linux_compiler_posix(pctx, windows_redist_err, windows_redist_err2);
#endif

  /* Free allocated arguments */
  free_unix_args();

#if defined(_DBG_PRINT)
  pr_info(stdout, "execute_linux_compiler: completed with result %d", result);
#endif
  return result;
} /* execute_linux_compiler */

#endif

// Main compiler execution function - dispatches to platform-specific implementations
int dog_exec_compiler_tasks(char* pawncc_path, char* input_path, char* output_path) {
  static io_compilers dog_pc_sys;
  io_compilers* pctx = &all_pc_field;
  int ret_compiler = 0;
  char* options = NULL;
  
#ifdef DOG_WINDOWS
  /* Clear Windows structures */
  memset(&_PROCESS_INFO, 0, sizeof(_PROCESS_INFO));
  memset(&_STARTUPINFO, 0, sizeof(_STARTUPINFO));
  memset(&_ATTRIBUTES, 0, sizeof(_ATTRIBUTES));
#endif

  /* Validate input parameters */
  if (pawncc_path == NULL) {
    pr_error(stdout, "dog_exec_compiler_tasks: pawncc_path is NULL");
    return (-2);
  } /* if */
  
  if (input_path == NULL) {
    pr_error(stdout, "dog_exec_compiler_tasks: input_path is NULL");
    return (-2);
  } /* if */
  
  if (output_path == NULL) {
    pr_error(stdout, "dog_exec_compiler_tasks: output_path is NULL");
    return (-2);
  } /* if */

  /* Display separator */
  fputs(LR_YELLOW " -----------------------------\n" LR_DEFAULT, stdout);

  /* Initialize global variables */
  pc_unix_token = NULL;
  memset(pc_input, 0, sizeof(pc_input));
  memset(pc_unix_args, 0, sizeof(pc_unix_args));

  /* Set default includes if not already set */
  if (pc_full_includes == NULL) {
    pc_full_includes = "-i=\"pawno/include\" "
               "-i=\"qawno/include\" "
               "-i=\"gamemodes\"";
  } /* if */

  /* Initialize server and permissions */
  dog_serv_init(pawncc_path, input_path);

  /* Normalize whitespace in all paths */
  normalize_spaces(pawncc_path);
  normalize_spaces(input_path);
  normalize_spaces(output_path);
  
  if (dogconfig.dog_toml_full_opt != NULL) {
    normalize_spaces(dogconfig.dog_toml_full_opt);
  } /* if */
  
  if (pc_full_includes != NULL) {
    normalize_spaces(pc_full_includes);
  } /* if */
  
  if (pc_include_path != NULL) {
    normalize_spaces(pc_include_path);
  } /* if */

  options = dogconfig.dog_toml_full_opt;

  /* Build compiler command line string */
  ret_compiler = build_compiler_command(pawncc_path,
                      input_path,
                      output_path,
                      options);

  if (ret_compiler < 0) {
    pr_error(stdout, "dog_exec_compiler_tasks: failed to build command");
    minimal_debugging();
    return (-2);
  } /* if */
  
  if (ret_compiler >= (int)sizeof(pc_input)) {
    pr_error(stdout, "dog_exec_compiler_tasks: command too long (needed %d bytes)", ret_compiler);
    minimal_debugging();
    return (-2);
  } /* if */

  /* Platform-specific execution */
  #ifdef DOG_WINDOWS
    return execute_windows_compiler(pctx);
  #else /* Linux/Android */
    return execute_linux_compiler(pctx);
  #endif
} /* dog_exec_compiler_tasks */

#ifdef DOG_WINDOWS
// Windows server execution
void dog_exec_windows_server(char* binary) {
  STARTUPINFOA        _STARTUPINFO = { 0 };
  PROCESS_INFORMATION     _PROCESS_INFO = { 0 };
  char pbuf[DOG_PATH_MAX + 28] = {0};
  BOOL create_result = FALSE;
  
  /* Validate input parameter */
  if (binary == NULL) {
    pr_error(stdout, "dog_exec_windows_server: binary is NULL");
    return;
  } /* if */

#if defined(_DBG_PRINT)
  pr_info(stdout, "dog_exec_windows_server: starting Windows server: %s", binary);
#endif
  /* Initialize startup info */
  _STARTUPINFO.cb = sizeof(_STARTUPINFO);
  _STARTUPINFO.dwFlags = STARTF_USESTDHANDLES;
  _STARTUPINFO.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  _STARTUPINFO.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  _STARTUPINFO.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

  /* Build Windows path */
  (void)snprintf(pbuf, DOG_PATH_MAX, ".\\%s", binary);
#if defined(_DBG_PRINT)
  pr_info(stdout, "dog_exec_windows_server: full path: %s", pbuf);
#endif
  /* Create and run process */
  create_result = CreateProcessA(NULL,
                   pbuf,
                   NULL,
                   NULL,
                   TRUE,
                   0,
                   NULL,
                   NULL,
                   &_STARTUPINFO,
                   &_PROCESS_INFO);

  if (!create_result) {
    DWORD err = GetLastError();
    fprintf(stdout, "failed to CreateProcessA: %lu\n", err);
    pr_error(stdout, "dog_exec_windows_server: CreateProcess failed with code %lu", err);
    minimal_debugging();
  } else {
#if defined(_DBG_PRINT)
    pr_info(stdout, "dog_exec_windows_server: process created successfully");
#endif
    /* Wait for completion and cleanup */
    WaitForSingleObject(_PROCESS_INFO.hProcess, INFINITE);
#if defined(_DBG_PRINT)
    pr_info(stdout, "dog_exec_windows_server: process completed");
#endif
    CloseHandle(_PROCESS_INFO.hProcess);
    CloseHandle(_PROCESS_INFO.hThread);
#if defined(_DBG_PRINT)
    pr_info(stdout, "dog_exec_windows_server: handles closed");
#endif
  } /* if */
} /* dog_exec_windows_server */
#else
void dog_exec_windows_server(char* binary) {
  return;
} /* dog_exec_windows_server */
#endif

#if defined(DOG_LINUX) && ! defined DOG_ANDROID
// Linux server execution with pipe redirection using posix_spawn
void dog_exec_linux_server(char* binary) {
  pid_t process_id = -1;
  int ret = 0;
  int max_fd = 0;
  int stdout_fd = -1, stderr_fd = -1;
  ssize_t br = 0;
  char *argv[] = {pbuf, NULL};
  char *envp[] = {NULL};
  int stdout_pipe[2] = {-1, -1};
  int stderr_pipe[2] = {-1, -1};
  fd_set readfds;
  
  /* Validate input parameter */
  if (binary == NULL) {
    pr_error(stdout, "dog_exec_linux_server: binary is NULL");
    return;
  } /* if */

#if defined(_DBG_PRINT)
  pr_info(stdout, "dog_exec_linux_server: starting Linux server: %s", binary);
#endif
  /* Clear buffer */
  pbuf[0] = '\0';

  /* Build full path */
  (void)snprintf(pbuf, sizeof(pbuf), "%s%s%s",
    procure_pwd(), _PATH_STR_SEP_POSIX, binary);

#if defined(_DBG_PRINT)
  pr_info(stdout, "dog_exec_linux_server: full path: %s", pbuf);
#endif
  /* Create pipes for output capture */
  if (pipe(stdout_pipe) == -1) {
    pr_error(stdout, "dog_exec_linux_server: failed to create stdout pipe: %s", strerror(errno));
    return;
  } /* if */
  
  if (pipe(stderr_pipe) == -1) {
    pr_error(stdout, "dog_exec_linux_server: failed to create stderr pipe: %s", strerror(errno));
    close(stdout_pipe[0]);
    close(stdout_pipe[1]);
    return;
  } /* if */

  /* Prepare posix_spawn file actions for redirection */
  posix_spawn_file_actions_t file_actions;
  posix_spawn_file_actions_init(&file_actions);

  posix_spawn_file_actions_addclose(&file_actions, stdout_pipe[0]);
  posix_spawn_file_actions_addclose(&file_actions, stderr_pipe[0]);

  posix_spawn_file_actions_adddup2(&file_actions,
                   stdout_pipe[1],
                   STDOUT_FILENO);
  posix_spawn_file_actions_adddup2(&file_actions,
                   stderr_pipe[1],
                   STDERR_FILENO);

  posix_spawn_file_actions_addclose(&file_actions, stdout_pipe[1]);
  posix_spawn_file_actions_addclose(&file_actions, stderr_pipe[1]);

  /* Spawn process */
  ret = posix_spawn(&process_id, pbuf, &file_actions, NULL, argv, environ);

  /* Clean up file actions */
  posix_spawn_file_actions_destroy(&file_actions);

  /* Close parent's pipe write ends */
  close(stdout_pipe[1]);
  close(stderr_pipe[1]);

  if (ret != 0) {
    /* Spawn failed */
    pr_error(stdout, "dog_exec_linux_server: posix_spawn failed: %s", strerror(ret));
    close(stdout_pipe[0]);
    close(stderr_pipe[0]);
    return;
  } /* if */
  
  /* Parent process: read output from pipes */
  stdout_fd = stdout_pipe[0];
  stderr_fd = stderr_pipe[0];
  max_fd = ((stdout_fd) > (stderr_fd) ? (stdout_fd) : (stderr_fd)) + 1;

  /* Monitor both pipes */
  while (true) {
    FD_ZERO(&readfds);

    if (stdout_fd >= 0) {
      FD_SET(stdout_fd, &readfds);
    } /* if */
    
    if (stderr_fd >= 0) {
      FD_SET(stderr_fd, &readfds);
    } /* if */

    if (select(max_fd, &readfds, NULL, NULL, NULL) < 0) {
      pr_error(stdout, "dog_exec_linux_server: select failed: %s", strerror(errno));
      minimal_debugging();
      break;
    } /* if */

    /* Read from stdout pipe */
    if (stdout_fd >= 0 && FD_ISSET(stdout_fd, &readfds)) {
      br = read(stdout_fd, pbuf, sizeof(pbuf) - 1);
      if (br <= 0) {
        stdout_fd = -1;
      } else {
        pbuf[br] = '\0';
        fprintf(stdout, "%s", pbuf);
        fflush(stdout);
      } /* if */
    } /* if */
    
    /* Read from stderr pipe */
    if (stderr_fd >= 0 && FD_ISSET(stderr_fd, &readfds)) {
      br = read(stderr_fd, pbuf, sizeof(pbuf) - 1);
      if (br <= 0) {
        stderr_fd = -1;
      } else {
        pbuf[br] = '\0';
        fprintf(stderr, "%s", pbuf);
        fflush(stderr);
      } /* if */
    } /* if */

    /* Exit when both pipes are closed */
    if (stdout_fd < 0 && stderr_fd < 0) {
      break;
    } /* if */
  } /* while */

  /* Cleanup pipe read ends */
  close(stdout_pipe[0]);
  close(stderr_pipe[0]);
#if defined(_DBG_PRINT)
  pr_info(stdout, "dog_exec_linux_server: pipes closed");
#endif
  /* Wait for child and check status */
  int child_status;
  waitpid(process_id, &child_status, 0);

#if defined(_DBG_PRINT)
  if (WIFEXITED(child_status)) {
    fprintf(stdout, "process exited with code %d\n", WEXITSTATUS(child_status));
    pr_info(stdout, "dog_exec_linux_server: process exited with code %d", WEXITSTATUS(child_status));
  } else if (WIFSIGNALED(child_status)) {
    fprintf(stdout, "process killed by signal %d\n", WTERMSIG(child_status));
    pr_info(stdout, "dog_exec_linux_server: process killed by signal %d", WTERMSIG(child_status));
  } /* if */
#endif
} /* dog_exec_linux_server */
#else
void dog_exec_linux_server(char* binary) {
  return;
} /* dog_exec_linux_server */
#endif