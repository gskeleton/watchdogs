#include "utils.h"
#include "debug.h"
#include "compiler.h"
#include "process.h"

char    pc_input[DOG_MAX_PATH] = { 0 };	/* Compiler command input buffer */
char* pc_unix_token = NULL;	/* Unix token pointer for strtok */
char* pc_unix_args[DOG_MAX_PATH] = { NULL };	/* Argument array for exec */
#ifdef DOG_WINDOWS
static PROCESS_INFORMATION _PROCESS_INFO = { 0 };	/* Windows process information */
static STARTUPINFO         _STARTUPINFO = { 0 };	/* Windows startup information */
static SECURITY_ATTRIBUTES _ATTRIBUTES = { 0 };	/* Windows security attributes */
#endif
/* Initialize log file path based on platform */
#ifdef DOG_WINDOWS
#define COMPILER_LOG ".watchdogs\\compiler.log"
#else
#define COMPILER_LOG ".watchdogs/compiler.log"
#endif

static
long pc_get_milisec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return
        ts.tv_sec * 1000 +
        ts.tv_nsec / 1000000;
}

static
void pc_stage_trying(const char* stage, int ms) {
    long start;
    start = pc_get_milisec();
    while (pc_get_milisec() - start < ms) {
        char buf[128];
        int len = snprintf(buf, sizeof(buf), "\r%s....", stage);
        fwrite(buf, 1, len, stdout);
        fflush(stdout);
    }
    if (strfind(stage, ".. user's script", true) == true) {
        print("\r\033[2K");

        static const char* amx_stage_lines[] = {
            "  o implicit include file\n"
            "  o user include file(s)\n"
            "  o user's script\n"
            DOG_COL_DEFAULT
            "** Preparing all tasks..\n",
            NULL
        };

        print(DOG_COL_BCYAN);
        int i;
        for (i = 0; amx_stage_lines[i]; ++i) {
            print(amx_stage_lines[i]);
        }
        print(DOG_COL_DEFAULT);
    }
}

static
void dog_serv_init(char* input_path, char* pawncc_path) {

    static bool permissions_initialized = false;
    if (permissions_initialized == false) {
        if (path_exists("gamemodes") == 1)
            __set_default_access("gamemodes");
        if (path_exists("pawno") == 1)
        {
            __set_default_access("pawno");
            if (path_exists("pawno/include"))
                __set_default_access("pawno/include");
        }
        if (path_exists("qawno") == 1)
        {
            __set_default_access("qawno");
            if (path_exists("qawno/include"))
                __set_default_access("qawno/include");
        }
        __set_default_access(pawncc_path);
        __set_default_access(input_path);
        permissions_initialized = true;
    }

    print("** Thinking all tasks..\n");
    static bool pc_pipe_info = false;
    if (pc_pipe_info == false) {
        pc_pipe_info = true;
        pc_stage_trying(".. implicit include file", 60);
        pc_stage_trying(".. user include file(s)", 60);
        pc_stage_trying(".. user's script", 60);
    } else {
        static const char* amx_stage_lines[] = {
            "  o implicit include file\n"
            "  o user include file(s)\n"
            "  o user's script\n"
            DOG_COL_DEFAULT
            "** Preparing all tasks..\n",
            NULL
        };

        print(DOG_COL_BCYAN);
        for (int i = 0; amx_stage_lines[i]; ++i) {
            print(amx_stage_lines[i]);
        }
        print(DOG_COL_DEFAULT);
    }
}

#ifdef DOG_LINUX
static
void configure_line_parsing(void) {
    char*   p = pc_input;
    int     arg_count = 0;
    char    current_token[DOG_MAX_PATH] = { 0 };
    int     token_pos = 0;
    int     inside_quotes = 0;
    while (*p) {
        if (*p == '"') {
            inside_quotes = !inside_quotes;
            p++;
            continue;
        }
        if (*p == ' ' && !inside_quotes) {
            if (token_pos > 0) {
                current_token[token_pos] = '\0';
                pc_unix_args[arg_count++]
                    = strdup(current_token);
                token_pos = 0;
            }
            p++;
            continue;
        }
        current_token[token_pos++]
            = *p++;
    }
    if (token_pos > 0) {
        current_token[token_pos] = '\0';
        pc_unix_args[arg_count++]
            = strdup(current_token);
    }
    pc_unix_args[arg_count] = NULL;
}
#endif

#ifdef DOG_WINDOWS
// Thread function for fast compilation using _beginthreadex
static unsigned __stdcall
pc_thread_func(void* arg) {
    pc_thread_data_t* data = (pc_thread_data_t*)arg;
    BOOL win32_process_success;

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

    DWORD err = GetLastError();

    if (data->hFile != INVALID_HANDLE_VALUE) {
        SetHandleInformation(data->hFile,
            HANDLE_FLAG_INHERIT, 0);
    }

    if (win32_process_success == TRUE) {
        SetThreadPriority(
            data->process_info->hThread,
            THREAD_PRIORITY_ABOVE_NORMAL);

        DWORD_PTR procMask, sysMask;
        GetProcessAffinityMask(
            GetCurrentProcess(),
            &procMask, &sysMask);
        SetProcessAffinityMask(
            data->process_info->hProcess,
            procMask & ~1);

        clock_gettime(CLOCK_MONOTONIC,
            data->pre_start);
        DWORD waitResult =
            WaitForSingleObject(
                data->process_info->hProcess,
                4096);
        switch (waitResult) {
        case WAIT_TIMEOUT:
            TerminateProcess(
                _PROCESS_INFO.hProcess, 1);
            WaitForSingleObject(
                _PROCESS_INFO.hProcess,
                5000);
        }
        clock_gettime(CLOCK_MONOTONIC,
            data->post_end);

        DWORD proc_exit_code;
        /* Retrieve process exit code for error reporting */
        GetExitCodeProcess(
            data->process_info->hProcess,
            &proc_exit_code);
#if defined(_DBG_PRINT)
        pr_info(stdout,
            "windows process exit with code: %lu",
            proc_exit_code);
        if (
            proc_exit_code ==
            3221225781)
        {
            pr_info(stdout,
                data->windows_redist_err);
            char pbuf[strlen(data->windows_redist_err2) + 1];
            int len = snprintf(pbuf, sizeof(pbuf),
                "%s", data->windows_redist_err2);
            fwrite(pbuf, 1, len, stdout);
            fflush(stdout);
        }
#endif
        CloseHandle(data->process_info->hThread);
        CloseHandle(data->process_info->hProcess);

        if (data->startup_info->hStdOutput != NULL &&
            data->startup_info->hStdOutput != data->hFile)
            CloseHandle(
                data->startup_info->hStdOutput);
        if (data->startup_info->hStdError != NULL &&
            data->startup_info->hStdError != data->hFile)
            CloseHandle(
                data->startup_info->hStdError);
    }
    else {
        pr_error(stdout,
            "CreateProcess failed! (%lu)",
            err);
        if (strfind(strerror(err), "The system cannot find the file specified", true))
            pr_error(stdout, "^ The compiler executable does not exist.");
        if (strfind(strerror(err), "Access is denied", true))
            pr_error(stdout, "^ You do not have permission to execute the compiler executable.");
        if (strfind(strerror(err), "The directory name is invalid", true))
            pr_error(stdout, "^ The compiler executable is not a directory.");
        if (strfind(strerror(err), "The system cannot find the path specified", true))
            pr_error(stdout, "^ The compiler executable does not exist.");
        minimal_debugging();
    }

    return (0);
}
#endif

static int build_compiler_command(char* pawncc_path, char* input_path,
    char* output_path, char* options) {
    return snprintf(pc_input, sizeof(pc_input),
        "%s \"%s\" \"-o%s\" %s %s %s",
        pawncc_path, input_path, output_path,
        options, pc_full_includes, pc_include_path);
}

static void display_compiler_command(void) {
    if (pc_input_info == true) {
#ifdef DOG_ANDROID
        println(stdout, "** %s", pc_input);
#else
        dog_console_title(pc_input);
        println(stdout, "** %s", pc_input);
#endif
    }
}

#ifdef DOG_WINDOWS
// Windows-specific: Create log file handle
static HANDLE create_windows_log_file(void) {
    return CreateFileA(
        COMPILER_LOG,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        &_ATTRIBUTES,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL |
        FILE_FLAG_SEQUENTIAL_SCAN |
        FILE_ATTRIBUTE_TEMPORARY,
        NULL);
}

// Windows-specific: Initialize startup info
static void init_windows_startup_info(HANDLE hFile) {
    _STARTUPINFO.cb = sizeof(_STARTUPINFO);
    _STARTUPINFO.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    _STARTUPINFO.wShowWindow = SW_HIDE;

    if (hFile != INVALID_HANDLE_VALUE) {
        _STARTUPINFO.hStdOutput = hFile;
        _STARTUPINFO.hStdError = hFile;
    }
    _STARTUPINFO.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
}

// Windows-specific: Execute compiler with CreateProcess
static int execute_windows_compiler_standard(HANDLE hFile, io_compilers* pctx,
    const char* windows_redist_err,
    const char* windows_redist_err2) {
    BOOL win32_process_success;

    win32_process_success = CreateProcessA(
        NULL, pc_input,
        NULL, NULL,
        TRUE,
        CREATE_NO_WINDOW |
        ABOVE_NORMAL_PRIORITY_CLASS |
        CREATE_BREAKAWAY_FROM_JOB,
        NULL, NULL,
        &_STARTUPINFO, &_PROCESS_INFO);

    DWORD err = GetLastError();

    if (hFile != INVALID_HANDLE_VALUE) {
        SetHandleInformation(hFile, HANDLE_FLAG_INHERIT, 0);
    }

    if (win32_process_success == TRUE) {
        SetThreadPriority(_PROCESS_INFO.hThread, THREAD_PRIORITY_ABOVE_NORMAL);

        DWORD_PTR procMask, sysMask;
        GetProcessAffinityMask(GetCurrentProcess(), &procMask, &sysMask);
        SetProcessAffinityMask(_PROCESS_INFO.hProcess, procMask & ~1);

        clock_gettime(CLOCK_MONOTONIC, &pre_start);
        DWORD waitResult = WaitForSingleObject(_PROCESS_INFO.hProcess, 4096);

        switch (waitResult) {
        case WAIT_TIMEOUT:
            TerminateProcess(_PROCESS_INFO.hProcess, 1);
            WaitForSingleObject(_PROCESS_INFO.hProcess, 5000);
        }
        clock_gettime(CLOCK_MONOTONIC, &post_end);

        DWORD proc_exit_code;
        GetExitCodeProcess(_PROCESS_INFO.hProcess, &proc_exit_code);

#if defined(_DBG_PRINT)
        pr_info(stdout, "windows process exit with code: %lu", proc_exit_code);
        if (proc_exit_code == 3221225781) {
            pr_info(stdout, windows_redist_err);
            char pbuf[strlen(data->windows_redist_err2) + 1];
            int len = snprintf(pbuf, sizeof(pbuf),
                "%s", data->windows_redist_err2);
            fwrite(pbuf, 1, len, stdout);
            fflush(stdout);
        }
#endif

        CloseHandle(_PROCESS_INFO.hThread);
        CloseHandle(_PROCESS_INFO.hProcess);

        if (_STARTUPINFO.hStdOutput != NULL && _STARTUPINFO.hStdOutput != hFile)
            CloseHandle(_STARTUPINFO.hStdOutput);
        if (_STARTUPINFO.hStdError != NULL && _STARTUPINFO.hStdError != hFile)
            CloseHandle(_STARTUPINFO.hStdError);
    }
    else {
        pr_error(stdout, "CreateProcess failed! (%lu)", err);
        if (strfind(strerror(err), "The system cannot find the file specified", true))
            pr_error(stdout, "^ The compiler executable does not exist.");
        if (strfind(strerror(err), "Access is denied", true))
            pr_error(stdout, "^ You do not have permission to execute the compiler executable.");
        if (strfind(strerror(err), "The directory name is invalid", true))
            pr_error(stdout, "^ The compiler executable is not a directory.");
        if (strfind(strerror(err), "The system cannot find the path specified", true))
            pr_error(stdout, "^ The compiler executable does not exist.");
        minimal_debugging();
    }

    return 0;
}

// Windows-specific: Execute compiler with thread (fast mode)
static int execute_windows_compiler_fast(HANDLE hFile, io_compilers* pctx,
    const char* windows_redist_err,
    const char* windows_redist_err2) {
    pc_thread_data_t thread_data;
    HANDLE thread_handle;
    unsigned thread_id;

    thread_data.pc_input = pc_input;
    thread_data.startup_info = &_STARTUPINFO;
    thread_data.process_info = &_PROCESS_INFO;
    thread_data.hFile = hFile;
    thread_data.pre_start = &pre_start;
    thread_data.post_end = &post_end;
    thread_data.windows_redist_err = windows_redist_err;
    thread_data.windows_redist_err2 = windows_redist_err2;

    thread_handle = (HANDLE)_beginthreadex(NULL, 0, pc_thread_func, &thread_data, 0, &thread_id);

    if (thread_handle == NULL) {
        pr_error(stdout, "_beginthreadex failed!");
        minimal_debugging();
        return -1;
    }
    else {
        WaitForSingleObject(thread_handle, INFINITE);
        CloseHandle(thread_handle);
    }

    return 0;
}

// Windows-specific: Execute compiler task
static int execute_windows_compiler(io_compilers* pctx) {
    const char* windows_redist_err =
        "Have you made sure to install the Visual CPP (C++) Redist All-in-One?";
    const char* windows_redist_err2 =
        "   - install first: https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/\n";

    _ATTRIBUTES.nLength = sizeof(_ATTRIBUTES);
    _ATTRIBUTES.bInheritHandle = TRUE;
    _ATTRIBUTES.lpSecurityDescriptor = NULL;

    HANDLE hFile = create_windows_log_file();
    init_windows_startup_info(hFile);

    display_compiler_command();

    int result = 0;
    if (pctx->flag_fast == true) {
        result = execute_windows_compiler_fast(hFile, pctx, windows_redist_err, windows_redist_err2);
    }
    else {
        result = execute_windows_compiler_standard(hFile, pctx, windows_redist_err, windows_redist_err2);
    }

    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }

    return result;
}
#endif /* DOG_WINDOWS */

#ifdef DOG_LINUX
// Linux-specific: Free unix args
static void free_unix_args(void) {
    for (int i = 0; pc_unix_args[i]; i++) {
        free(pc_unix_args[i]);
    }
}

#ifdef DOG_ANDROID
// Android-specific: Execute compiler using fork/vfork
static int execute_android_compiler(io_compilers* pctx) {
    static bool vfork_mode = false;
    if (pctx->flag_fast == 1) {
        vfork_mode = true;
    }

    pid_t pc_process_id;
    if (vfork_mode == false) {
        pc_process_id = fork();
    }
    else {
        pc_process_id = vfork();
    }

    if (pc_process_id == 0) {
        int logging_file = open(COMPILER_LOG, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (logging_file != -1) {
            dup2(logging_file, STDOUT_FILENO);
            dup2(logging_file, STDERR_FILENO);
            close(logging_file);
        }
        execv(pc_unix_args[0], pc_unix_args);
        fprintf(stderr, "execv failed: %s\n", strerror(errno));
        _exit(127);
    }
    else if (pc_process_id > 0) {
        int process_status;
        int process_timeout_occurred = 0;
        clock_gettime(CLOCK_MONOTONIC, &pre_start);

        for (int k = 0; k < 4096; k++) {
            int proc_result = waitpid(pc_process_id, &process_status, WNOHANG);
            if (proc_result == 0) {
                usleep(100000); /* 100ms sleep between polls */
            }
            else if (proc_result == pc_process_id) {
                break;
            }
            else {
                pr_error(stdout, "waitpid error");
                minimal_debugging();
                break;
            }

            if (k == 4096 - 1) {
                kill(pc_process_id, SIGTERM);
                sleep(2);
                kill(pc_process_id, SIGKILL);
                pr_error(stdout, "process execution timeout! (%d seconds)", 4096);
                minimal_debugging();
                waitpid(pc_process_id, &process_status, 0);
                process_timeout_occurred = 1;
            }
        }

        clock_gettime(CLOCK_MONOTONIC, &post_end);

        if (!process_timeout_occurred) {
            if (WIFEXITED(process_status)) {
                int proc_exit_code = WEXITSTATUS(process_status);
                if (proc_exit_code != 0 && proc_exit_code != 1) {
                    pr_error(stdout, "compiler process exited with code (%d)", proc_exit_code);
                    minimal_debugging();
                }
            }
            else if (WIFSIGNALED(process_status)) {
                pr_error(stdout, "compiler process terminated by signal (%d)", WTERMSIG(process_status));
            }
        }
    }
    else {
        pr_error(stdout, "process creation failed: %s", strerror(errno));
        minimal_debugging();
    }

    return 0;
}
#else /* !DOG_ANDROID */
// Linux (non-Android)-specific: Execute compiler using posix_spawn
static int execute_linux_compiler_posix(io_compilers* pctx,
    const char* windows_redist_err,
    const char* windows_redist_err2) {
    posix_spawn_file_actions_t process_file_actions;
    posix_spawn_file_actions_init(&process_file_actions);

    int posix_logging_file = open(COMPILER_LOG, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (posix_logging_file != -1) {
        posix_spawn_file_actions_adddup2(&process_file_actions, posix_logging_file, STDOUT_FILENO);
        posix_spawn_file_actions_adddup2(&process_file_actions, posix_logging_file, STDERR_FILENO);
        posix_spawn_file_actions_addclose(&process_file_actions, posix_logging_file);
    }

    posix_spawnattr_t spc_attr;
    posix_spawnattr_init(&spc_attr);

    sigset_t sigmask;
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGCHLD);
    posix_spawnattr_setsigmask(&spc_attr, &sigmask);

    sigset_t sigdefault;
    sigemptyset(&sigdefault);
    sigaddset(&sigdefault, SIGPIPE);
    sigaddset(&sigdefault, SIGINT);
    sigaddset(&sigdefault, SIGTERM);
    posix_spawnattr_setsigdefault(&spc_attr, &sigdefault);

    short flags = POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
    posix_spawnattr_setflags(&spc_attr, flags);

    pid_t pc_process_id;
    int process_spc_result = posix_spawn(&pc_process_id, pc_unix_args[0],
        &process_file_actions, &spc_attr,
        pc_unix_args, environ);

    if (posix_logging_file != -1) {
        close(posix_logging_file);
    }

    posix_spawnattr_destroy(&spc_attr);
    posix_spawn_file_actions_destroy(&process_file_actions);

    if (process_spc_result == 0) {
        int process_status;
        int process_timeout_occurred = 0;
        clock_gettime(CLOCK_MONOTONIC, &pre_start);

        for (int k = 0; k < 4096; k++) {
            int proc_result = waitpid(pc_process_id, &process_status, WNOHANG);
            if (proc_result == 0)
                usleep(50000); /* 50ms sleep between polls */
            else if (proc_result == pc_process_id) {
                break;
            }
            else {
                pr_error(stdout, "waitpid error");
                minimal_debugging();
                break;
            }

            if (k == 4096 - 1) {
                kill(pc_process_id, SIGTERM);
                sleep(2);
                kill(pc_process_id, SIGKILL);
                pr_error(stdout, "posix_spawn process execution timeout! (%d seconds)", 4096);
                minimal_debugging();
                waitpid(pc_process_id, &process_status, 0);
                process_timeout_occurred = 1;
            }
        }

        clock_gettime(CLOCK_MONOTONIC, &post_end);

        if (!process_timeout_occurred) {
            if (WIFEXITED(process_status)) {
                int proc_exit_code = WEXITSTATUS(process_status);
                if (proc_exit_code != 0 && proc_exit_code != 1) {
                    pr_error(stdout, "compiler process exited with code (%d)", proc_exit_code);
                    if (getenv("WSL_DISTRO_NAME") &&
                        strcmp(dogconfig.dog_toml_os_type, OS_SIGNAL_WINDOWS) == 0 &&
                        proc_exit_code == 53) {
                        pr_info(stdout, windows_redist_err);
                        char pbuf[strlen(windows_redist_err2) + 1];
                        int len = snprintf(pbuf, sizeof(pbuf),
                            "%s", windows_redist_err2);
                        fwrite(pbuf, 1, len, stdout);
                        fflush(stdout);
                    }
                    minimal_debugging();
                }
            }
            else if (WIFSIGNALED(process_status)) {
                pr_error(stdout, "compiler process terminated by signal (%d)", WTERMSIG(process_status));
            }
        }
    }
    else {
        pr_error(stdout, "posix_spawn failed: %s", strerror(process_spc_result));
        if (strfind(strerror(process_spc_result), "Exec format error", true))
            pr_error(stdout, "^ The compiler executable is not compatible with your system.");
        if (strfind(strerror(process_spc_result), "Permission denied", true))
            pr_error(stdout, "^ You do not have permission to execute the compiler executable.");
        if (strfind(strerror(process_spc_result), "No such file or directory", true))
            pr_error(stdout, "^ The compiler executable does not exist.");
        if (strfind(strerror(process_spc_result), "Not a directory", true))
            pr_error(stdout, "^ The compiler executable is not a directory.");
        if (strfind(strerror(process_spc_result), "Is a directory", true))
            pr_error(stdout, "^ The compiler executable is a directory.");
        minimal_debugging();
    }

    return 0;
}

// Linux-specific: Execute compiler task
static int execute_linux_compiler(io_compilers* pctx) {
    const char* windows_redist_err =
        "Have you made sure to install the Visual CPP (C++) Redist All-in-One?";
    const char* windows_redist_err2 =
        "   - install first: https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/\n";

    configure_line_parsing();
    display_compiler_command();

    int result;
#ifdef DOG_ANDROID
    result = execute_android_compiler(pctx);
#else
    result = execute_linux_compiler_posix(pctx, windows_redist_err, windows_redist_err2);
#endif

    free_unix_args();
    return result;
}
#endif /* !DOG_ANDROID */
#endif /* DOG_LINUX */

// Main compiler execution function - dispatches to platform-specific implementations
int dog_exec_compiler_tasks(char* pawncc_path, char* input_path, char* output_path) {
    static io_compilers dog_pc_sys;
    io_compilers all_pc_field;
    io_compilers* pctx = &all_pc_field;
#ifdef DOG_WINDOWS
    memset(&_PROCESS_INFO, 0, sizeof(_PROCESS_INFO));
    memset(&_STARTUPINFO, 0, sizeof(_STARTUPINFO));
    memset(&_ATTRIBUTES, 0, sizeof(_ATTRIBUTES));
#endif

    if (is_binary_file(pawncc_path) == false) {
        return (-2);
    }

    print(DOG_COL_YELLOW "-----------------------------\n" DOG_COL_DEFAULT);

    pc_unix_token = NULL;
    memset(pc_input, 0, sizeof(pc_input));
    memset(pc_unix_args, 0, sizeof(pc_unix_args));

    int ret_compiler = 0;

    if (pc_full_includes == NULL)
        pc_full_includes = "-i=\"pawno/include\" -i=\"qawno/include\" -i=\"gamemodes\"";

    dog_serv_init(pawncc_path, input_path);

    /* Normalize Whitespace */
    normalize_spaces(pawncc_path);
    normalize_spaces(input_path);
    normalize_spaces(output_path);
    normalize_spaces(dogconfig.dog_toml_full_opt);
    normalize_spaces(pc_full_includes);
    normalize_spaces(pc_include_path);

    char* options = dogconfig.dog_toml_full_opt;

    /* Build compiler command line string */
    ret_compiler = build_compiler_command(pawncc_path, input_path, output_path, options);

    if (ret_compiler < 0 || ret_compiler >= sizeof(pc_input)) {
        pr_error(stdout, "ret_compiler too long!");
        minimal_debugging();
        return (-2);
    }

    /* Platform-specific execution */
    #ifdef DOG_WINDOWS
        return execute_windows_compiler(pctx);
    #else /* Linux/Android */
        return execute_linux_compiler(pctx);
    #endif
}

#ifdef DOG_WINDOWS
// Windows server execution
void dog_exec_windows_server(char* binary) {
    STARTUPINFOA              _STARTUPINFO = { 0 };
    PROCESS_INFORMATION       _PROCESS_INFO = { 0 };

    /* Initialize startup info */
    _STARTUPINFO.cb = sizeof(_STARTUPINFO);
    _STARTUPINFO.dwFlags = STARTF_USESTDHANDLES;
    _STARTUPINFO.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    _STARTUPINFO.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    _STARTUPINFO.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    char pbuf[DOG_PATH_MAX + 28];

    /* Build Windows path */
    (void)snprintf(pbuf, DOG_PATH_MAX, ".\\%s", binary);

    /* Create and run process */
    if (!CreateProcessA(NULL, pbuf, NULL, NULL, TRUE, 0, NULL, NULL, &_STARTUPINFO, &_PROCESS_INFO)) {
        fprintf(stdout, "failed to CreateProcessA..");
        minimal_debugging();
    }
    else {
        /* Wait for completion and cleanup */
        WaitForSingleObject(_PROCESS_INFO.hProcess, INFINITE);
        CloseHandle(_PROCESS_INFO.hProcess);
        CloseHandle(_PROCESS_INFO.hThread);
    }
}
#else
void dog_exec_windows_server(char* binary) {
    return;
}
#endif

#ifdef DOG_LINUX
// Linux server execution with pipe redirection
void dog_exec_linux_server(char* binary) {
    pid_t process_id;

    char pbuf[DOG_PATH_MAX + 28];

    /* Build full path */
    (void)snprintf(pbuf, DOG_PATH_MAX, "%s%s%s",
        dog_procure_pwd(), _PATH_STR_SEP_POSIX, binary);

    int stdout_pipe[2], stderr_pipe[2];

    /* Create pipes for output capture */
    if (pipe(stdout_pipe) == -1 || pipe(stderr_pipe) == -1) {
        perror("pipe");
        return;
    }

    process_id = fork();
    if (process_id == 0) {
        /* Child process: setup redirection */
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);

        /* Execute server */
        execl(pbuf, pbuf, (char*)NULL);

        /* If we get here, exec failed */
        perror("execl failed");
        fprintf(stderr, "errno = %d\n", errno);

        int child_status;
        waitpid(process_id, &child_status, 0);
        if (WIFEXITED(child_status)) {
            fprintf(stdout, "process exited with code %d\n", WEXITSTATUS(child_status));
        }
        else if (WIFSIGNALED(child_status)) {
            fprintf(stdout, "process killed by signal %d\n", WTERMSIG(child_status));
        }

        _exit(127);
    } else if (process_id > 0) {
        /* Parent process: read output from pipes */
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);

        int stdout_fd;
        int stderr_fd;
        ssize_t br;
        stdout_fd = stdout_pipe[0];
        stderr_fd = stderr_pipe[0];
        int max_fd = (stdout_fd > stderr_fd ? stdout_fd : stderr_fd) + 1;

        fd_set readfds;

        pbuf[0] = '\0';

        /* Monitor both pipes */
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

            /* Read stdout */
            if (stdout_fd >= 0 && FD_ISSET(stdout_fd, &readfds)) {
                br = read(stdout_fd, pbuf, sizeof(pbuf) - 1);
                if (br <= 0) {
                    stdout_fd = -1;
                } else {
                    pbuf[br] = '\0';
                    fprintf(stdout, "%s", pbuf);
                }
            }

            /* Read stderr */
            if (stderr_fd >= 0 && FD_ISSET(stderr_fd, &readfds)) {
                br = read(stderr_fd, pbuf, sizeof(pbuf) - 1);
                if (br <= 0) {
                    stderr_fd = -1;
                } else {
                    pbuf[br] = '\0';
                    fprintf(stderr, "%s", pbuf);
                }
            }

            /* Exit when both pipes are closed */
            if (stdout_fd < 0 && stderr_fd < 0) break;
        }

        /* Cleanup */
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
    }
}
#else
void dog_exec_linux_server(char* binary) {
    return;
}
#endif