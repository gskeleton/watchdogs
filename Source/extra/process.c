#include "../utils.h"
#include "debug.h"
#include "../compiler.h"
#include "process.h"

char    pawn_input[DOG_MAX_PATH] = { 0 };	/* Compiler command input buffer */
char   *pawn_unix_token = NULL;	/* Unix token pointer for strtok */
char   *pawn_unix_args[DOG_MAX_PATH] = { NULL };	/* Argument array for exec */
#ifdef DOG_WINDOWS
PROCESS_INFORMATION _PROCESS_INFO;	/* Windows process information */
STARTUPINFO         _STARTUPINFO;	/* Windows startup information */
SECURITY_ATTRIBUTES _ATTRIBUTES;	/* Windows security attributes */
#endif

long pawn_get_milisec() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return
    	ts.tv_sec * 1000 +
    	ts.tv_nsec / 1000000;
}

void pawn_stage_trying(const char *stage, int ms) {
	long start = pawn_get_milisec();
	while (pawn_get_milisec() - start < ms) {
		printf("\r%s....", stage);
		fflush(stdout);
	}
	if (strcmp(stage, ".. user's script") == 0) {
		printf("\r\033[2K");
        fflush(stdout);
		static const char *amx_stage_lines[] = {
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

void dog_serv_init(char *input_path, char *pawncc_path) {

	static bool rate_init_proc = false;
	if (rate_init_proc == false) {
		if ( path_exists("gamemodes") == 1 )
			__set_default_access("gamemodes");
		if ( path_exists("pawno") == 1 )
		{
			__set_default_access("pawno");
			if (path_exists("pawno/include"))
				__set_default_access("pawno/include");
		}
		if ( path_exists("qawno") == 1 )
		{
			__set_default_access("qawno");
			if (path_exists("qawno/include"))
				__set_default_access("qawno/include");
		}
		__set_default_access( pawncc_path );
		__set_default_access( input_path );
		rate_init_proc = true;
	}

    print(      "** Thinking all tasks..\n");
	static bool pawn_pipe_info = false;
	if (pawn_pipe_info == false) {
		pawn_pipe_info = !pawn_pipe_info;
		pawn_stage_trying(".. implicit include file", 60);
		pawn_stage_trying(".. user include file(s)", 60);
		pawn_stage_trying(".. user's script", 60);
	} else {
		static const char *amx_stage_lines[] = {
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

    fflush(stdout);
}

#ifdef DOG_WINDOWS
	// Thread function for fast compilation using _beginthreadex
static unsigned __stdcall
pawn_thread_func(void *arg) {
	pawn_thread_data_t *data = (pawn_thread_data_t *)arg;
	BOOL win32_process_success;

	/* Create Windows process for compiler execution */
	win32_process_success = CreateProcessA(
		NULL, data->pawn_input,
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
			0x3E8000);
		switch(waitResult) {
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
			printf("%s", data->windows_redist_err2);
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
	} else {
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

int dog_exec_pawn_process(char *pawncc_path,
							  char *input_path,
							  char *output_path) {

    if (binary_condition_check(pawncc_path) == false) {
        return (-2);
    }

	if (false != pawn_opt_clean) {
		pr_info(stdout,
			"Place #pragma option -Z+ at "
			"the top of %s if needed or if "
			"you're running into unexpected errors.", input_path);
	}
	
    print(DOG_COL_YELLOW "-----------------------------\n" DOG_COL_DEFAULT);

	pawn_unix_token = NULL;
	memset(pawn_input, 0, sizeof(pawn_input));
	memset(pawn_unix_args, 0, sizeof(pawn_unix_args));

	int         result_configure = 0;
	#ifdef DOG_LINUX
	int         i = 0;
	char       *unix_pointer_token = NULL;
	#endif
	const char *windows_redist_err = /* 0 */"Have you made sure to install "
					/* 1 */			  "the Visual CPP (C++) "
					/* 2 */				"Redist All-in-One?";
	const char *windows_redist_err2 = /* 0 */ "   - install first: "
	/* 1 */								"https://www.techpowerup.com/"
	/* 2 */								"download/"
	/* 3 */								"visual-c-redistributable-"
	/* 4 */								"runtime-package-all-in-one"
	/* 5 */								"/"
	/* 7 newline */				        "\n";

	if (pawn_full_includes == NULL)
		pawn_full_includes =
      strdup("-ipawno/include -iqawno/include -igamemodes");

	dog_serv_init(pawncc_path, input_path);

    /* Normalize Whitespace */
    normalize_spaces(pawncc_path);
    normalize_spaces(input_path);
    normalize_spaces(output_path);
    normalize_spaces(dogconfig.dog_toml_all_flags);
    normalize_spaces(pawn_full_includes);
    normalize_spaces(pawn_include_path);
	
	/* Build compiler command line string */
	result_configure = snprintf(pawn_input,
		sizeof(pawn_input), "%s \"%s\" \"-o%s\" %s %s %s",
		/// ./.\path/path/pawncc a.pwn -oa.amx -d:3 -i=pawno/include
		pawncc_path, // pawncc
		input_path, // input
		output_path, // output
		dogconfig.dog_toml_all_flags, // flag
		pawn_full_includes, // includes
		pawn_include_path); // includes
    
	/* Initialize log file path based on platform */
	#ifdef DOG_WINDOWS
	#define COMPILER_LOG ".watchdogs\\compiler.log"
	#else
	#define COMPILER_LOG ".watchdogs/compiler.log"
	#endif

	#ifdef DOG_WINDOWS
		ZeroMemory(&_STARTUPINFO,
			sizeof(_STARTUPINFO));
		_STARTUPINFO.cb = sizeof(_STARTUPINFO);

		ZeroMemory(&_ATTRIBUTES, sizeof(_ATTRIBUTES));
		_ATTRIBUTES.nLength = sizeof(_ATTRIBUTES);
		_ATTRIBUTES.bInheritHandle = TRUE;
		_ATTRIBUTES.lpSecurityDescriptor = NULL;

		ZeroMemory(&_PROCESS_INFO,
			sizeof(_PROCESS_INFO));

		HANDLE hFile = CreateFileA(
			COMPILER_LOG,
			GENERIC_WRITE,
			FILE_SHARE_READ,
			&_ATTRIBUTES,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL |
			FILE_FLAG_SEQUENTIAL_SCAN |
			FILE_ATTRIBUTE_TEMPORARY,
			NULL);

		_STARTUPINFO.dwFlags = STARTF_USESTDHANDLES |
			STARTF_USESHOWWINDOW;
		_STARTUPINFO.wShowWindow = SW_HIDE;

		if (hFile != INVALID_HANDLE_VALUE) {
			_STARTUPINFO.hStdOutput = hFile;
			_STARTUPINFO.hStdError = hFile;
		}
		_STARTUPINFO.hStdInput = GetStdHandle(
			STD_INPUT_HANDLE);

		if (pawn_input_info == true) {
		#ifdef DOG_ANDROID
			println(stdout, "** %s", pawn_input);
		#else
			dog_console_title(pawn_input);
			println(stdout, "** %s", pawn_input);
		#endif
		}

		if (result_configure < 0 ||
			result_configure >= sizeof(pawn_input)) {
			pr_error(stdout,
				"ret_compiler too long!");
			minimal_debugging();
			return (-2);
		}

		/* Create Windows process for compiler execution */
		if (pawn_opt_fast == true) {
			/* Use _beginthreadex for fast compilation */
			pawn_thread_data_t thread_data;
			HANDLE thread_handle;
			unsigned thread_id;

			thread_data.pawn_input        = pawn_input;
			thread_data.startup_info          = &_STARTUPINFO;
			thread_data.process_info          = &_PROCESS_INFO;
			thread_data.hFile                 = hFile;
			thread_data.pre_start             = &pre_start;
			thread_data.post_end              = &post_end;
			thread_data.windows_redist_err    = windows_redist_err;
			thread_data.windows_redist_err2   = windows_redist_err2;

			thread_handle = (HANDLE)_beginthreadex(
				NULL,
				0,
				pawn_thread_func,
				&thread_data,
				0,
				&thread_id);

			if (thread_handle == NULL) {
				pr_error(stdout,
					"_beginthreadex failed!");
				minimal_debugging();
			} else {
				/* Wait for thread to complete */
				WaitForSingleObject(thread_handle, INFINITE);
				CloseHandle(thread_handle);
			}
		} else {
			/* Standard CreateProcess approach */
			BOOL win32_process_success;
			win32_process_success = CreateProcessA(
				NULL, pawn_input,
				NULL, NULL,
				TRUE,
				CREATE_NO_WINDOW |
				ABOVE_NORMAL_PRIORITY_CLASS |
				CREATE_BREAKAWAY_FROM_JOB,
				NULL, NULL,
				&_STARTUPINFO, &_PROCESS_INFO);

			DWORD err = GetLastError();

			if (hFile != INVALID_HANDLE_VALUE) {
				SetHandleInformation(hFile,
					HANDLE_FLAG_INHERIT, 0);
			}

			if (win32_process_success == TRUE) {
				SetThreadPriority(
					_PROCESS_INFO.hThread,
					THREAD_PRIORITY_ABOVE_NORMAL);

				DWORD_PTR procMask, sysMask;
				GetProcessAffinityMask(
					GetCurrentProcess(),
					&procMask, &sysMask);
				SetProcessAffinityMask(
					_PROCESS_INFO.hProcess,
					procMask & ~1);

				clock_gettime(CLOCK_MONOTONIC,
					&pre_start);
				DWORD waitResult =
					WaitForSingleObject(
					_PROCESS_INFO.hProcess,
					0x3E8000);
				switch(waitResult) {
				case WAIT_TIMEOUT:
					TerminateProcess(
						_PROCESS_INFO.hProcess, 1);
					WaitForSingleObject(
						_PROCESS_INFO.hProcess,
						5000);
				}
				clock_gettime(CLOCK_MONOTONIC,
					&post_end);

				DWORD proc_exit_code;
				/* Retrieve process exit code for error reporting */
				GetExitCodeProcess(
					_PROCESS_INFO.hProcess,
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
						windows_redist_err);
					printf("%s", windows_redist_err2);
					fflush(stdout);
				}
#endif
				CloseHandle(_PROCESS_INFO.hThread);
				CloseHandle(_PROCESS_INFO.hProcess);

				if (_STARTUPINFO.hStdOutput != NULL &&
					_STARTUPINFO.hStdOutput != hFile)
					CloseHandle(
						_STARTUPINFO.hStdOutput);
				if (_STARTUPINFO.hStdError != NULL &&
					_STARTUPINFO.hStdError != hFile)
					CloseHandle(
						_STARTUPINFO.hStdError);
			} else {
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
		}
		if (hFile != INVALID_HANDLE_VALUE) {
			CloseHandle(hFile);
		}
	#else
		if (result_configure < 0 ||
			result_configure >= sizeof(pawn_input)) {
			pr_error(stdout,
				"ret_compiler too long!");
			minimal_debugging();
			return (-2);
		}

		if (pawn_input_info == true) {
		#ifdef DOG_ANDROID
			println(stdout, "@ %s", pawn_input);
		#else
			dog_console_title(pawn_input);
			if (strlen(pawn_input) > 120)
				println(stdout, "@ %s", pawn_input);
		#endif
		}

		/* Command line parsing for Unix-like systems */
		char *tmp_input = pawn_input;
		int arg_count = 0;
		char current_token[DOG_MAX_PATH]
			= {0};
		int token_pos = 0;
		int inside_quotes = 0;
		while (*tmp_input) {
			if (*tmp_input == '"') {
				inside_quotes = !inside_quotes;
				tmp_input++;
				continue;
			}
			if (*tmp_input == ' ' && !inside_quotes) {
				if (token_pos > 0) {
					current_token[token_pos] = '\0';
					pawn_unix_args[arg_count++]
						= strdup(current_token);
					token_pos = 0;
				}
				tmp_input++;
				continue;
			}
			current_token[token_pos++]
				= *tmp_input++;
		}
		if (token_pos > 0) {
			current_token[token_pos] = '\0';
			pawn_unix_args[arg_count++]
				= strdup(current_token);
		}
		pawn_unix_args[arg_count] = NULL;

		#ifdef DOG_ANDROID
		/* Android-specific process creation using fork/vfork */
			static bool vfork_mode = false;
			if (pawn_opt_fast == 1) {
				vfork_mode = true;
			}
			pid_t pawn_process_id;
			if (vfork_mode == false) {
				pawn_process_id = fork();
			} else {
				pawn_process_id = vfork();
			}
			if (pawn_process_id == 0) {
				int logging_file = open(
					COMPILER_LOG,
					O_WRONLY | O_CREAT | O_TRUNC, 0644);
				if (logging_file != -1) {
					dup2(logging_file, STDOUT_FILENO);
					dup2(logging_file, STDERR_FILENO);
					close(logging_file);
				} else {
					process_file_success = true;
				}
				execv(pawn_unix_args[0], pawn_unix_args);
				fprintf(stderr, "execv failed: %s\n", strerror(errno));
				_exit(127);
			} else if (pawn_process_id > 0) {
				int process_status;
				int process_timeout_occurred = 0;
				clock_gettime(CLOCK_MONOTONIC, &pre_start);
				/* Poll for process completion with timeout (4096 iterations) */
				for (int k = 0; k < 0x1000; k++) {
					int proc_result = waitpid(
						pawn_process_id,
						&process_status,
						WNOHANG);
					if (proc_result == 0) {
						usleep(100000);	/* 100ms sleep between polls */
					} else if (proc_result == pawn_process_id) {
						break;
					} else {
						pr_error(stdout, "waitpid error");
						minimal_debugging();
						break;
					}
					/* Terminate process if timeout exceeded */
					if (k == 0x1000 - 1) {
						kill(pawn_process_id, SIGTERM);
						sleep(2);
						kill(pawn_process_id, SIGKILL);
						pr_error(stdout,
							"process execution timeout! (%d seconds)",
							0x1000);
						minimal_debugging();
						waitpid(
							pawn_process_id,
							&process_status,
							0);
						process_timeout_occurred = 1;
					}
				}
				clock_gettime(CLOCK_MONOTONIC, &post_end);
				if (!process_timeout_occurred) {
					if (WIFEXITED(process_status)) {
						int proc_exit_code =
							WEXITSTATUS(process_status);
						if (proc_exit_code != 0 &&
						proc_exit_code != 1) {
							pr_error(stdout,
								"compiler process exited with code (%d)",
								proc_exit_code);
							minimal_debugging();
						}
					} else if (WIFSIGNALED(process_status)) {
						pr_error(stdout,
							"compiler process terminated by signal (%d)",
							WTERMSIG(process_status));
					}
				}
			} else {
				pr_error(stdout,
					"process creation failed: %s",
					strerror(errno));
				minimal_debugging();
			}
		#else
			posix_spawn_file_actions_t process_file_actions;
			/* Initialize file actions for output redirection */
			posix_spawn_file_actions_init(
				&process_file_actions);
			int posix_logging_file = open(
				COMPILER_LOG,
				O_WRONLY | O_CREAT | O_TRUNC, 0644);
			if (posix_logging_file != -1) {
				/* Redirect stdout and stderr to log file */
				posix_spawn_file_actions_adddup2(
					&process_file_actions,
					posix_logging_file,
					STDOUT_FILENO);
				posix_spawn_file_actions_adddup2(
					&process_file_actions,
					posix_logging_file,
					STDERR_FILENO);
				posix_spawn_file_actions_addclose(&process_file_actions,
						posix_logging_file);
			} else {
				process_file_success = true;
			}

			/* Configure signal handling for spawned process */
			posix_spawnattr_t spawn_attr;
			posix_spawnattr_init(&spawn_attr);

			/* Set signal mask to block SIGCHLD */
			sigset_t sigmask;
			sigemptyset(&sigmask);
			sigaddset(&sigmask, SIGCHLD);

			posix_spawnattr_setsigmask(&spawn_attr,
				&sigmask);

			/* Set default signal actions */
			sigset_t sigdefault;
			sigemptyset(&sigdefault);
			sigaddset(&sigdefault, SIGPIPE);
			sigaddset(&sigdefault, SIGINT);
			sigaddset(&sigdefault, SIGTERM);

			posix_spawnattr_setsigdefault(&spawn_attr,
				&sigdefault);

			/* Apply signal mask and default settings */
			short flags = POSIX_SPAWN_SETSIGMASK |
				POSIX_SPAWN_SETSIGDEF;

			posix_spawnattr_setflags(&spawn_attr, flags);

			pid_t pawn_process_id;
			int process_spawn_result = posix_spawn(
				&pawn_process_id,
				pawn_unix_args[0],
				&process_file_actions,
				&spawn_attr,
				pawn_unix_args,
				environ);

			if (posix_logging_file != -1) {
				close(posix_logging_file);
			}

			posix_spawnattr_destroy(&spawn_attr);
			posix_spawn_file_actions_destroy(
				&process_file_actions);

			if (process_spawn_result == 0) {
				int process_status;
				int process_timeout_occurred = 0;
				clock_gettime(CLOCK_MONOTONIC,
					&pre_start);
				for (int k = 0; k < 0x1000; k++) {
					int proc_result = -1;
					proc_result = waitpid(
						pawn_process_id,
						&process_status, WNOHANG);
					if (proc_result == 0)
						usleep(50000);	/* 50ms sleep between polls */
					else if (proc_result ==
						pawn_process_id) {
						break;
					} else {
						pr_error(stdout,
							"waitpid error");
						minimal_debugging();
						break;
					}
					/* Terminate on timeout */
					if (k == 0x1000 - 1) {
						kill(pawn_process_id,
							SIGTERM);
						sleep(2);
						kill(pawn_process_id,
							SIGKILL);
						pr_error(stdout,
							"posix_spawn process execution timeout! (%d seconds)",
							0x1000);
						minimal_debugging();
						waitpid(
							pawn_process_id,
							&process_status, 0);
						process_timeout_occurred =
							1;
					}
				}
				clock_gettime(CLOCK_MONOTONIC, &post_end);
				/* Check exit status if process completed normally */
				if (!process_timeout_occurred) {
					if (WIFEXITED(process_status)) {
						int proc_exit_code = 0;
						proc_exit_code =
							WEXITSTATUS(
							process_status);
						if (proc_exit_code != 0 &&
							proc_exit_code != 1) {
							pr_error(stdout,
								"compiler process exited with code (%d)",
								proc_exit_code);
							if (getenv("WSL_DISTRO_NAME") &&
								strcmp(dogconfig.dog_toml_os_type,
									OS_SIGNAL_WINDOWS) == 0 && proc_exit_code == 53)
							{
								pr_info(stdout,
									windows_redist_err);
								printf("%s", windows_redist_err2);
								fflush(stdout);
							}
							minimal_debugging();
						}
					} else if (WIFSIGNALED(
						process_status)) {
						pr_error(stdout,
							"compiler process terminated by signal (%d)",
							WTERMSIG(
							process_status));
					}
				}
			} else {
				pr_error(stdout,
					"posix_spawn failed: %s",
					strerror(process_spawn_result));
				if (strfind(strerror(process_spawn_result), "Exec format error", true))
					pr_error(stdout, "^ The compiler executable is not compatible with your system.");
				if (strfind(strerror(process_spawn_result), "Permission denied", true))
					pr_error(stdout, "^ You do not have permission to execute the compiler executable.");
				if (strfind(strerror(process_spawn_result), "No such file or directory", true))
					pr_error(stdout, "^ The compiler executable does not exist.");
				if (strfind(strerror(process_spawn_result), "Not a directory", true))
					pr_error(stdout, "^ The compiler executable is not a directory.");
				if (strfind(strerror(process_spawn_result), "Is a directory", true))
					pr_error(stdout, "^ The compiler executable is a directory.");
				minimal_debugging();
			}
		#endif
	#endif

	return (0);
}
