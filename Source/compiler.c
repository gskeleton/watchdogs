#include  "utils.h"
#include  "units.h"
#include  "library.h"
#include  "crypto.h"
#include  "cause.h"
#include  "extra/debug.h"
#include  "extra/process.h"
#include  "compiler.h"

const CompilerOption object_opt[] = {
{ BIT_FLAG_DEBUG,     " -d:2 ", 5 }, { BIT_FLAG_ASSEMBLER, " -a "  , 4 },
{ BIT_FLAG_COMPAT,    " -Z:+ ", 5 }, { BIT_FLAG_PROLIX,    " -v:2 ", 5 },
{ BIT_FLAG_COMPACT,   " -C:+ ", 5 }, { BIT_FLAG_TIME,      " -d:3 ", 5 },
{ 0, NULL, 0 }
};

static bool pc_opt_detailed = false;
static bool pc_opt_asm = false;
static bool pc_opt_compat = false;
static bool pc_opt_prolix = false;
static bool pc_opt_compact = false;
bool pc_opt_clean = false;
bool pc_opt_fast = false;
bool pc_opt_debug = false;
bool pc_debug_options = false;

struct
timespec pre_start = { 0 },
post_end           = { 0 };
static double  elapsed_time;
static         io_compilers  dog_pc_sys;
static FILE   *fp = NULL;
static char   *gamemodes_slash = "gamemodes/";
static char   *gamemodes_back_slash = "gamemodes\\";
bool           pc_missing_stdlib = NULL;
bool           pc_is_error = false;
static int     pc_retry_stat = 0;
bool           pc_input_info = false;
static bool    pc_time_issue = false;
static bool    pc_target_exists = false;
char          *pc_full_includes = NULL;
static char    pc_temp[DOG_PATH_MAX + 28] = { 0 };
static char    pbuf[DOG_MAX_PATH * 2];
static char    parsing[DOG_PATH_MAX] = { 0 };
char           pc_include_path[DOG_PATH_MAX] = { 0 };
static char    appended_flags[456] = { 0 };
static char   *server_path = NULL;
static char   *pc_back_slash = NULL;
static char   *pc_size_last_slash = NULL;
static char   *size_include_extra = NULL;
static char   *procure_string_pos = NULL;
bool           process_file_success = false;

static OptionMap pc_all_flag_map[] = {
    {"--detailed",       "-w",
    	&pc_opt_detailed},
    {"--watchdogs",      "-w",
    	&pc_opt_detailed},
    {"--debug",          "-d",
    	&pc_debug_options},
    {"--clean",          "-n",
    	&pc_opt_clean},
    {"--assembler",      "-a",
    	&pc_opt_asm},
    {"--compat",         "-c",
    	&pc_opt_compat},
    {"--compact",        "-m",
    	&pc_opt_compact},
    {"--prolix",         "-p",
    	&pc_opt_prolix},
    {"--fast",           "-f",
    	&pc_opt_fast},
    {NULL, NULL, NULL}
};

static void pc_show_tip(void) {
    static const char *tip_options =
    DOG_COL_BCYAN
        " o [--watchdogs/--detailed/-w] * Enable detailed watchdog output\n"
    DOG_COL_BCYAN
        " o [--debug/-d]                * Enable debugger options\n"
    DOG_COL_BCYAN
        " o [--prolix/-p]               * Enable verbose compilation\n"
    DOG_COL_BCYAN
        " o [--assembler/-a]            * Show assembler output\n"
    DOG_COL_BCYAN
        " o [--compact/-m]              * Use compact encoding\n"
    DOG_COL_BCYAN
        " o [--compat/-c]               * Active cross path separator\n"
    DOG_COL_BCYAN
        " o [--fast/-f]                 * Enable faster compilation mode\n"
    DOG_COL_BCYAN
        " o [--clean/-n]                * Enable safe mode or clean mode\n";
    fwrite(tip_options, 1, strlen(tip_options), stdout);
    print_restore_color();
    return;
}

static int configure_retry_stat(void) {
	switch(pc_retry_stat)
	{
	case 1:
		pc_opt_compat   = true;
		pc_opt_compact  = true;
		pc_opt_fast     = true;
		pc_opt_detailed = true;
		pbuf[0] = '\0';
		#define _MAX_PLAYERS "MAX_PLAYERS=50"
		#define _MAX_VEHICLES "MAX_VEHICLES=100"
		#define _MAX_ACTORS "MAX_ACTORS=10"
		#define _MAX_OBJECTS "MAX_OBJECTS=1000"
		snprintf(pbuf, sizeof(pbuf),
			"%s " _MAX_PLAYERS " " _MAX_VEHICLES " " _MAX_ACTORS " " _MAX_OBJECTS,
			dogconfig.dog_toml_full_opt);
		if (dogconfig.dog_toml_full_opt)
			{
			free(dogconfig.dog_toml_full_opt);
			dogconfig.dog_toml_full_opt = NULL;
			}
		dogconfig.dog_toml_full_opt = strdup(pbuf);
	case 2:
		pbuf[0] = '\0';
		#define _MAX_PLAYERS2 "MAX_PLAYERS=100"
		#define _MAX_VEHICLES2 "MAX_VEHICLES=1000"
		#define _MAX_ACTORS2 "MAX_ACTORS=100"
		#define _MAX_OBJECTS2 "MAX_OBJECTS=2000"
		snprintf(pbuf, sizeof(pbuf),
			_MAX_PLAYERS2 " " _MAX_VEHICLES2 " " _MAX_ACTORS2 " " _MAX_OBJECTS2);
		if (dogconfig.dog_toml_full_opt)
			{
			free(dogconfig.dog_toml_full_opt);
			dogconfig.dog_toml_full_opt = NULL;
			}
		dogconfig.dog_toml_full_opt = strdup(pbuf);

		return 0;
	}
	if (false != pc_time_issue) {
		pc_opt_compat   = true;
		pc_opt_compact  = true;
		pc_opt_fast     = true;
		pc_opt_detailed = true;
		pbuf[0] = '\0';
		#define _MAX_PLAYERS3 "MAX_PLAYERS=50"
		#define _MAX_VEHICLES3 "MAX_VEHICLES=50"
		#define _MAX_ACTORS3 "MAX_ACTORS=50"
		#define _MAX_OBJECTS3 "MAX_OBJECTS=1000"
		snprintf(pbuf, sizeof(pbuf),
			"%s " _MAX_PLAYERS3 " " _MAX_VEHICLES3 " " _MAX_ACTORS3 " " _MAX_OBJECTS3,
			dogconfig.dog_toml_full_opt);
		if (dogconfig.dog_toml_full_opt)
			{
			free(dogconfig.dog_toml_full_opt);
			dogconfig.dog_toml_full_opt = NULL;
			}
		dogconfig.dog_toml_full_opt = strdup(pbuf);
	}
	if (false != pc_opt_fast) {
		pc_opt_compact  = true;
	}
	return 1;
}

static void bitmask_flag(void) {	
	unsigned int __set_bit = 0;

	if (pc_opt_debug)
		__set_bit |= BIT_FLAG_DEBUG;
	if (pc_opt_asm)
		__set_bit |= BIT_FLAG_ASSEMBLER;
	if (pc_opt_compat)
		__set_bit |= BIT_FLAG_COMPAT;
	if (pc_opt_prolix)
		__set_bit |= BIT_FLAG_PROLIX;
	if (pc_opt_compact)
		__set_bit |= BIT_FLAG_COMPACT;
	if (pc_opt_fast)
		__set_bit |= BIT_FLAG_TIME;

	char *p = appended_flags;
	p += strlen(p);

	for (int i = 0; object_opt[i].option; i++) {
		if (!(__set_bit & object_opt[i].flag))
			continue;

		memcpy(p, object_opt[i].option,
			object_opt[i].len);
		p += object_opt[i].len;
	}

	*p = '\0';
}

static void normalize_path(char *path) {
	if (path[0] != '\0') {
		char *p;
		#ifdef DOG_LINUX
		for (p = path; *p; p++) {
			if (*p == _PATH_CHR_SEP_WIN32)
				*p = _PATH_CHR_SEP_POSIX;
		}
		#else
		for (p = path; *p; p++) {
			if (*p == _PATH_CHR_SEP_POSIX)
				*p = _PATH_CHR_SEP_WIN32;
		}
		#endif
	}
	return;
}

static void configure_parent_dir(char *path) {
	if (strstr(path, "../") == NULL) {
		snprintf(pc_include_path, sizeof(pc_include_path),
			" ");
		return;
	}

	bool	parent_path_found = false;
	char	*tmp;
	size_t	i, wpos = 0;

	if ((tmp = strdup(path)) == NULL)
		return;

	for (i = 0; tmp[i] != '\0'; i++) {
		if (strncmp(tmp + i, "../", 3) != 0)
			continue;

		parent_path_found = true;
		i += 3;

		while (tmp[i] != '\0'
		&& tmp[i] != ' '
		&& tmp[i] != '"') {
		    parsing[wpos++] = tmp[i++];
		}

		if (wpos > 0) {
			size_t	last_sep = 0;
			size_t	k;

			for (k = 0; k < wpos; k++) {
				if (parsing[k] == _PATH_CHR_SEP_POSIX ||
					parsing[k] == _PATH_CHR_SEP_WIN32)
					last_sep = k + 1;
			}

			if (last_sep > 0)
				wpos = last_sep;
		}

		break;
	}

	free(tmp);

	if (!parent_path_found && wpos == 0) {
		strlcpy(parsing, "../", sizeof(parsing));
		goto done;
	}

    if (wpos + 3 < sizeof(parsing)) {
        #ifdef DOG_LINUX
        bcopy(parsing, parsing + 3, wpos);
        #else
        memmove(parsing, parsing + 3, wpos);
        #endif
        memcpy(parsing, "../", 3);
        wpos += 3;
        parsing[wpos] = '\0';
    }

	if (parsing[wpos - 1] != _PATH_CHR_SEP_POSIX &&
		parsing[wpos - 1] != _PATH_CHR_SEP_WIN32) {
		parsing[wpos++] = '/';
		parsing[wpos] = '\0';
	}

done:
	memset(pc_temp, 0, sizeof(pc_temp));
	strcpy(pc_temp, parsing);

	if (strstr(pc_temp, gamemodes_slash) ||
		strstr(pc_temp, gamemodes_back_slash))
	{
		char *p = strstr(pc_temp, gamemodes_slash);
		if (!p) {
			p = strstr(pc_temp, gamemodes_back_slash);
		}
		if (p) *p = '\0';
	}

	if (!strstr(dogconfig.dog_toml_full_opt,
		"gamemodes/") &&
		!strstr(dogconfig.dog_toml_full_opt,
		"pawno/include/") &&
		!strstr(dogconfig.dog_toml_full_opt,
		"qawno/include/"))
	{
		pbuf[0] = '\0';
		snprintf(pbuf, sizeof(pbuf),
			"-i" "=\"%s\" "
			"-i" "=\"%s" "gamemodes/\" "
			"-i" "=\"%s" "pawno/include/\" "
			"-i" "=\"%s" "qawno/include/\" ",
		pc_temp, pc_temp, pc_temp, pc_temp);
	} else {
		pbuf[0] = '\0';
		snprintf(pbuf, sizeof(pbuf),
			"-i" "=\"%s\"", pc_temp);
	}

	strncpy(pc_include_path, pbuf,
		sizeof(pc_include_path) - 1);
	pc_include_path[
		sizeof(pc_include_path) - 1] = '\0';

	return;
}

int
dog_exec_compiler(const char *args, const char *compile_args_val,
    const char *second_arg, const char *four_arg, const char *five_arg,
    const char *six_arg, const char *seven_arg, const char *eight_arg,
    const char *nine_arg, const char *ten_arg)
{
	io_compilers   all_pc_field;
	io_compilers  *ctx = &all_pc_field;
	size_t	       fet_sef_ent;
	#ifdef DOG_LINUX
	const 	char  *posix_fzf_path[] = { ".", "download", "~/downloads", ANDROID_DOWNLOADS, NULL };
	char posix_fzf_select[1024];
  	char posix_fzf_finder[2048];
	#endif

	print_restore_color();

	fet_sef_ent = sizeof(dogconfig.dog_sef_found_list) /
				sizeof(dogconfig.dog_sef_found_list[0]);

	if (dir_exists(".watchdogs") == 0) MKDIR(".watchdogs");

	_sef_restore();

	memset(&pre_start, 0, sizeof(pre_start));
	memset(&post_end, 0, sizeof(post_end));

	pc_opt_detailed = false, pc_opt_debug = false,
	pc_opt_clean = false, pc_opt_asm = false,
	pc_opt_compat = false, pc_opt_prolix = false,
	pc_opt_compact = false, pc_time_issue = false,
	process_file_success = false,
	pc_retry_stat = 0, pc_target_exists = false;

	fp = NULL, pc_size_last_slash = NULL,
	pc_back_slash = NULL, size_include_extra = NULL,
	procure_string_pos = NULL;

	memset(&dog_pc_sys, 0, sizeof(io_compilers));
	memset(parsing, 0, sizeof(parsing));
	memset(pc_temp, 0, sizeof(pc_temp));
	memset(pc_include_path, 0,
	    sizeof(pc_include_path));
	memset(appended_flags, 0,
	    sizeof(appended_flags));
	pbuf[0] = '\0';

	if (compile_args_val == NULL) {
		compile_args_val = "";
	}

	char *new_compile_args_val = strdup(compile_args_val);
	normalize_path(new_compile_args_val);
	
	if (dogconfig.dog_pawncc_path[0] == '\0') {
		print_restore_color();

		printf("\033[1;31merror:\033[0m pawncc (our compiler) not found\n"
		    "  \033[2mhelp:\033[0m install it before continuing\n");
		if ((getenv("WSL_INTEROP") || getenv("WSL_DISTRO_NAME")) &&
			strcmp(dogconfig.dog_toml_os_type, OS_SIGNAL_WINDOWS) == 0 &&
			(path_exists("pawno/pawncc") == 1 || path_exists("qawno/pawncc") == 1))
			{
				pr_info(stdout, "Remember, if you run Watchdogs on Windows..");
			}
		printf("\n  \033[1mInstall now?\033[0m  [\033[32mY\033[0m/\033[31mn\033[0m]: ");
        fflush(stdout);

		print_restore_color();

		char *pointer_signalA = readline("");

		if (pointer_signalA && (pointer_signalA[0] == '\0' ||
		    strcmp(pointer_signalA, "Y") == 0 ||
		    strcmp(pointer_signalA, "y") == 0)) {
			dog_free(pointer_signalA);
			if (path_exists(".watchdogs/compiler.log") != 0) {
				remove(".watchdogs/compiler.log");
			}
			unit_ret_main("pawncc");
		}
		dog_free(pointer_signalA);
	}

	const char *argv_buf[] = {
		second_arg,four_arg,five_arg,
		six_arg,seven_arg,eight_arg,nine_arg,ten_arg
	};

	for (int i = 0; i < 8 && argv_buf[i]; ++i) {
		const char *arg = argv_buf[i];
		if (*arg != '-') continue;

		for (OptionMap *entry = pc_all_flag_map;
			entry->full_name;
			++entry)
		{
			if (!strcmp(arg, entry->full_name) ||
				!strcmp(arg, entry->short_name))
			{
				*entry->flag_ptr = true;
				break;
			}
		}
	}

	if (false != pc_opt_clean)
	{
		pbuf[0] = '\0';
		snprintf(pbuf, sizeof(pbuf),
			" ");
		dog_free(dogconfig.dog_toml_full_opt);
		dogconfig.dog_toml_full_opt
			= strdup(pbuf);

		goto _pc_input_info;
	}

_pc_retry_stat:
	int _ret = configure_retry_stat();
	if (!_ret) {
		goto _pc_input_info;
	}
	bitmask_flag();

_pc_input_info:
	if (pc_retry_stat == 2)
		appended_flags[0] = '\0';
	if (pc_opt_detailed)
		pc_input_info = true;
#if defined(_DBG_PRINT)
	pc_input_info = true;
#endif
	if (strlen(appended_flags) > 0) {
		size_t len_toml_all_flags = 0;

		if (dogconfig.dog_toml_full_opt) {
			len_toml_all_flags =
				strlen(dogconfig.dog_toml_full_opt);
		} else {
			dogconfig.dog_toml_full_opt = strdup("");
		}

		size_t extra_len = strlen(appended_flags);
		char *new_ptr = dog_realloc(
			dogconfig.dog_toml_full_opt,
			len_toml_all_flags + extra_len + 1);

		if (!new_ptr) {
			pr_error(stdout,
				"Memory allocation failed for extra options");
			return (-2);
		}

		dogconfig.dog_toml_full_opt = new_ptr;
		strcat(dogconfig.dog_toml_full_opt,
			appended_flags);
	}

	static bool rate_flag_notice = false;
	if (!pc_opt_detailed && !pc_opt_debug &&
		!pc_opt_clean && !pc_opt_asm &&
		!pc_opt_compat && !pc_opt_prolix &&
		!pc_opt_compact && !rate_flag_notice) {
		print("\n");
		pc_show_tip();
		print("\n");
		rate_flag_notice = true;
	}

	printf(DOG_COL_DEFAULT);

	if (new_compile_args_val[0] == '\0')
		goto skip_parent;
	
	configure_parent_dir(new_compile_args_val);
	
skip_parent:
	if (*new_compile_args_val == '\0' ||
		(new_compile_args_val[0] == '.' &&
		new_compile_args_val[1] == '\0')) {
		if (new_compile_args_val[0] != '.')
		{
			if (pc_target_exists == true)
				goto answer_done;
			pc_opt_detailed = true;
			pc_target_exists = !pc_target_exists;
			pr_color(stdout, DOG_COL_YELLOW,
				DOG_COL_BYELLOW
				"** COMPILER TARGET\n");
			print("-------------------------------------\n");
			printf("|- * You run the compiler command "
				"without any args: compile\n"
				"|- * Do you want to compile for "
				DOG_COL_GREEN "%s " DOG_COL_DEFAULT
				"(enter), \n"
				"|- * or do you want to compile for something else?\n",
				dogconfig.dog_toml_serv_input);
			#ifndef DOG_LINUX
				goto manual_configure;
			#else
			int fzf_ok = 2;

			fzf_ok = system("command " "-v " "fzf " "> " "/dev/null " "2>&1");

			if (fzf_ok == 0) {
				printf(DOG_COL_CYAN ">" \
					DOG_COL_DEFAULT \
					" [Using fzf, press Ctrl+C for: " \
					DOG_COL_GREEN "%s" DOG_COL_RESET \
					"]\n\tArrow Up (" DOG_COL_BOLD "^" DOG_COL_RESET \
					") to scroll | Arrow Down (" DOG_COL_BOLD \
					"v" DOG_COL_RESET ") to scroll | " DOG_COL_BOLD"[Enter] " \
					DOG_COL_RESET "to select\n",
					dogconfig.dog_toml_serv_input);

				strlcpy(posix_fzf_finder,
					"find -L ",
					sizeof(posix_fzf_finder));

				for (int f = 0; posix_fzf_path[f] != NULL; f++) {
					if (path_exists(posix_fzf_path[f]) == 1) {
						strlcat(posix_fzf_finder,
							posix_fzf_path[f],
							sizeof(posix_fzf_finder));
						strlcat(posix_fzf_finder,
							" ", sizeof(posix_fzf_finder));
					}
				}
				
				strlcat(posix_fzf_finder,
					"-type f "
					"\\( -name \"*.pwn\" "
					"-o -name \"*.p\" "
					"-o -name \"*.pawn\" \\) "
					"! -path \"*pawno*\" "
					"! -path \"*qawno*\" "
					"2>/dev/null",
					sizeof(posix_fzf_finder));

				memset(pbuf,
					0, sizeof(pbuf));
				
				#ifndef DOG_ANDROID
				#define FZF_COMMAND "%s | fzf " \
					"--height 40%% --reverse " \
					"--prompt 'Select file to compile: ' " \
					"--preview 'if [ -f {} ]; then " \
					"echo \"=== Preview ===\"; " \
					"head -n 20 {}; " \
					"echo \"=== Path ===\"; " \
					"realpath {}; fi'"
				#else
				#define FZF_COMMAND "%s | fzf " \
					"--height 40%% --reverse " \
					"--prompt 'Select file to compile: ' "
				#endif
				snprintf(pbuf, sizeof(pbuf),
					FZF_COMMAND,
					posix_fzf_finder);

				fp = popen(pbuf, "r");
				if (fp == NULL)
					goto pc_end;

				if (fgets(pbuf,
					sizeof(pbuf),
					fp) == NULL)
					goto fzf_end;

				pbuf[strcspn(pbuf, "\n")] = '\0';
				if (pbuf[0] == '\0')
					goto fzf_end;

				strlcpy(posix_fzf_select,
					pbuf,
					sizeof(posix_fzf_select));

				dog_free(dogconfig.dog_toml_serv_input);

				dogconfig.dog_toml_serv_input
					= strdup(posix_fzf_select);
				if (dogconfig.dog_toml_serv_input == NULL) {
					pr_error(stdout,
						"Memory allocation failed");
					goto fzf_end;
				}
				
			fzf_end:
				pclose(fp);
				goto answer_done;
			} else {
				goto manual_configure;
			}
			#endif
		} else {
			goto answer_done;
		}

	manual_configure:
		static bool one_show = false;
		if (!one_show) {
			one_show = !one_show;
			int tree_ret = -1;
			tree_ret = system("tree " "> " "/dev/null " "2>&1");
			if (!tree_ret) {
				if (path_exists(ANDROID_DOWNLOADS)) {
					system("tree " "-P " "\"*.p\" " "-P " "\"*.pawn\" " "-P " "\"*.pwn\" " ANDROID_DOWNLOADS);
				} else {
					system("tree " "-P " "\"*.p\" " "-P " "\"*.pawn\" " "-P " "\"*.pwn\" " ".");
				}
			} else {
				#ifdef DOG_LINUX
				if (path_exists(ANDROID_DOWNLOADS) == 1) {
					system("ls " ANDROID_DOWNLOADS " -R");
				} else {
					system("ls . -R");
				}
				#else
				system("dir . -s");
				#endif
			}
		}
		print(
		" * Input examples such as:\n"
		"   bare.pwn | grandlarc.pwn | main.pwn | server.p\n"
		"   ../storage/downloads/dog/gamemodes/main.pwn\n"
		"   ../storage/downloads/osint/gamemodes/gm.pwn\n"
		);
		print_restore_color();
		print(DOG_COL_CYAN ">"
			DOG_COL_DEFAULT);
		fflush(stdout);
		char *pc_target = NULL;
		pc_target = readline(" ");
		if (pc_target &&
			strlen(pc_target) > 0) {
			dog_free(
				dogconfig.dog_toml_serv_input);
			dogconfig.dog_toml_serv_input =
				strdup(pc_target);
			if (!dogconfig.dog_toml_serv_input) {
				pr_error(stdout,
					"Memory allocation failed");
				dog_free(pc_target);
				goto pc_end;
			}
		}
		free(pc_target);
		pc_target = NULL;
	answer_done:
		char *copy_input
			= strdup(dogconfig.dog_toml_serv_input);
		char *extension
			= strrchr(copy_input, '.');
		if (extension)
			*extension = '\0';
		snprintf(pbuf, DOG_PATH_MAX,
			"%s.amx", copy_input);
		dogconfig.dog_toml_serv_output
			= strdup(pbuf);
		dog_free(copy_input);

		if (path_exists(dogconfig.dog_toml_serv_input) == 0) {
			printf(
				"Cannot locate input: " DOG_COL_CYAN
				"%s" DOG_COL_DEFAULT
				" - No such file or directory\n",
				dogconfig.dog_toml_serv_input);
			goto pc_end;
		}

		dog_free(new_compile_args_val);
		new_compile_args_val = strdup(dogconfig.dog_toml_serv_input);
		configure_parent_dir(new_compile_args_val);
		
		int _process = dog_exec_pc_process(
				dogconfig.dog_pawncc_path,
				dogconfig.dog_toml_serv_input,
				dogconfig.dog_toml_serv_output);
		if (_process != 0) {
			goto pc_end;
		}

		if (path_exists(".watchdogs/compiler.log")) {
			print("\n");
			char *ca = NULL;
			ca = dogconfig.dog_toml_serv_output;
			bool cb = 0;
			if (pc_debug_options)
				cb = 1;
			if (pc_opt_detailed) {
				cause_pc_expl(
					".watchdogs/compiler.log",
					ca, cb);
				print_restore_color();
				goto pc_done;
			}

			if (process_file_success == false)
				dog_printfile(
					".watchdogs/compiler.log");
		}
	pc_done:
		fp = fopen(".watchdogs/compiler.log",
			"r");
		if (fp) {
			bool has_err = false;
			while (fgets(pbuf,
				sizeof(pbuf),
				fp)) {
				if (strfind(pbuf,
					"error", true)) {
					has_err = false;
					break;
				}
			}
			fclose(fp);
			fp = NULL;
			if (has_err) {
				if (dogconfig.dog_toml_serv_output != NULL &&
					path_access(dogconfig.dog_toml_serv_output))
					remove(dogconfig.dog_toml_serv_output);
				pc_is_error = true;
			} else {
				pc_is_error = false;
			}
		} else {
			pr_error(stdout,
				"Failed to open .watchdogs/compiler.log");
			minimal_debugging();
		}

		elapsed_time = ((double)(post_end.tv_sec - pre_start.tv_sec)) +
						((double)(post_end.tv_nsec - pre_start.tv_nsec)) / 1e9;

		print("\n");

		if (!pc_is_error)
			print("** Completed Tasks.\n");
		print(DOG_COL_YELLOW "-----------------------------\n" DOG_COL_DEFAULT);

		pr_color(stdout, DOG_COL_CYAN,
			" <C> (compile-time) Complete At %.3fs (%.0f ms)\n",
			elapsed_time,
			elapsed_time * 1000.0);
		if (elapsed_time > 300) {
			goto _print_time;
		}
	} else {
		if (strfind(new_compile_args_val, ".pwn", true) == false &&
			strfind(new_compile_args_val, ".pawn", true) == false &&
			strfind(new_compile_args_val, ".p", true) == false)
		{
			pr_warning(stdout, "The compiler only accepts '.p' '.pawn' and '.pwn' files.");
			goto pc_end;
		}

		strncpy(ctx->pc_size_temp,
			new_compile_args_val,
			sizeof(ctx->pc_size_temp) -
			1);
		ctx->pc_size_temp[
			sizeof(ctx->pc_size_temp) -
			1] = '\0';

		pc_size_last_slash = strrchr(
			ctx->pc_size_temp,
			_PATH_CHR_SEP_POSIX);
		pc_back_slash = strrchr(
			ctx->pc_size_temp,
			_PATH_CHR_SEP_WIN32);

		if (pc_back_slash && (!pc_size_last_slash ||
			pc_back_slash > pc_size_last_slash))
			pc_size_last_slash =
				pc_back_slash;

		if (pc_size_last_slash) {
			size_t pc_dir_len;
			pc_dir_len = (size_t)
				(pc_size_last_slash -
				ctx->pc_size_temp);

			if (pc_dir_len >=
				sizeof(ctx->pc_direct_path))
				pc_dir_len =
					sizeof(ctx->pc_direct_path) -
					1;

			memcpy(ctx->pc_direct_path,
				ctx->pc_size_temp,
				pc_dir_len);
			ctx->pc_direct_path[
				pc_dir_len] = '\0';

			const char *pc_filename_start =
				pc_size_last_slash + 1;
			size_t pc_filename_len;
			pc_filename_len = strlen(
				pc_filename_start);

			if (pc_filename_len >=
				sizeof(ctx->pc_size_file_name))
				pc_filename_len =
					sizeof(ctx->pc_size_file_name) -
					1;

			memcpy(
				ctx->pc_size_file_name,
				pc_filename_start,
				pc_filename_len);
			ctx->pc_size_file_name[
				pc_filename_len] = '\0';

			size_t total_needed;
			total_needed =
				strlen(ctx->pc_direct_path) +
				1 +
				strlen(ctx->pc_size_file_name) +
				1;

			if (total_needed >
				sizeof(ctx->pc_size_input_path)) {
				strncpy(ctx->pc_direct_path,
					"gamemodes",
					sizeof(ctx->pc_direct_path) -
					1);
				ctx->pc_direct_path[
					sizeof(ctx->pc_direct_path) -
					1] = '\0';

				size_t pc_max_size_file_name;
				pc_max_size_file_name =
					sizeof(ctx->pc_size_file_name) -
					1;

				if (pc_filename_len >
					pc_max_size_file_name) {
					memcpy(
						ctx->pc_size_file_name,
						pc_filename_start,
						pc_max_size_file_name);
					ctx->pc_size_file_name[
						pc_max_size_file_name] =
						'\0';
				}
			}

			if (snprintf(
				ctx->pc_size_input_path,
				sizeof(ctx->pc_size_input_path),
				"%s/%s",
				ctx->pc_direct_path,
				ctx->pc_size_file_name) >=
				(int)sizeof(
				ctx->pc_size_input_path)) {
				ctx->pc_size_input_path[
					sizeof(ctx->pc_size_input_path) -
					1] = '\0';
			}
		} else {
			strncpy(
				ctx->pc_size_file_name,
				ctx->pc_size_temp,
				sizeof(ctx->pc_size_file_name) -
				1);
			ctx->pc_size_file_name[
				sizeof(ctx->pc_size_file_name) -
				1] = '\0';

			strncpy(
				ctx->pc_direct_path,
				".",
				sizeof(ctx->pc_direct_path) -
				1);
			ctx->pc_direct_path[
				sizeof(ctx->pc_direct_path) -
				1] = '\0';

			if (snprintf(
				ctx->pc_size_input_path,
				sizeof(ctx->pc_size_input_path),
				"./%s",
				ctx->pc_size_file_name) >=
				(int)sizeof(
				ctx->pc_size_input_path)) {
				ctx->pc_size_input_path[
					sizeof(ctx->pc_size_input_path) -
					1] = '\0';
			}
		}

		int pc_finding_compile_args = 0;
		pc_finding_compile_args = dog_find_path(
			ctx->pc_direct_path,
			ctx->pc_size_file_name,
			NULL);

		if (!pc_finding_compile_args &&
			strcmp(ctx->pc_direct_path,
			"gamemodes") != 0) {
			pc_finding_compile_args =
				dog_find_path("gamemodes",
				ctx->pc_size_file_name,
				NULL);
			if (pc_finding_compile_args) {
				strncpy(
					ctx->pc_direct_path,
					"gamemodes",
					sizeof(ctx->pc_direct_path) -
					1);
				ctx->pc_direct_path[
					sizeof(ctx->pc_direct_path) -
					1] = '\0';

				if (snprintf(
					ctx->pc_size_input_path,
					sizeof(ctx->pc_size_input_path),
					"gamemodes/%s",
					ctx->pc_size_file_name) >=
					(int)sizeof(
					ctx->pc_size_input_path)) {
					ctx->pc_size_input_path[
						sizeof(ctx->pc_size_input_path) -
						1] = '\0';
				}

				if (dogconfig.dog_sef_count >
					RATE_SEF_EMPTY)
					strncpy(
						dogconfig.dog_sef_found_list[
						dogconfig.dog_sef_count -
						1],
						ctx->pc_size_input_path,
						MAX_SEF_PATH_SIZE);
			}
		}

		if (!pc_finding_compile_args &&
			!strcmp(ctx->pc_direct_path,
			".")) {
			pc_finding_compile_args =
				dog_find_path("gamemodes",
				ctx->pc_size_file_name,
				NULL);
			if (pc_finding_compile_args) {
				strncpy(
					ctx->pc_direct_path,
					"gamemodes",
					sizeof(ctx->pc_direct_path) -
					1);
				ctx->pc_direct_path[
					sizeof(ctx->pc_direct_path) -
					1] = '\0';

				if (snprintf(
					ctx->pc_size_input_path,
					sizeof(ctx->pc_size_input_path),
					"gamemodes/%s",
					ctx->pc_size_file_name) >=
					(int)sizeof(
					ctx->pc_size_input_path)) {
					ctx->pc_size_input_path[
						sizeof(ctx->pc_size_input_path) -
						1] = '\0';
				}

				if (dogconfig.dog_sef_count >
					RATE_SEF_EMPTY)
					strncpy(
						dogconfig.dog_sef_found_list[
						dogconfig.dog_sef_count -
						1],
						ctx->pc_size_input_path,
						MAX_SEF_PATH_SIZE);
			}
		}

		for (int i = 0; i < fet_sef_ent; i++) {
			if (strfind(dogconfig.dog_sef_found_list[i],
				new_compile_args_val, true) == true)
			{
				memset(pc_temp, 0, sizeof(pc_temp));
				pbuf[0] = '\0';

				snprintf(pc_temp,
					sizeof(pc_temp), "%s",
					dogconfig.dog_sef_found_list[i]);
				
				snprintf(pbuf, sizeof(pbuf),
					"%s", pc_temp);
				if (server_path)
					{
						free(server_path);
						server_path = NULL;
					}
					
				server_path = strdup(pbuf);
			}
		}

#if defined(_DBG_PRINT)
		if (server_path != NULL)
			pr_info(stdout, "server_path: %s", server_path);
#endif
		if (path_exists(server_path) == 1) {

			if (server_path[0] != '\0') {
				memset(pc_temp, 0, sizeof(pc_temp));
				strncpy(pc_temp, server_path,
					sizeof(pc_temp) - 1);
				pc_temp[sizeof(pc_temp) - 1] = '\0';
			} else {
				memset(pc_temp, 0, sizeof(pc_temp));
			}

			char *extension = strrchr(pc_temp,
				'.');
			if (extension)
				*extension = '\0';

			ctx->container_output = strdup(pc_temp);

			snprintf(pc_temp, sizeof(pc_temp),
				"%s.amx", ctx->container_output);

			char *pc_temp2 = strdup(pc_temp);

			int _process = dog_exec_pc_process(
					dogconfig.dog_pawncc_path,
					server_path,
					pc_temp2);
			if (_process != 0) {
				goto pc_end;
			}
			if (server_path) {
				free(server_path);
				server_path = NULL;
			}

			if (path_exists(
				".watchdogs/compiler.log")) {
				print("\n");
				char *ca = NULL;
				ca = pc_temp2;
				bool cb = 0;
				if (pc_debug_options)
					cb = 1;
				if (pc_opt_detailed) {
					cause_pc_expl(
						".watchdogs/compiler.log",
						ca, cb);
					print_restore_color();
					goto pc_done2;
				}

				if (process_file_success == false)
					dog_printfile(
						".watchdogs/compiler.log");
			}

	pc_done2:
			fp = fopen(
				".watchdogs/compiler.log", "r");
			pbuf[0] = '\0';
			if (fp) {
				bool has_err = false;
				while (fgets(
					pbuf,
					sizeof(pbuf),
					fp)) {
					if (strfind(
						pbuf,
						"error", true)) {
						has_err = true;
						break;
					}
				}
				fclose(fp);
				fp = NULL;
				if (has_err) {
					if (pc_temp2 &&
						path_access(pc_temp2))
						remove(pc_temp2);
					pc_is_error = true;
				} else {
					pc_is_error = false;
				}
			} else {
				pr_error(stdout,
					"Failed to open .watchdogs/compiler.log");
				minimal_debugging();
			}

			if (pc_temp2)
				{
					free(pc_temp2);
					pc_temp2 = NULL;
				}

			elapsed_time = ((double)(post_end.tv_sec - pre_start.tv_sec)) +
							((double)(post_end.tv_nsec - pre_start.tv_nsec)) / 1e9;

			print("\n");

			if (!pc_is_error)
				print("** Completed Tasks.\n");
			print(DOG_COL_YELLOW "-----------------------------\n" DOG_COL_DEFAULT);

			pr_color(stdout, DOG_COL_CYAN,
				" <C> (compile-time) Complete At %.3fs (%.0f ms)\n",
				elapsed_time,
				elapsed_time * 1000.0);
			if (elapsed_time > 300) {
				goto _print_time;
			}
		} else {
			printf(
				"Cannot locate input: " DOG_COL_CYAN
				"%s" DOG_COL_DEFAULT
				" - No such file or directory\n",
				new_compile_args_val);
			goto pc_end;
		}
	}

	if (fp)
		fclose(fp);

	pbuf[0] = '\0';

	fp = fopen(".watchdogs/compiler.log", "rb");

	if (!fp)
		goto pc_end;
	if (pc_time_issue)
		goto pc_end;

	bool
		stdlib_fail=false;

	while (fgets(
			pbuf,
			sizeof(pbuf),
		fp) != NULL)
		{
		if (strfind(pbuf, "error",
			true) != false) {
				switch(pc_retry_stat)
				{
				case 0:
					pc_retry_stat = 1;
					printf(DOG_COL_BCYAN
						"** Compilation Process Exit with Failed. "
						"recompiling: "
						"%d/2\n"
						BKG_DEFAULT, pc_retry_stat);
					fflush(stdout);
					goto _pc_retry_stat;
				case 1:
					pc_retry_stat = 2;
					printf(DOG_COL_BCYAN
						"** Compilation Process Exit with Failed. "
						"recompiling: "
						"%d/2\n"
						BKG_DEFAULT, pc_retry_stat);
					fflush(stdout);
					goto _pc_retry_stat;
				}
			}
		if((strfind(pbuf, "a_samp" ,true)
			== 1 &&
			strfind(pbuf, "cannot read from file", true)
			== 1) ||
			(strfind(pbuf, "open.mp", true)
			== 1 &&
			strfind(pbuf, "cannot read from file", true)
			== 1))
		{
			stdlib_fail = !stdlib_fail;
		}
		}

	if (fp)
		fclose(fp);

	if (stdlib_fail == true) {
		pc_missing_stdlib = true;
	}

	goto pc_end;

pc_end:
	_sef_restore();
	int ret = dog_find_path(".watchdogs", "*_temp", NULL);
	if (ret) {
		for (int i = 0; i < fet_sef_ent; i++) {
			remove(dogconfig.dog_sef_found_list[i]);
		}
		_sef_restore();
	}
    fflush(stdout);
    dog_free(new_compile_args_val);
	return (1);
_print_time:
    fflush(stdout);
	print(
		"** Process is taking a while..\n");
	if (pc_time_issue == false) {
		pr_info(stdout, "Retrying..");
		pc_time_issue = true;
		goto _pc_retry_stat;
	}
	return (1);
}
