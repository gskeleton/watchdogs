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
struct
	timespec pre_start = { 0 },
	post_end = { 0 };
static double  elapsed_time;
static FILE*   fp = NULL;
bool           pc_missing_stdlib = false;
bool           pc_is_error = false;
static int     pc_retry_state = PC_RETRY_STATE_NONE;
bool           pc_input_info = false;
bool           pc_debug_options = false;
static bool    pc_time_issue = false;
char*          pc_full_includes = NULL;
static bool    applied_opt = false;
static char    pc_temp[DOG_PATH_MAX + 28] = { 0 };
static char    pbuf[DOG_MAX_PATH * 2];
static char    parsing[DOG_PATH_MAX] = { 0 };
char           pc_include_path[DOG_PATH_MAX] = { 0 };
static char    fzf_select[1024];
static char    fzf_finder[2048];
static char*   server_path = NULL;
static char*   pc_back_slash = NULL;
static char*   pc_last_slash = NULL;
static char*   size_include_extra = NULL;
static char*   procure_string_pos = NULL;
bool           process_file_success = false;

static void pc_show_tip(void) {
	static const char* tip_options =
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
	switch (pc_retry_state) {
	case PC_RETRY_STATE_FIRST: {
		/* First retry: conservative limits */
		pctx->flag_compat = true;
		pctx->flag_fast = true, pctx->flag_detailed = true;
		static const char* MAX_PLAYERS = "MAX_PLAYERS=50";
		static const char* MAX_VEHICLES = "MAX_VEHICLES=100";
		static const char* MAX_ACTORS = "MAX_ACTORS=20";
		static const char* MAX_OBJECTS = "MAX_OBJECTS=1000";
		pbuf[0] = '\0';
		(void)snprintf(pbuf, sizeof(pbuf),
			"%s %s %s %s %s",
			dogconfig.dog_toml_full_opt, MAX_PLAYERS, MAX_VEHICLES, MAX_ACTORS, MAX_OBJECTS);
		dog_free(dogconfig.dog_toml_full_opt);
		dogconfig.dog_toml_full_opt = strdup(pbuf);
		break;
	}
	case PC_RETRY_STATE_FINAL: {
		/* Final retry: increased limits */
		static const char* MAX_PLAYERS = "MAX_PLAYERS=100";
		static const char* MAX_VEHICLES = "MAX_VEHICLES=1000";
		static const char* MAX_ACTORS = "MAX_ACTORS=100";
		static const char* MAX_OBJECTS = "MAX_OBJECTS=2000";
		pbuf[0] = '\0';
		(void)snprintf(pbuf, sizeof(pbuf),
			"%s %s %s %s",
			MAX_PLAYERS, MAX_VEHICLES, MAX_ACTORS, MAX_OBJECTS);
		dog_free(dogconfig.dog_toml_full_opt);
		dogconfig.dog_toml_full_opt = strdup(pbuf);
		return 0;
	}
	}
	if (false != pc_time_issue) {
		/* Handle timeout issues with reduced limits */
		pctx->flag_compat = true;
		pctx->flag_fast = true, pctx->flag_detailed = true;
		static const char* MAX_PLAYERS = "MAX_PLAYERS=50";
		static const char* MAX_VEHICLES = "MAX_VEHICLES=50";
		static const char* MAX_ACTORS = "MAX_ACTORS=20";
		static const char* MAX_OBJECTS = "MAX_OBJECTS=1000";
		pbuf[0] = '\0';
		(void)snprintf(pbuf, sizeof(pbuf),
			"%s %s %s %s %s",
			dogconfig.dog_toml_full_opt, MAX_PLAYERS, MAX_VEHICLES, MAX_ACTORS, MAX_OBJECTS);
		dog_free(dogconfig.dog_toml_full_opt);
		dogconfig.dog_toml_full_opt = strdup(pbuf);
	}
	return 1;
}

static void collect_option_bitmask(void) {

	unsigned int __set_bit = 0;
	char *p, *ptr;
	int i;
	pbuf[0] = '\0';
	ptr = pbuf;

	/* Show tip if no flags specified */
	if (!(pctx->flag_detailed || pctx->flag_assembly || pctx->flag_compat ||
		pctx->flag_compact  || pctx->flag_prolix  || pctx->flag_debug  ||
		pctx->flag_clean    || pctx->flag_fast))
	{
		static bool notice = false;
		if (!notice) {
			notice = true;
			putchar('\n');
			pc_show_tip();
			putchar('\n');
		}
	}

	if (applied_opt == false) {
		applied_opt = true;
	} else if (applied_opt == true) {
		return;
	}

	/* Set bits for enabled flags */
	if (pctx->flag_debug)
		__set_bit |= BIT_FLAG_DEBUG;
	if (pctx->flag_assembly)
		__set_bit |= BIT_FLAG_ASSEMBLER;
	if (pctx->flag_compat)
		__set_bit |= BIT_FLAG_COMPAT;
	if (pctx->flag_prolix)
		__set_bit |= BIT_FLAG_PROLIX;
	if (pctx->flag_compact)
		__set_bit |= BIT_FLAG_COMPACT;
	if (pctx->flag_fast)
		__set_bit |= BIT_FLAG_TIME;

	if (!pctx->flag_debug) {
		goto next;
	}

	static const char *f[] = {
		"-d0 ", "-d1 ", "-d2 ", "-d3 ",
		"-d:0 ", "-d:1 ", "-d:2 ", "-d:3 ",
		"-d=0 ", "-d=1 ", "-d=2 ", "-d=3 "
	};
	for (i = 0; i < 12; i++) {
		char* options = dogconfig.dog_toml_full_opt;
		while ((p = strstr(options, f[i])) != NULL) {
			size_t len = strlen(f[i]);
			(void)memmove(p, p + len, strlen(p + len) + 1);
			options = p;
			if (len == 0)
				break;
			options += 1;
		}
	}

next:
	/* Compiler option flags mapping */
	static const CompilerOption object_opt[] = {
		{ BIT_FLAG_DEBUG, " -d:2 ", 5 },
		{ BIT_FLAG_ASSEMBLER, " -a ", 4 },
		{ BIT_FLAG_COMPAT, " -Z:+ ", 5 },
		{ BIT_FLAG_PROLIX, " -v:2 ", 5 },
		{ BIT_FLAG_COMPACT, " -C:+ ", 5 },
		{ BIT_FLAG_TIME, " -d:3 ", 5 },
		{ 0, NULL, 0 }
	};

	/* Append corresponding option strings */
	for (int i = 0; object_opt[i].option; i++) {
		if (!(__set_bit & object_opt[i].flag))
			continue;

		(void)memcpy(ptr, object_opt[i].option,
			object_opt[i].len);
		ptr += object_opt[i].len;
	}

	*ptr = '\0';

	/* Append collected flags to options */
	if (strlen(pbuf) > 0) {
		applied_opt = true;

		size_t len;
		size_t extra_len;
		char* new_options;
		len = strlen(dogconfig.dog_toml_full_opt);
		extra_len = strlen(pbuf);

		new_options = dog_realloc(dogconfig.dog_toml_full_opt,
								len + extra_len + 1);

		if (!new_options) {
			pr_error(stdout,
				"Memory allocation failed");
			minimal_debugging();
			return;
		}

		dogconfig.dog_toml_full_opt = new_options;
		(void)strcat(dogconfig.dog_toml_full_opt, pbuf);
	}
}

static void normalize_path(char* path) {
	if (path[0] == '\0')
		return;

	char* p;
	#ifdef DOG_LINUX
	/* Convert Windows backslashes to POSIX forward slashes */
	for (p = path; *p; p++) {
		if (*p == _PATH_CHR_SEP_WIN32)
			*p = _PATH_CHR_SEP_POSIX;
	}
	#else
	/* Convert POSIX forward slashes to Windows backslashes */
	for (p = path; *p; p++) {
		if (*p == _PATH_CHR_SEP_POSIX)
			*p = _PATH_CHR_SEP_WIN32;
	}
	#endif

	return;
}

static void configure_parent_dir(char* path) {
	if (strstr(path, "../") == NULL) {
		(void)snprintf(pc_include_path, sizeof(pc_include_path),
			" ");
		return;
	}

	bool	parent_path_found = false;
	char* tmp;
	size_t	i, wpos = 0;

	if ((tmp = strdup(path)) == NULL)
		return;

	/* Extract parent directory path */
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

		/* Find last path separator */
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

	/* Add ../ prefix */
	if (wpos + 3 < sizeof(parsing)) {
		#ifdef DOG_LINUX
		(void)bcopy(parsing, parsing + 3, wpos);
		#else
		(void)memmove(parsing, parsing + 3, wpos);
		#endif
		(void)memcpy(parsing, "../", 3);
		wpos += 3;
		parsing[wpos] = '\0';
	}

	/* Ensure trailing separator */
	if (parsing[wpos - 1] != _PATH_CHR_SEP_POSIX
		&& parsing[wpos - 1] != _PATH_CHR_SEP_WIN32) {
		parsing[wpos++] = '/';
		parsing[wpos] = '\0';
	}

done:
	pc_temp[0] = '\0';
	(void)strcpy(pc_temp, parsing);

	/* Remove gamemodes suffix if present */
	if (strfind(pc_temp, "gamemodes/", true) != false ||
		strfind(pc_temp, "gamemodes\\", true) != false)
	{
		char* p = strstr(pc_temp, "gamemodes/");
		char* p2 = strstr(pc_temp, "gamemodes\\");
		if (p)
			*p = '\0';
		if (p2)
			*p2 = '\0';
	}

	/* Build include path string */
	if (!strstr(dogconfig.dog_toml_full_opt,
		"gamemodes/") &&
		!strstr(dogconfig.dog_toml_full_opt,
			"pawno/include/") &&
		!strstr(dogconfig.dog_toml_full_opt,
			"qawno/include/"))
	{
		pbuf[0] = '\0';
		(void)snprintf(pbuf, sizeof(pbuf),
			"-i" "=\"%s\" "
			"-i" "=\"%s" "gamemodes/\" "
			"-i" "=\"%s" "pawno/include/\" "
			"-i" "=\"%s" "qawno/include/\" ",
			pc_temp, pc_temp, pc_temp, pc_temp);
	}
	else {
		pbuf[0] = '\0';
		(void)snprintf(pbuf, sizeof(pbuf),
			"-i" "=\"%s\"", pc_temp);
	}

	strncpy(pc_include_path, pbuf,
		sizeof(pc_include_path) - 1);
	pc_include_path[
		sizeof(pc_include_path) - 1] = '\0';

	return;
}

static int compiler_show_fzf_file_selector(void) {
	pr_color(stdout, DOG_COL_YELLOW,
		DOG_COL_BYELLOW
		"          [COMPILER TARGET]\n");
	print("  -------------------------------------\n");
	pbuf[0] = '\0';
	int len = snprintf(pbuf, sizeof(pbuf),
		"  |- * You run the compiler command "
		"without any args: compile\n"
		"  |- * Do you want to compile for "
		DOG_COL_GREEN "%s " DOG_COL_DEFAULT
		"(enter), \n"
		"  |- * or do you want to compile for something else?\n",
		dogconfig.dog_toml_serv_input);
	fwrite(pbuf, 1, len, stdout);
	fflush(stdout);

	/* Active flags */
	pctx->flag_detailed = true;
	pctx->flag_fast = true;

	/* Paths to search for source files */
	const char* fzf_path[] = {
		".",
		"download",
		"~/downloads",
		ANDROID_SHARED_DOWNLOADS_PATH,
		NULL
	};

	fzf_select[0] = '\0';
	fzf_finder[0] = '\0';

	int fzf_ret = 2;

	/* Check if fzf is installed */
	#ifdef DOG_WINDOWS
	fzf_ret = system("cmd.exe /C where fzf.exe >NUL 2>&1");
	#else
	fzf_ret = system("command " "-v " "fzf " "> " "/dev/null " "2>&1");
	#endif

	if (fzf_ret == 0) {
		pbuf[0] = '\0';
		len = snprintf(pbuf, sizeof(pbuf),
			DOG_COL_CYAN "   >" \
			DOG_COL_DEFAULT \
			" [Using fzf, press Ctrl+C for: " \
			DOG_COL_GREEN "%s" DOG_COL_RESET \
			"]\n\tArrow Up (" DOG_COL_BOLD "^" DOG_COL_RESET \
			") to scroll | Arrow Down (" DOG_COL_BOLD \
			"v" DOG_COL_RESET ") to scroll | " DOG_COL_BOLD"[Enter] " \
			DOG_COL_RESET "to select\n",
			dogconfig.dog_toml_serv_input);
		fwrite(pbuf, 1, len, stdout);
        fflush(stdout);

		/* Build find command */
		#ifndef DOG_WINDOWS
		(void)strlcpy(fzf_finder,
			"find -L ",
			sizeof(fzf_finder));

		for (int f = 0; fzf_path[f] != NULL; f++) {
			if (path_exists(fzf_path[f]) == 1) {
				(void)strlcat(fzf_finder,
					fzf_path[f],
					sizeof(fzf_finder));
				(void)strlcat(fzf_finder,
					" ", sizeof(fzf_finder));
			}
		}

		(void)strlcat(fzf_finder,
			"-type f "
			"\\( -name \"*.pwn\" "
			"-o -name \"*.p\" "
			"-o -name \"*.pawn\" \\) "
			"! -path \"*pawno*\" "
			"! -path \"*qawno*\" "
			"2>/dev/null",
			sizeof(fzf_finder));
		#endif
		#ifdef DOG_LINUX
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
		#endif
		pbuf[0] = '\0';
		#ifdef DOG_WINDOWS
		(void)snprintf(pbuf, sizeof(pbuf),
			"fzf.exe");
		#else
		(void)snprintf(pbuf, sizeof(pbuf),
			FZF_COMMAND,
			fzf_finder);
		#endif

		/* Execute fzf and read selection */
		fp = popen(pbuf, "r");
		if (fp == NULL)
			return -2;

		if (fgets(pbuf,
			sizeof(pbuf),
			fp) == NULL)
			goto fzf_end;

		pbuf[strcspn(pbuf, "\n")] = '\0';
		if (pbuf[0] == '\0')
			goto fzf_end;

		strlcpy(fzf_select,
			pbuf,
			sizeof(fzf_select));

		dog_free(dogconfig.dog_toml_serv_input);

		dogconfig.dog_toml_serv_input
			= strdup(fzf_select);
		if (dogconfig.dog_toml_serv_input == NULL) {
			pr_error(stdout,
				"Memory allocation failed");
			goto fzf_end;
		}

	fzf_end:
		pclose(fp);
		return 2;
	} else {
		return 3;
	}
}

static void compiler_state_init(void) {
	if (dir_exists(".watchdogs") == 0)
		MKDIR(".watchdogs");

	print_restore_color();

	_sef_restore();

	/* Reset timing and state */
	pre_start = (struct timespec){ 0 };
	post_end = (struct timespec){ 0 };

	process_file_success = false,
		pc_retry_state = PC_RETRY_STATE_NONE;

	fp = NULL, pc_last_slash = NULL,
		pc_back_slash = NULL, size_include_extra = NULL,
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

	applied_opt = false;

	/* Clear buffers */
	pctx->direct_path[0] = '\0';
	pctx->file_name_buf[0] = '\0';
	pctx->input_path[0] = '\0';
	pctx->temp_path[0] = '\0';
	parsing[0] = '\0';
	pc_include_path[0] = '\0';
	pc_temp[0] = '\0';
	pbuf[0] = '\0';
}

int
dog_exec_compiler(const char* args, char* compile_args_val,
	const char* second_arg, const char* four_arg, const char* five_arg,
	const char* six_arg, const char* seven_arg, const char* eight_arg,
	const char* nine_arg, const char* ten_arg)
{
	size_t	       fet_sef_ent, len;
	fet_sef_ent = sizeof(dogconfig.dog_sef_found_list) /
		sizeof(dogconfig.dog_sef_found_list[0]);

	/* macro of operating system (OS) */
	pbuf[0] = '\0';
	#ifdef DOG_WINDOWS // Windows
		(void)snprintf(pbuf, sizeof(pbuf),
			"%s WINDOWS=1 LINUX=0 ANDROID=0",
			dogconfig.dog_toml_full_opt);
	#else
	#ifdef DOG_ANDROID // Android
		(void)snprintf(pbuf, sizeof(pbuf),
			"%s WINDOWS=0 LINUX=0 ANDROID=1",
			dogconfig.dog_toml_full_opt);
	#else // Linux
		(void)snprintf(pbuf, sizeof(pbuf),
			"%s WINDOWS=0 LINUX=1 ANDROID=0",
			dogconfig.dog_toml_full_opt);
	#endif
	#endif
	// Windows Subsystem Linux (WSL) with OS_SIGNAL_WINDOWS
	if ((getenv("WSL_INTEROP") || getenv("WSL_DISTRO_NAME")) &&
		strcmp(dogconfig.dog_toml_os_type, OS_SIGNAL_WINDOWS) == 0)
	{
		(void)snprintf(pbuf, sizeof(pbuf),
			"%s WINDOWS=1 LINUX=0 ANDROID=0",
			dogconfig.dog_toml_full_opt);
	}
	dog_free(dogconfig.dog_toml_full_opt);
	dogconfig.dog_toml_full_opt = strdup(pbuf);

	if (compile_args_val == NULL) {
		compile_args_val = "";
	}

	compiler_state_init();
	normalize_path(compile_args_val);

	const char* argv_buf[] = {
		second_arg,four_arg,five_arg,
		six_arg,seven_arg,eight_arg,nine_arg,ten_arg
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

	for (int i = 0; i < 8 && argv_buf[i]; ++i) {
		const char* argv = argv_buf[i];
		if (*argv != '-')
			continue;

		OptionMap* entry;
		for (entry = flag_map; entry->full_name; ++entry) {
			if (strcmp(argv, entry->full_name) == 0
				|| strcmp(argv, entry->short_name) == 0)
			{
				*entry->flag_ptr = 1;
				break;
			}
		}
	}

	/* Clean mode: clear all options */
	if (false != pctx->flag_clean)
	{
		pbuf[0] = '\0';
		(void)snprintf(pbuf, sizeof(pbuf),
			" ");
		dog_free(dogconfig.dog_toml_full_opt);
		dogconfig.dog_toml_full_opt
			= strdup(pbuf);

		goto _pc_input_info;
	}

	int _ret = configure_retry_stat();
	if (!_ret) {
		goto _pc_input_info;
	}

	/* Fast mode implies compact encoding */
	if (false != pctx->flag_fast) {
		pctx->flag_compact = true;
	}

_pc_retry_state:
	collect_option_bitmask();

_pc_input_info:
	if (pctx->flag_detailed)
		pc_input_info = true;
#if defined(_DBG_PRINT)
	pc_input_info = true;
#endif

	if (compile_args_val[0] == '\0')
		goto skip_parent;

	configure_parent_dir(compile_args_val);

skip_parent:
	/* Handle interactive file selection */
	if (*compile_args_val == '\0'
		|| (compile_args_val[0] == '.'
			&& compile_args_val[1] == '\0')) {
		if (compile_args_val[0] != '.') {
			int ret = compiler_show_fzf_file_selector();
			if (ret == -2) {
				goto pc_end;
			} else if (ret == 2) {
				goto answer_done;
			} else if (ret == 3) {
				goto manual_configure;
			}
		} else {
			goto answer_done;
		}

		static bool listing_shown = false;
	manual_configure:
		/* Show file listing for manual selection */
		if (!listing_shown) {
			listing_shown = true;
			int tree_ret = -1;
			tree_ret = system("tree > /dev/null 2>&1");
			if (!tree_ret) {
				if (path_exists(ANDROID_SHARED_DOWNLOADS_PATH)) {
					system(
						"tree "
						"-P \"*.p\" "
						"-P \"*.pawn\" "
						"-P \"*.pwn\" "
						ANDROID_SHARED_DOWNLOADS_PATH);
				} else {
					system("tree -P \"*.p\" -P \"*.pawn\" -P \"*.pwn\" .");
				}
			} else {
			#ifdef DOG_LINUX
				if (path_exists(ANDROID_SHARED_DOWNLOADS_PATH) == 1) {
					system("ls " ANDROID_SHARED_DOWNLOADS_PATH  " -R");
				} else {
					system("ls . -R");
				}
			#else
				system("dir . -s");
			#endif
			}
		}
		print(
			" * Input examples such as:\n   bare.pwn main.pwn server.pwn\n"
		);
		print_restore_color();
		print(DOG_COL_CYAN ">"
			DOG_COL_DEFAULT);
		fflush(stdout);
		char* pc_target = NULL;
		pc_target = readline(" ");
		if (pc_target &&
			strlen(pc_target) > 0) {
			dog_free(
				dogconfig.dog_toml_serv_input);
			if (path_access(pc_target) == 1) {
				dogconfig.dog_toml_serv_input =
					strdup(pc_target);
				goto pc_target_done;
			}
			if (strfind(pc_target, "gamemodes", true) == true)
				dogconfig.dog_toml_serv_input =
				strdup(pc_target);
			else {
				pbuf[0] = '\0';
				(void)snprintf(pbuf, sizeof(pbuf),
					"gamemodes/%s", pc_target);
				dogconfig.dog_toml_serv_input =
					strdup(pbuf);
			}
		}
	pc_target_done:
		free(pc_target);
		pc_target = NULL;
	answer_done:
		/* Build output filename */
		char* copy_input
			= strdup(dogconfig.dog_toml_serv_input);
		char* ext
			= strrchr(copy_input, '.');
		if (ext)
			*ext = '\0';
		(void)snprintf(pbuf, MAX_SEF_PATH_SIZE + 28,
			"%s.amx", copy_input);
		dog_free(dogconfig.dog_toml_serv_output);
		dogconfig.dog_toml_serv_output
			= strdup(pbuf);
		dog_free(copy_input);

		if (path_exists(dogconfig.dog_toml_serv_input) == 0) {
			pbuf[0] = '\0';
			len = snprintf(pbuf, sizeof(pbuf),
				"Cannot locate input: " DOG_COL_CYAN
				"%s" DOG_COL_DEFAULT
				" - No such file or directory\n",
				dogconfig.dog_toml_serv_input);
			fwrite(pbuf, 1, len, stdout);
			fflush(stdout);
			goto pc_end;
		}

		compile_args_val = dogconfig.dog_toml_serv_input;
		configure_parent_dir(compile_args_val);

		/* Execute compiler */
		int _process = dog_exec_compiler_tasks(
			dogconfig.dog_pawncc_path,
			dogconfig.dog_toml_serv_input,
			dogconfig.dog_toml_serv_output);
		if (_process != 0) {
			goto pc_end;
		}

		/* Process compiler output */
		if (path_exists(".watchdogs/compiler.log")) {
			putchar('\n');
			char* ca = NULL;
			ca = dogconfig.dog_toml_serv_output;
			bool cb = 0;
			if (pc_debug_options)
				cb = 1;
			if (pctx->flag_detailed) {
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
		/* Check for compilation errors */
		fp = fopen(".watchdogs/compiler.log",
			"r");
		if (fp) {
			bool has_err = false;
			while (fgets(pbuf,
				sizeof(pbuf),
				fp)) {
				if (strfind(pbuf,
					"error", true)) {
					has_err = true;
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

		/* Calculate and display compilation time */
		elapsed_time = ((double)(post_end.tv_sec - pre_start.tv_sec)) +
					   ((double)(post_end.tv_nsec - pre_start.tv_nsec)) / 1e9;

		putchar('\n');

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
	}
	else {
		/* Validate file ext */
		if (strfind(compile_args_val, ".pwn", true) == false &&
			strfind(compile_args_val, ".pawn", true) == false &&
			strfind(compile_args_val, ".p", true) == false)
		{
			pr_warning(stdout,
				"The compiler only accepts '.p' '.pawn' and '.pwn' files.");
			goto pc_end;
		}

		/* Parse path components */
		(void)strncpy(pctx->temp_path,
			compile_args_val,
			sizeof(pctx->temp_path) -
			1);
		pctx->temp_path[
			sizeof(pctx->temp_path) -
				1] = '\0';

		pc_last_slash = strrchr(
			pctx->temp_path,
			_PATH_CHR_SEP_POSIX);
		pc_back_slash = strrchr(
			pctx->temp_path,
			_PATH_CHR_SEP_WIN32);

		if (pc_back_slash && (!pc_last_slash ||
			pc_back_slash > pc_last_slash))
		{
			pc_last_slash = pc_back_slash;
		}

		if (pc_last_slash) {
			/* Extract directory and filename */
			size_t pc_dir_len;
			pc_dir_len = (size_t)
				(pc_last_slash -
					pctx->temp_path);

			if (pc_dir_len >=
				sizeof(pctx->direct_path))
				pc_dir_len =
				sizeof(pctx->direct_path) -
				1;

			(void)memcpy(pctx->direct_path,
				pctx->temp_path,
				pc_dir_len);
			pctx->direct_path[
				pc_dir_len] = '\0';

			const char* pc_filename_start =
				pc_last_slash + 1;
			size_t pc_filename_len;
			pc_filename_len = strlen(
				pc_filename_start);

			if (pc_filename_len >=
				sizeof(pctx->file_name_buf))
				pc_filename_len =
				sizeof(pctx->file_name_buf) -
				1;

			(void)memcpy(
				pctx->file_name_buf,
				pc_filename_start,
				pc_filename_len);
			pctx->file_name_buf[
				pc_filename_len] = '\0';

			size_t total_needed;
			total_needed =
				strlen(pctx->direct_path) +
				1 +
				strlen(pctx->file_name_buf) +
				1;

			if (total_needed >
				sizeof(pctx->input_path)) {
				(void)strncpy(pctx->direct_path,
					"gamemodes",
					sizeof(pctx->direct_path) -
					1);
				pctx->direct_path[
					sizeof(pctx->direct_path) -
						1] = '\0';

				size_t pc_max_size_file_name;
				pc_max_size_file_name =
					sizeof(pctx->file_name_buf) -
					1;

				if (pc_filename_len >
					pc_max_size_file_name) {
					(void)memcpy(
						pctx->file_name_buf,
						pc_filename_start,
						pc_max_size_file_name);
					pctx->file_name_buf[
						pc_max_size_file_name] =
						'\0';
				}
			}

			if (snprintf(
				pctx->input_path,
				sizeof(pctx->input_path),
				"%s/%s",
				pctx->direct_path,
				pctx->file_name_buf) >=
				(int)sizeof(
					pctx->input_path)) {
				pctx->input_path[
					sizeof(pctx->input_path) -
						1] = '\0';
			}
		}
		else {
			/* No directory separator, use current directory */
			(void)strncpy(
				pctx->file_name_buf,
				pctx->temp_path,
				sizeof(pctx->file_name_buf) -
				1);
			pctx->file_name_buf[
				sizeof(pctx->file_name_buf) -
					1] = '\0';

			(void)strncpy(
				pctx->direct_path,
				".",
				sizeof(pctx->direct_path) -
				1);
			pctx->direct_path[
				sizeof(pctx->direct_path) -
					1] = '\0';

			if (snprintf(
				pctx->input_path,
				sizeof(pctx->input_path),
				"./%s",
				pctx->file_name_buf) >=
				(int)sizeof(
					pctx->input_path)) {
				pctx->input_path[
					sizeof(pctx->input_path) -
						1] = '\0';
			}
		}

		/* Search for file in gamemodes directory if not found */
		int pc_finding_compile_args = 0;
		pc_finding_compile_args = dog_find_path(
			pctx->direct_path,
			pctx->file_name_buf,
			NULL);

		if (!pc_finding_compile_args &&
			strcmp(pctx->direct_path,
				"gamemodes") != 0) {
			pc_finding_compile_args =
				dog_find_path("gamemodes",
					pctx->file_name_buf,
					NULL);
			if (pc_finding_compile_args) {
				(void)strncpy(
					pctx->direct_path,
					"gamemodes",
					sizeof(pctx->direct_path) -
					1);
				pctx->direct_path[
					sizeof(pctx->direct_path) -
						1] = '\0';

				if (snprintf(
					pctx->input_path,
					sizeof(pctx->input_path),
					"gamemodes/%s",
					pctx->file_name_buf) >=
					(int)sizeof(
						pctx->input_path)) {
					pctx->input_path[
						sizeof(pctx->input_path) -
							1] = '\0';
				}

				if (dogconfig.dog_sef_count >
					RATE_SEF_EMPTY)
				{
					(void)strncpy(
						dogconfig.dog_sef_found_list[
							dogconfig.dog_sef_count - 1],
						pctx->input_path,
								MAX_SEF_PATH_SIZE);
				}
			}
		}

		if (!pc_finding_compile_args &&
			!strcmp(pctx->direct_path,
				".")) {
			pc_finding_compile_args =
				dog_find_path("gamemodes",
					pctx->file_name_buf,
					NULL);
			if (pc_finding_compile_args) {
				(void)strncpy(
					pctx->direct_path,
					"gamemodes",
					sizeof(pctx->direct_path) -
					1);
				pctx->direct_path[
					sizeof(pctx->direct_path) -
						1] = '\0';

				if (snprintf(
					pctx->input_path,
					sizeof(pctx->input_path),
					"gamemodes/%s",
					pctx->file_name_buf) >=
					(int)sizeof(
						pctx->input_path)) {
					pctx->input_path[
						sizeof(pctx->input_path) -
							1] = '\0';
				}

				if (dogconfig.dog_sef_count >
					RATE_SEF_EMPTY)
					strncpy(
						dogconfig.dog_sef_found_list[
							dogconfig.dog_sef_count -
								1],
						pctx->input_path,
								MAX_SEF_PATH_SIZE);
			}
		}

		/* Find matching server path */
		for (int i = 0; i < fet_sef_ent; i++) {
			if (strfind(dogconfig.dog_sef_found_list[i],
				compile_args_val, true) == true)
			{
				pc_temp[0] = '\0';
				pbuf[0] = '\0';

				(void)snprintf(pc_temp,
					sizeof(pc_temp), "%s",
					dogconfig.dog_sef_found_list[i]);

				(void)snprintf(pbuf, sizeof(pbuf),
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
		/* Execute compilation if file exists */
		if (path_exists(server_path) == 1) {

			if (server_path[0] != '\0') {
				pc_temp[0] = '\0';
				strncpy(pc_temp, server_path,
					sizeof(pc_temp) - 1);
				pc_temp[sizeof(pc_temp) - 1] = '\0';
			} else {
				pc_temp[0] = '\0';
			}

			char* ext = strrchr(pc_temp,
				'.');
			if (ext)
				*ext = '\0';

			pctx->output = strdup(pc_temp);

			(void)snprintf(pc_temp, sizeof(pc_temp),
				"%s.amx", pctx->output);

			char* pc_temp2 = strdup(pc_temp);

			int _process = dog_exec_compiler_tasks(
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

			/* Process compiler output */
			if (path_exists(
				".watchdogs/compiler.log")) {
				putchar('\n');
				char* ca = NULL;
				ca = pc_temp2;
				bool cb = 0;
				if (pc_debug_options)
					cb = 1;
				if (pctx->flag_detailed) {
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
			/* Check for compilation errors */
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

			/* Calculate and display compilation time */
			elapsed_time = ((double)(post_end.tv_sec - pre_start.tv_sec)) +
						   ((double)(post_end.tv_nsec - pre_start.tv_nsec)) / 1e9;

			putchar('\n');

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
			pbuf[0] = '\0';
			len = snprintf(pbuf, sizeof(pbuf),
				"Cannot locate input: " DOG_COL_CYAN
				"%s" DOG_COL_DEFAULT
				" - No such file or directory\n",
				compile_args_val);
			fwrite(pbuf, 1, len, stdout);
			fflush(stdout);
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

	/* Check for errors and trigger retry if needed */
	bool
		has_stdlib_error = false;

	while (fgets(pbuf, sizeof(pbuf), fp) != NULL) {
		if (strfind(pbuf, "error",
			true) != false) {
			switch (pc_retry_state)
			{
			case PC_RETRY_STATE_NONE:
				pc_retry_state = PC_RETRY_STATE_FIRST;
				pbuf[0] = '\0';
				len = snprintf(pbuf, sizeof(pbuf),
					DOG_COL_BCYAN
					"** Compilation Process Exit with Failed. "
					"recompiling: "
					"%d/2\n"
					DOG_COL_DEFAULT, pc_retry_state);
				fwrite(pbuf, 1, len, stdout);
				fflush(stdout);
				goto _pc_retry_state;
			case PC_RETRY_STATE_FIRST:
				pc_retry_state = PC_RETRY_STATE_FINAL;
				pbuf[0] = '\0';
				len = snprintf(pbuf, sizeof(pbuf),
					DOG_COL_BCYAN
					"** Compilation Process Exit with Failed. "
					"recompiling: "
					"%d/2\n"
					DOG_COL_DEFAULT, pc_retry_state);
				fwrite(pbuf, 1, len, stdout);
				fflush(stdout);
				goto _pc_retry_state;
			}
		}
		/* Check for missing standard library */
		if ((strfind(pbuf, "a_samp", true) == 1
			&& strfind(pbuf, "cannot read from file", true) == 1)
			|| (strfind(pbuf, "open.mp", true) == 1
				&& strfind(pbuf, "cannot read from file", true) == 1))
		{
			has_stdlib_error = true;
		}
	}

	if (fp)
		fclose(fp);

	if (has_stdlib_error == true) {
		pc_missing_stdlib = true;
	}

	goto pc_end;

pc_end:
	/* Cleanup temporary files */
	if (dog_find_path(".watchdogs", "*_temp", NULL) > 0) {
		for (int i = 0; i < fet_sef_ent; i++) {
			remove(dogconfig.dog_sef_found_list[i]);
		}
		_sef_restore();
	}
	return (1);
_print_time:
	print(
		"** Process is taking a while..\n");
	if (pc_time_issue == false) {
		pr_info(stdout, "Retrying..");
		pc_time_issue = true;
		goto _pc_retry_state;
	}
	return (1);
}