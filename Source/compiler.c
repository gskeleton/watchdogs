#include  "utils.h"
#include  "units.h"
#include  "library.h"
#include  "debug.h"
#include  "crypto.h"
#include  "cause.h"
#include  "extra/process.h"
#include  "compiler.h"

// Maps bit flags to their corresponding command-line option strings
const CompilerOption object_opt[] = {
{ BIT_FLAG_DEBUG,     " -d:2 ", 5 },
{ BIT_FLAG_ASSEMBLER, " -a "  , 4 },
{ BIT_FLAG_COMPAT,    " -Z:+ ", 5 },
{ BIT_FLAG_PROLIX,    " -v:2 ", 5 },
{ BIT_FLAG_COMPACT,   " -C:+ ", 5 },
{ BIT_FLAG_TIME,      " -d:3 ", 5 },
{ 0, NULL, 0 }
};

/*
 * Command-line flag mapping table.
 * Maps long and short option names to their corresponding flag variables.
 */
static bool compiler_dog_flag_detailed = false;	// Detailed output
bool compiler_dog_flag_clean = false; // Clean compilation
static bool compiler_dog_flag_asm = false; // Assembler output
static bool compiler_dog_flag_compat = false; // Compatibility mode
static bool compiler_dog_flag_prolix = false; // Verbose output
static bool compiler_dog_flag_compact = false; // Compact output
bool compiler_dog_flag_fast = false;	// Fast compilation
bool compiler_debug_flag_is_exists = false; // Debug flag presence indicator

#define _detailed "--detailed"
#define _watchdogs "--watchdogs"
#define _debug "--debug"
#define _clean "--clean"
#define _assembler "--assembler"
#define _compat "--compat"
#define _compact "--compact"
#define _prolix "--prolix"
#define _fast "--fast"

static OptionMap compiler_all_flag_map[] = {
    {_detailed,       "-w",
    	&compiler_dog_flag_detailed},
    {_watchdogs,      "-w",
    	&compiler_dog_flag_detailed},
    {_debug,          "-d",
    	&compiler_debug_flag_is_exists},
    {_clean,          "-n",
    	&compiler_dog_flag_clean},
    {_assembler,      "-a",
    	&compiler_dog_flag_asm},
    {_compat,         "-c",
    	&compiler_dog_flag_compat},
    {_compact,        "-m",
    	&compiler_dog_flag_compact},
    {_prolix,         "-p",
    	&compiler_dog_flag_prolix},
    {_fast,           "-f",
    	&compiler_dog_flag_fast},
    {NULL, NULL, NULL}
};

// compiler_show_tip
// show available options
static
void compiler_show_tip(void) {
    static const char *tip_options =
    DOG_COL_BCYAN " o [--watchdogs/--detailed/-w] * Enable detailed watchdog output\n"
    DOG_COL_BCYAN " o [--debug/-d]                * Enable debugger options\n"
    DOG_COL_BCYAN " o [--prolix/-p]               * Enable verbose compilation\n"
    DOG_COL_BCYAN " o [--assembler/-a]            * Show assembler output\n"
    DOG_COL_BCYAN " o [--compact/-m]              * Use compact encoding\n"
    DOG_COL_BCYAN " o [--compat/-c]               * Active cross path separator\n"
    DOG_COL_BCYAN " o [--fast/-f]                 * Enable faster compilation mode\n"
    DOG_COL_BCYAN " o [--clean/-n]                * Enable safe mode or clean mode\n";
    fwrite(tip_options, 1, strlen(tip_options), stdout);
    print_restore_color();
    return;
}

 /*
 * Timing structures for measuring compilation duration.
 * pre_start and post_end record the start and end times
 * of the compilation process.
 */
struct
timespec pre_start = { 0 },
post_end           = { 0 };
static double  escape_time;	/* Calculated compilation time in seconds */
static         io_compilers  dog_compiler_sys; /* Compiler I/O context structure */
static FILE   *this_proc_file = NULL; /* File handle for compiler log */
bool           compiler_installing_stdlib = NULL; /* Flag indicating stdlib installation status */
bool           compiler_is_err = false;	/* Global error state flag */
static int     compiler_retry_stat = 0;	/* Retry attempt counter */
bool           compiler_input_debug = false; /* Enable debug output for compiler input */
static bool    compiler_time_issue = false;	/* Flag for long-running compilations */
bool           compiler_dog_flag_debug = false;	/* Debug mode flag */
static bool    compiler_target_ready = false; /* compiler target initialize */
char          *compiler_full_includes = NULL; /* Full include path string */
static char    compiler_temp[DOG_PATH_MAX + 28] = { 0 }; /* Temporary path buffer */
static char    compiler_buf[DOG_MAX_PATH] = { 0 };	/* General purpose buffer */
static char    compiler_mb[128] = { 0 }; /* Small message buffer */
static char    compiler_parsing[DOG_PATH_MAX] = { 0 }; /* Path parsing buffer */
char           compiler_path_include_buf[DOG_PATH_MAX] = { 0 };	/* Include path buffer */
static char    flag_stock[456] = { 0 };	/* Flag list string buffer */
static char   *server_path = NULL; /* Project path pointer */
static char   *compiler_back_slash = NULL; /* Backslash position pointer */
static char   *compiler_size_last_slash = NULL;	/* Last path separator position */
static char   *size_include_extra = NULL; /* Extra include size pointer */
static char   *procure_string_pos = NULL; /* String position pointer */
bool           process_file_success = false;	/* Unix file operation failure flag */

/*
 * compiler_refresh_data
 * Reset all compiler state variables and memory buffers to their initial state.
 * Creates the .watchdogs directory if it doesn't exist and resets all
 * timing, boolean flags, pointers, and memory buffers.
 */
static
void
compiler_refresh_data ( void )  {

	if ( dir_exists( ".watchdogs" ) == 0 )
		MKDIR( ".watchdogs" );

	/* sef reset */
	dog_sef_path_revert();

	/* time reset */
	memset(&pre_start, 0, sizeof(pre_start));
	memset(&post_end, 0, sizeof(post_end));

	/* bool reset */
	compiler_dog_flag_detailed = false, compiler_dog_flag_debug = false,
	compiler_dog_flag_clean = false, compiler_dog_flag_asm = false,
	compiler_dog_flag_compat = false, compiler_dog_flag_prolix = false,
	compiler_dog_flag_compact = false, compiler_time_issue = false,
	process_file_success = false,
	compiler_retry_stat = 0, compiler_target_ready = false;

	/* pointer reset */
	this_proc_file = NULL, compiler_size_last_slash = NULL,
	compiler_back_slash = NULL, size_include_extra = NULL,
	procure_string_pos = NULL;

	/* memory reset */
	memset(&dog_compiler_sys, 0, sizeof(io_compilers));
	memset(compiler_parsing, 0, sizeof(compiler_parsing));
	memset(compiler_temp, 0, sizeof(compiler_temp));
	memset(compiler_mb, 0, sizeof(compiler_mb));
	memset(compiler_path_include_buf, 0,
	    sizeof(compiler_path_include_buf));
	memset(compiler_buf, 0, sizeof(compiler_buf));
	memset(flag_stock, 0,
	    sizeof(flag_stock));
}

void _compiler_bitmask_start(void) {
	unsigned int __set_bit = 0;

	if (compiler_dog_flag_debug)
		/* bit 0 = 1 (  0x01  ) */
		__set_bit |= BIT_FLAG_DEBUG;

	if (compiler_dog_flag_asm)
		/* bit 1 = 1 (  0x03  ) */
		__set_bit |= BIT_FLAG_ASSEMBLER;

	if (compiler_dog_flag_compat)
		/* bit 2 = 1 (  0x07  ) */
		__set_bit |= BIT_FLAG_COMPAT;

	if (compiler_dog_flag_prolix)
		/* bit 3 = 1 (  0x0F  ) */
		__set_bit |= BIT_FLAG_PROLIX;

	if (compiler_dog_flag_compact)
		/* bit 4 = 1 (  0x1F  ) */
		__set_bit |= BIT_FLAG_COMPACT;

	if (compiler_dog_flag_fast)
		/* bit 5 = 1 (  0x20  ) */
		__set_bit |= BIT_FLAG_TIME;

	/* Build flag string from enabled options */
	char *p = flag_stock;
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

/*
 * dog_exec_compiler
 * Main compiler execution function. This function orchestrates the
 * entire compilation process including finding the compiler executable,
 * parsing command-line arguments, setting up compiler flags, handling
 * input file paths, executing the compilation, and processing results.
 * Supports both default project compilation and explicit file compilation.
 */
int
dog_exec_compiler(const char *args, const char *compile_args_val,
    const char *second_arg, const char *four_arg, const char *five_arg,
    const char *six_arg, const char *seven_arg, const char *eight_arg,
    const char *nine_arg, const char *ten_arg)
{
	io_compilers   all_compiler_field;
	io_compilers  *ctx = &all_compiler_field;
	size_t	       fet_sef_ent;
	char          *gamemodes_slash = "gamemodes/";
	char          *gamemodes_back_slash = "gamemodes\\";
	#ifdef DOG_LINUX
	const 	char  *posix_fzf_path[] = {
      		"download", /* download/folders/files */
			"~/downloads", /* ~/downloads/folder/files */
			/* ../storage/shared/Download/folders/files */
			ANDROID_DOWNLOADS,
			".", /* root/folder/files */
			NULL};
  	// buf selection
	char posix_fzf_select[1024];
	// buf finder
  	char posix_fzf_finder[2048];
	#endif

	print(DOG_COL_DEFAULT);

	/* Match input file against found file list */
	fet_sef_ent = sizeof(dogconfig.dog_sef_found_list) /
					   sizeof(dogconfig.dog_sef_found_list[0]);

	/* Reset all compiler state */
	compiler_refresh_data();

	/* Handle null to empty */
	if (compile_args_val == NULL) {
		compile_args_val = "";
	}

	/* Converting Path Separator */
	char *new_compile_args_val = strdup(compile_args_val);
	if (compile_args_val[0] != '\0') {
		char *p;
		
		#ifdef DOG_LINUX
		for (p = new_compile_args_val; *p; p++) {
				if (*p == _PATH_CHR_SEP_WIN32)
					*p = _PATH_CHR_SEP_POSIX;
			}
		#else
		for (p = new_compile_args_val; *p; p++) {
				if (*p == _PATH_CHR_SEP_POSIX)
					*p = _PATH_CHR_SEP_WIN32;
			}
		#endif
	}

	/* Process command-line flags if compiler was found */
	if (dogconfig.dog_pawncc_path[0] != '\0') {
		/* Build argument array from variadic parameters */
		const char *argv_buf[] = {
			second_arg,four_arg,five_arg,six_arg,seven_arg,eight_arg,nine_arg,ten_arg
		};
		/* Parse command-line arguments and set corresponding flags */
		for (int i = 0; i < 8 && argv_buf[i] != NULL; ++i)
		{
			const char *options = argv_buf[i];

			if (options[0] != '-')
				continue;

			OptionMap *opt;
			for (opt = compiler_all_flag_map; opt->full_name; ++opt) {
				if (strcmp(options, opt->full_name) == 0 ||
					strcmp(options, opt->short_name) == 0)
				{
					*(opt->flag_ptr) = true;
					break;
				}
			}
		}

		/* Handle clean flag: reset all compiler flags */
			if (false != compiler_dog_flag_clean)
		{
			memset(compiler_buf, 0, sizeof(compiler_buf));
			snprintf(compiler_buf, sizeof(compiler_buf),
				" ");
			if (dogconfig.dog_toml_all_flags)
				{
					free(dogconfig.dog_toml_all_flags);
					dogconfig.dog_toml_all_flags = NULL;
				}
			dogconfig.dog_toml_all_flags
				= strdup(compiler_buf);

			goto apply_dbg;
		}

		/* Retry logic for failed compilations with adjusted parameters */
	_compiler_retry_stat:
		switch(compiler_retry_stat)
		{
		case 1:
			compiler_dog_flag_compat = true, compiler_dog_flag_compact = true;
			compiler_dog_flag_fast = true, compiler_dog_flag_detailed = true;
			memset(compiler_buf, 0, sizeof(compiler_buf));
			snprintf(compiler_buf, sizeof(compiler_buf),
				"%s MAX_PLAYERS=50 MAX_VEHICLES=50 MAX_ACTORS=50 MAX_OBJECTS=1000",
				dogconfig.dog_toml_all_flags);
			if (dogconfig.dog_toml_all_flags)
				{
					free(dogconfig.dog_toml_all_flags);
					dogconfig.dog_toml_all_flags = NULL;
				}
			dogconfig.dog_toml_all_flags = strdup(compiler_buf);
		case 2:
			memset(compiler_buf, 0, sizeof(compiler_buf));
			snprintf(compiler_buf, sizeof(compiler_buf),
				"MAX_PLAYERS=100 MAX_VEHICLES=1000 MAX_ACTORS=100 MAX_OBJECTS=2000");
			if (dogconfig.dog_toml_all_flags)
				{
					free(dogconfig.dog_toml_all_flags);
					dogconfig.dog_toml_all_flags = NULL;
				}
			dogconfig.dog_toml_all_flags = strdup(compiler_buf);

			goto apply_dbg;
		}
		if (false != compiler_time_issue) {
			compiler_dog_flag_compat = true, compiler_dog_flag_compact = true;
			compiler_dog_flag_fast = true, compiler_dog_flag_detailed = true;
			memset(compiler_buf, 0, sizeof(compiler_buf));
			snprintf(compiler_buf, sizeof(compiler_buf),
				"%s MAX_PLAYERS=50 MAX_VEHICLES=50 MAX_ACTORS=50 MAX_OBJECTS=1000",
				dogconfig.dog_toml_all_flags);
			if (dogconfig.dog_toml_all_flags)
				{
					free(dogconfig.dog_toml_all_flags);
					dogconfig.dog_toml_all_flags = NULL;
				}
			dogconfig.dog_toml_all_flags = strdup(compiler_buf);
		}

		/* Build bitmask of enabled compiler flags */
		_compiler_bitmask_start();

	/* Merge flag list with existing compiler flags */
	apply_dbg:
		if (compiler_retry_stat == 2)
			flag_stock[0] = '\0';
		if (compiler_dog_flag_detailed)
			compiler_input_debug = true;
#if defined(_DBG_PRINT)
		compiler_input_debug = true;
#endif
		/* Append flag list to existing compiler flags */
		if (strlen(flag_stock) > 0) {
			size_t calcute_len_all_flags = 0;

			if (dogconfig.dog_toml_all_flags) {
				calcute_len_all_flags =
					strlen(dogconfig.dog_toml_all_flags);
			} else {
				dogconfig.dog_toml_all_flags = strdup("");
			}

			size_t extra_len =
				strlen(flag_stock);
			char *new_ptr = dog_realloc(
				dogconfig.dog_toml_all_flags,
				calcute_len_all_flags + extra_len + 1);

			if (!new_ptr) {
				pr_error(stdout,
					"Memory allocation failed for extra options");
				return (-2);
			}

			dogconfig.dog_toml_all_flags = new_ptr;
			strcat(dogconfig.dog_toml_all_flags,
				flag_stock);
		}

		/* Show tip message if no flags were specified */
		static bool rate_flag_notice = false;
		if (!compiler_dog_flag_detailed && !compiler_dog_flag_debug &&
			!compiler_dog_flag_clean && !compiler_dog_flag_asm &&
			!compiler_dog_flag_compat && !compiler_dog_flag_prolix &&
			!compiler_dog_flag_compact && !rate_flag_notice) {
			print("\n");
			compiler_show_tip();
			print("\n");
			rate_flag_notice = true;
		}

		#ifdef DOG_ANDROID
			/* Disable warning 200 (truncated char) by default on Android */
			memset(compiler_buf, 0, sizeof(compiler_buf));
			snprintf(compiler_buf, sizeof(compiler_buf), "%s -w:200-",
				dogconfig.dog_toml_all_flags);
			dog_free(dogconfig.dog_toml_all_flags);
			dogconfig.dog_toml_all_flags = strdup(compiler_buf);
		#endif

		printf(DOG_COL_DEFAULT);

        if (new_compile_args_val[0] == '\0')
            goto skip_parent;
        
        /* Handle parent directory references in compile arguments */
        for (;;) {
            if (strfind(new_compile_args_val, "../", true) !=
                false) {
                char *tmp_args = strdup(new_compile_args_val);
                if (!tmp_args)
                    break;
                size_t
                    write_pos = 0, j,
                    read_cur = 0, scan_idx;
                bool
                    parent_ready = false;
                for (j = 0; tmp_args[j] != '\0';) {
                    if (!parent_ready && !strncmp(&tmp_args[j], "../", 3)) {
                        j += 3;
                        while (tmp_args[j] != '\0' && tmp_args[j] != ' ' &&
                               tmp_args[j] != '"')
                        {
                            compiler_parsing[write_pos++]
                                = tmp_args[j++];
                        }
                        for (scan_idx = 0; scan_idx < write_pos; scan_idx++) {
                            if (compiler_parsing[scan_idx] ==
                                _PATH_CHR_SEP_POSIX ||
                                compiler_parsing[scan_idx] ==
                                _PATH_CHR_SEP_WIN32)
                            {
                                read_cur =
                                    scan_idx + 1;
                            }
                        }
                        if (read_cur > 0) {
                            write_pos = read_cur;
                        }
                        parent_ready = !parent_ready;
                        break;
                    } else { ++j; }
                }

                dog_free(tmp_args);

                if (!parent_ready && write_pos < 1) {
                    strcpy(compiler_parsing, "../");
                    goto parent_next;
                }

                const int push_integar = 3;
                memmove(compiler_parsing + push_integar, compiler_parsing, write_pos);
                memcpy(compiler_parsing, "../", push_integar);
                write_pos += push_integar;
                compiler_parsing[write_pos] = '\0';
                
                if (compiler_parsing[write_pos - 1] != _PATH_CHR_SEP_POSIX &&
                    compiler_parsing[write_pos - 1] != _PATH_CHR_SEP_WIN32)
                    { strcat(compiler_parsing, "/"); }

            parent_next:
                memset(compiler_temp, 0, sizeof(compiler_temp));
                strcpy(compiler_temp, compiler_parsing);

                if (strstr(compiler_temp, gamemodes_slash) ||
                    strstr(compiler_temp, gamemodes_back_slash))
                {
                    char *p = strstr(compiler_temp,
                        gamemodes_slash);
                    if (!p)
                        p = strstr(compiler_temp,
                            gamemodes_back_slash);
                    if (p)
                        *p = '\0';
                }

                char *rets = strdup(dogconfig.dog_toml_all_flags);

                memset(compiler_buf, 0, sizeof(compiler_buf));

                if (!strstr(rets, "gamemodes/") &&
                    !strstr(rets, "pawno/include/") &&
                    !strstr(rets, "qawno/include/"))
                {
                    snprintf(compiler_buf, sizeof(compiler_buf),
                        "-i" "=\"%s\""
                        "-i" "=\"%s" "gamemodes/\" "
                        "-i" "=\"%s" "pawno/include/\" "
                        "-i" "=\"%s" "qawno/include/\" ",
                    compiler_temp, compiler_temp, compiler_temp, compiler_temp);
                } else {
                    snprintf(compiler_buf, sizeof(compiler_buf),
                        "-i" "=\"%s\"",
                        compiler_temp);
                }

                if (rets) {
                    free(rets);
                    rets = NULL;
                }

                strncpy(compiler_path_include_buf, compiler_buf,
                    sizeof(compiler_path_include_buf) - 1);
                compiler_path_include_buf[
                    sizeof(compiler_path_include_buf) - 1] = '\0';
            } else {
                snprintf(compiler_path_include_buf, sizeof(compiler_path_include_buf),
                    "-i=none");
            }
            break;
        }

    skip_parent:
		if (*new_compile_args_val == '\0' ||
			(new_compile_args_val[0] == '.' &&
			new_compile_args_val[1] == '\0')) {
			/* Prompt user for compilation target if not specified */
			if (new_compile_args_val[0] != '.')
			{
				if (compiler_target_ready == true)
					goto answer_done;
				compiler_target_ready = !compiler_target_ready;
				pr_color(stdout, DOG_COL_YELLOW,
					DOG_COL_BYELLOW
					"** COMPILER TARGET\n");
				print("-------------------------------------\n");
				printf(
					"|- * You run the compiler command "
					"without any args: compile\n"
					"|- * Do you want to compile for "
					DOG_COL_GREEN "%s " DOG_COL_DEFAULT
					"(enter), \n"
					"|- * or do you want to compile for something else?\n",
					dogconfig.dog_toml_serv_input);
				#ifndef DOG_LINUX
					goto manual_configure;
				#else
				char *argv[] = {
					"command", "-v",
					"fzf", ">",
					"/dev/null", "2>&1",
					NULL
				};
				int fzf_ok = 2;

				fzf_ok = dog_exec_command(argv);

				if (fzf_ok == 0) {
					printf(DOG_COL_CYAN ">"
						DOG_COL_DEFAULT
						" [Using fzf, press Ctrl+C for: "
						DOG_COL_GREEN "%s" DOG_COL_DEFAULT "]\n",
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
						"-o -name \"*.p\" \\) "
						"2>/dev/null",
						sizeof(posix_fzf_finder));

					memset(compiler_buf,
						0, sizeof(compiler_buf));

					snprintf(compiler_buf, sizeof(compiler_buf),
						"%s | fzf "
						"--height 40%% --reverse "
						"--prompt 'Select file to compile: ' "
						"--preview 'if [ -f {} ]; then "
						"echo \"=== Preview ===\"; "
						"head -n 20 {}; "
						"echo \"=== Path ===\"; "
						"realpath {}; fi'",
						posix_fzf_finder);

					this_proc_file = popen(compiler_buf, "r");
					if (this_proc_file == NULL)
						goto compiler_end;

					if (fgets(compiler_buf,
						sizeof(compiler_buf),
						this_proc_file) == NULL)
						goto fzf_end;

					compiler_buf[strcspn(compiler_buf, "\n")] = '\0';
					if (compiler_buf[0] == '\0')
						goto fzf_end;

					strlcpy(posix_fzf_select,
						compiler_buf,
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
					pclose(this_proc_file);
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
                /* Creating list */
                one_show = !one_show;
                int tree_ret = -1;
                {
                    char *tree[] = { "tree", ">", "/dev/null 2>&1", NULL };
                    tree_ret = dog_exec_command(tree);
                }
                if (!tree_ret) {
                    if (path_exists(ANDROID_DOWNLOADS)) {
                        char *tree[] = {
                            "tree", "-P",
                            "\"*.p\"", "-P",
                            "\"*.pawn\"", "-P",
                            "\"*.pwn\"", ANDROID_DOWNLOADS,
                            NULL
                        };
                        dog_exec_command(tree);
                    } else {
                        char *tree[] = {
                            "tree", "-P",
                            "\"*.p\"", "-P",
                            "\"*.pawn\"", "-P",
                            "\"*.pwn\"", ".",
                            NULL
                        };
                        dog_exec_command(tree);
                    }
                } else {
                    #ifdef DOG_LINUX
                    if (path_exists(ANDROID_DOWNLOADS) == 1) {
                        char *argv[] = { "ls", ANDROID_DOWNLOADS, "-R", NULL };
                        dog_exec_command(argv);
                    } else {
                        char *argv[] = { "ls", ".", "-R", NULL };
                        dog_exec_command(argv);
                    }
                    #else
                    char *argv[] = { "dir", ".", "-s", NULL };
                    dog_exec_command(argv);
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
            char *compiler_target = NULL;
            compiler_target = readline(" ");
            if (compiler_target &&
                strlen(compiler_target) > 0) {
                dog_free(
                    dogconfig.dog_toml_serv_input);
                dogconfig.dog_toml_serv_input =
                    strdup(compiler_target);
                if (!dogconfig.dog_toml_serv_input) {
                    pr_error(stdout,
                        "Memory allocation failed");
                    dog_free(compiler_target);
                    goto compiler_end;
                }
            }
            free(compiler_target);
            compiler_target = NULL;
		answer_done:
			/* Copying path for output */
			char *copy_input
				= strdup(dogconfig.dog_toml_serv_input);
			char *extension
				= strrchr(copy_input, '.');
			if (extension)
				*extension = '\0';
			char end_output[DOG_PATH_MAX];
			snprintf(end_output, DOG_PATH_MAX,
				"%s.amx", copy_input);
			dogconfig.dog_toml_serv_output
				= strdup(end_output);
			dog_free(copy_input);

			if (path_exists(dogconfig.dog_toml_serv_input) == 0) {
				printf(
					"Cannot locate input: " DOG_COL_CYAN
					"%s" DOG_COL_DEFAULT
					" - No such file or directory\n",
					dogconfig.dog_toml_serv_input);
				goto compiler_end;
			}

            dog_free(new_compile_args_val);
            new_compile_args_val = strdup(dogconfig.dog_toml_serv_input);
            
    		/* Handle parent directory references in compile arguments */
    		for (;;) {
    			if (strfind(new_compile_args_val, "../", true) !=
    				false) {
    				char *tmp_args = strdup(new_compile_args_val);
    				if (!tmp_args)
    					break;
    				size_t
    					write_pos = 0, j,
    					read_cur = 0, scan_idx;
    				bool
    					parent_ready = false;
    				for (j = 0; tmp_args[j] != '\0';) {
    					if (!parent_ready && !strncmp(&tmp_args[j], "../", 3)) {
    						j += 3;
    						while (tmp_args[j] != '\0' && tmp_args[j] != ' ' &&
    							   tmp_args[j] != '"')
    						{
    							compiler_parsing[write_pos++]
    								= tmp_args[j++];
    						}
    						for (scan_idx = 0; scan_idx < write_pos; scan_idx++) {
    							if (compiler_parsing[scan_idx] ==
    								_PATH_CHR_SEP_POSIX ||
    								compiler_parsing[scan_idx] ==
    								_PATH_CHR_SEP_WIN32)
    							{
    								read_cur =
    									scan_idx + 1;
    							}
    						}
    						if (read_cur > 0) {
    							write_pos = read_cur;
    						}
    						parent_ready = !parent_ready;
    						break;
    					} else { ++j; }
    				}
    
    				dog_free(tmp_args);
    
    				if (!parent_ready && write_pos < 1) {
    					strcpy(compiler_parsing, "../");
    					goto parent_next2;
    				}
    
    				const int push_integar = 3;
    				memmove(compiler_parsing + push_integar, compiler_parsing, write_pos);
    				memcpy(compiler_parsing, "../", push_integar);
    				write_pos += push_integar;
    				compiler_parsing[write_pos] = '\0';
    				
    				if (compiler_parsing[write_pos - 1] != _PATH_CHR_SEP_POSIX &&
    					compiler_parsing[write_pos - 1] != _PATH_CHR_SEP_WIN32)
    					{ strcat(compiler_parsing, "/"); }
    
    			parent_next2:
    				memset(compiler_temp, 0, sizeof(compiler_temp));
    				strcpy(compiler_temp, compiler_parsing);
    
    				if (strstr(compiler_temp, gamemodes_slash) ||
    					strstr(compiler_temp, gamemodes_back_slash))
    				{
    					char *p = strstr(compiler_temp,
    						gamemodes_slash);
    					if (!p)
    						p = strstr(compiler_temp,
    							gamemodes_back_slash);
    					if (p)
    						*p = '\0';
    				}
    
    				char *rets = strdup(dogconfig.dog_toml_all_flags);
    
    				memset(compiler_buf, 0, sizeof(compiler_buf));
    
    				if (!strstr(rets, "gamemodes/") &&
    					!strstr(rets, "pawno/include/") &&
    					!strstr(rets, "qawno/include/"))
    				{
    					snprintf(compiler_buf, sizeof(compiler_buf),
    						"-i" "=\"%s\""
    						"-i" "=\"%s" "gamemodes/\" "
    						"-i" "=\"%s" "pawno/include/\" "
    						"-i" "=\"%s" "qawno/include/\" ",
    					compiler_temp, compiler_temp, compiler_temp, compiler_temp);
    				} else {
    					snprintf(compiler_buf, sizeof(compiler_buf),
    						"-i" "=\"%s\"",
    						compiler_temp);
    				}
    
    				if (rets) {
    					free(rets);
    					rets = NULL;
    				}
    
    				strncpy(compiler_path_include_buf, compiler_buf,
    					sizeof(compiler_path_include_buf) - 1);
    				compiler_path_include_buf[
    					sizeof(compiler_path_include_buf) - 1] = '\0';
    			} else {
    				snprintf(compiler_path_include_buf, sizeof(compiler_path_include_buf),
    					"-i=none");
    			}
    			break;
    		}
            
			/* Execute compilation process */
			int _process = dog_exec_compiler_process(
					dogconfig.dog_pawncc_path,
					dogconfig.dog_toml_serv_input,
					dogconfig.dog_toml_serv_output);
			if (_process != 0) {
				goto compiler_end;
			}

			/* Process compiler log output */
			if (path_exists(".watchdogs/compiler.log")) {
				print("\n");
				char *ca = NULL;
				ca = dogconfig.dog_toml_serv_output;
				bool cb = 0;
				if (compiler_debug_flag_is_exists)
					cb = 1;
				if (compiler_dog_flag_detailed) {
					cause_compiler_expl(
						".watchdogs/compiler.log",
						ca, cb);
					goto compiler_done;
				}

				if (process_file_success == false)
					dog_printfile(
						".watchdogs/compiler.log");
			}
		compiler_done:
			/* Check log file for compilation errors */
			this_proc_file = fopen(".watchdogs/compiler.log",
				"r");
			if (this_proc_file) {
				bool has_err = false;
				while (fgets(compiler_mb,
					sizeof(compiler_mb),
					this_proc_file)) {
					if (strfind(compiler_mb,
						"error", true)) {
						has_err = false;
						break;
					}
				}
				fclose(this_proc_file);
				this_proc_file = NULL;
				if (has_err) {
					if (dogconfig.dog_toml_serv_output != NULL &&
						path_access(dogconfig.dog_toml_serv_output))
						remove(dogconfig.dog_toml_serv_output);
					compiler_is_err = true;
				} else {
					compiler_is_err = false;
				}
			} else {
				pr_error(stdout,
					"Failed to open .watchdogs/compiler.log");
				minimal_debugging();
			}

			/* Calculate and display compilation time */
			escape_time = ((double)(post_end.tv_sec - pre_start.tv_sec)) +
                          ((double)(post_end.tv_nsec - pre_start.tv_nsec)) / 1e9;

			print("\n");

			if (!compiler_is_err)
				print("** Completed Tasks.\n");
			print(DOG_COL_YELLOW "-----------------------------\n" DOG_COL_DEFAULT);

			pr_color(stdout, DOG_COL_CYAN,
				" <C> (compile-time) Complete At %.3fs (%.0f ms)\n",
				escape_time,
				escape_time * 1000.0);
			if (escape_time > 300) {
				goto _print_time;
			}
		} else {
			/* Handle explicit file compilation (not default project) */

            /* Validate file extension */
            if (strfind(new_compile_args_val, ".pwn", true) == false &&
                strfind(new_compile_args_val, ".pawn", true) == false &&
                strfind(new_compile_args_val, ".p", true) == false)
            {
                pr_warning(stdout, "The compiler only accepts '.p' '.pawn' and '.pwn' files.");
                goto compiler_end;
            }

			/* Parse input file path to extract directory and filename */
			strncpy(ctx->compiler_size_temp,
				new_compile_args_val,
				sizeof(ctx->compiler_size_temp) -
				1);
			ctx->compiler_size_temp[
				sizeof(ctx->compiler_size_temp) -
				1] = '\0';

			/* Find path separators (handle both Unix and Windows) */
			compiler_size_last_slash = strrchr(
				ctx->compiler_size_temp,
				_PATH_CHR_SEP_POSIX);
			compiler_back_slash = strrchr(
				ctx->compiler_size_temp,
				_PATH_CHR_SEP_WIN32);

			if (compiler_back_slash && (!compiler_size_last_slash ||
				compiler_back_slash > compiler_size_last_slash))
				compiler_size_last_slash =
					compiler_back_slash;

			/* Extract directory and filename components */
			if (compiler_size_last_slash) {
				size_t compiler_dir_len;
				compiler_dir_len = (size_t)
					(compiler_size_last_slash -
					ctx->compiler_size_temp);

				if (compiler_dir_len >=
					sizeof(ctx->compiler_direct_path))
					compiler_dir_len =
						sizeof(ctx->compiler_direct_path) -
						1;

				memcpy(ctx->compiler_direct_path,
					ctx->compiler_size_temp,
					compiler_dir_len);
				ctx->compiler_direct_path[
					compiler_dir_len] = '\0';

				const char *compiler_filename_start =
					compiler_size_last_slash + 1;
				size_t compiler_filename_len;
				compiler_filename_len = strlen(
					compiler_filename_start);

				if (compiler_filename_len >=
					sizeof(ctx->compiler_size_file_name))
					compiler_filename_len =
						sizeof(ctx->compiler_size_file_name) -
						1;

				memcpy(
					ctx->compiler_size_file_name,
					compiler_filename_start,
					compiler_filename_len);
				ctx->compiler_size_file_name[
					compiler_filename_len] = '\0';

				size_t total_needed;
				total_needed =
					strlen(ctx->compiler_direct_path) +
					1 +
					strlen(ctx->compiler_size_file_name) +
					1;

				if (total_needed >
					sizeof(ctx->compiler_size_input_path)) {
					strncpy(ctx->compiler_direct_path,
						"gamemodes",
						sizeof(ctx->compiler_direct_path) -
						1);
					ctx->compiler_direct_path[
						sizeof(ctx->compiler_direct_path) -
						1] = '\0';

					size_t compiler_max_size_file_name;
					compiler_max_size_file_name =
						sizeof(ctx->compiler_size_file_name) -
						1;

					if (compiler_filename_len >
						compiler_max_size_file_name) {
						memcpy(
							ctx->compiler_size_file_name,
							compiler_filename_start,
							compiler_max_size_file_name);
						ctx->compiler_size_file_name[
							compiler_max_size_file_name] =
							'\0';
					}
				}

				if (snprintf(
					ctx->compiler_size_input_path,
					sizeof(ctx->compiler_size_input_path),
					"%s/%s",
					ctx->compiler_direct_path,
					ctx->compiler_size_file_name) >=
					(int)sizeof(
					ctx->compiler_size_input_path)) {
					ctx->compiler_size_input_path[
						sizeof(ctx->compiler_size_input_path) -
						1] = '\0';
				}
			} else {
				strncpy(
					ctx->compiler_size_file_name,
					ctx->compiler_size_temp,
					sizeof(ctx->compiler_size_file_name) -
					1);
				ctx->compiler_size_file_name[
					sizeof(ctx->compiler_size_file_name) -
					1] = '\0';

				strncpy(
					ctx->compiler_direct_path,
					".",
					sizeof(ctx->compiler_direct_path) -
					1);
				ctx->compiler_direct_path[
					sizeof(ctx->compiler_direct_path) -
					1] = '\0';

				if (snprintf(
					ctx->compiler_size_input_path,
					sizeof(ctx->compiler_size_input_path),
					"./%s",
					ctx->compiler_size_file_name) >=
					(int)sizeof(
					ctx->compiler_size_input_path)) {
					ctx->compiler_size_input_path[
						sizeof(ctx->compiler_size_input_path) -
						1] = '\0';
				}
			}

			/* Search for input file in specified directory */
			int compiler_finding_compile_args = 0;
			compiler_finding_compile_args = dog_find_path(
				ctx->compiler_direct_path,
				ctx->compiler_size_file_name,
				NULL);

			/* Fallback to gamemodes directory if not found */
			if (!compiler_finding_compile_args &&
				strcmp(ctx->compiler_direct_path,
				"gamemodes") != 0) {
				compiler_finding_compile_args =
					dog_find_path("gamemodes",
					ctx->compiler_size_file_name,
					NULL);
				if (compiler_finding_compile_args) {
					strncpy(
						ctx->compiler_direct_path,
						"gamemodes",
						sizeof(ctx->compiler_direct_path) -
						1);
					ctx->compiler_direct_path[
						sizeof(ctx->compiler_direct_path) -
						1] = '\0';

					if (snprintf(
						ctx->compiler_size_input_path,
						sizeof(ctx->compiler_size_input_path),
						"gamemodes/%s",
						ctx->compiler_size_file_name) >=
						(int)sizeof(
						ctx->compiler_size_input_path)) {
						ctx->compiler_size_input_path[
							sizeof(ctx->compiler_size_input_path) -
							1] = '\0';
					}

					if (dogconfig.dog_sef_count >
						RATE_SEF_EMPTY)
						strncpy(
							dogconfig.dog_sef_found_list[
							dogconfig.dog_sef_count -
							1],
							ctx->compiler_size_input_path,
							MAX_SEF_PATH_SIZE);
				}
			}

			if (!compiler_finding_compile_args &&
				!strcmp(ctx->compiler_direct_path,
				".")) {
				compiler_finding_compile_args =
					dog_find_path("gamemodes",
					ctx->compiler_size_file_name,
					NULL);
				if (compiler_finding_compile_args) {
					strncpy(
						ctx->compiler_direct_path,
						"gamemodes",
						sizeof(ctx->compiler_direct_path) -
						1);
					ctx->compiler_direct_path[
						sizeof(ctx->compiler_direct_path) -
						1] = '\0';

					if (snprintf(
						ctx->compiler_size_input_path,
						sizeof(ctx->compiler_size_input_path),
						"gamemodes/%s",
						ctx->compiler_size_file_name) >=
						(int)sizeof(
						ctx->compiler_size_input_path)) {
						ctx->compiler_size_input_path[
							sizeof(ctx->compiler_size_input_path) -
							1] = '\0';
					}

					if (dogconfig.dog_sef_count >
						RATE_SEF_EMPTY)
						strncpy(
							dogconfig.dog_sef_found_list[
							dogconfig.dog_sef_count -
							1],
							ctx->compiler_size_input_path,
							MAX_SEF_PATH_SIZE);
				}
			}

			for (int i = 0; i < fet_sef_ent; i++) {
				if (strfind(dogconfig.dog_sef_found_list[i],
					new_compile_args_val, true) == true)
				{
					memset(compiler_temp, 0, sizeof(compiler_temp));
					memset(compiler_buf, 0, sizeof(compiler_buf));

					snprintf(compiler_temp,
						sizeof(compiler_temp), "%s",
						dogconfig.dog_sef_found_list[i]);
					
					snprintf(compiler_buf, sizeof(compiler_buf),
						"%s", compiler_temp);
					if (server_path)
						{
							free(server_path);
							server_path = NULL;
						}
						
					server_path = strdup(compiler_buf);
				}
			}

#if defined(_DBG_PRINT)
			if (server_path != NULL)
				pr_info(stdout, "server_path: %s", server_path);
#endif
			/* Generate output filename and execute compilation */
			if (path_exists(server_path) == 1) {

				if (server_path[0] != '\0') {
					memset(compiler_temp, 0, sizeof(compiler_temp));
					strncpy(compiler_temp, server_path,
						sizeof(compiler_temp) - 1);
					compiler_temp[sizeof(compiler_temp) - 1] = '\0';
				} else {
					memset(compiler_temp, 0, sizeof(compiler_temp));
				}

				/* Remove file extension to generate .amx output name */
				char *extension = strrchr(compiler_temp,
					'.');
				if (extension)
					*extension = '\0';

				ctx->container_output = strdup(compiler_temp);

				snprintf(compiler_temp, sizeof(compiler_temp),
					"%s.amx", ctx->container_output);

				char *compiler_temp2 = strdup(compiler_temp);

				/* Execute compilation process */
				int _process = dog_exec_compiler_process(
						dogconfig.dog_pawncc_path,
						server_path,
						compiler_temp2);
				if (_process != 0) {
					goto compiler_end;
				}
				if (server_path) {
					free(server_path);
					server_path = NULL;
				}

				if (path_exists(
					".watchdogs/compiler.log")) {
					print("\n");
					char *ca = NULL;
					ca = compiler_temp2;
					bool cb = 0;
					if (compiler_debug_flag_is_exists)
						cb = 1;
					if (compiler_dog_flag_detailed) {
						cause_compiler_expl(
							".watchdogs/compiler.log",
							ca, cb);
						goto compiler_done2;
					}

					if (process_file_success == false)
						dog_printfile(
							".watchdogs/compiler.log");
				}

		compiler_done2:
				this_proc_file = fopen(
					".watchdogs/compiler.log", "r");
				memset(compiler_mb, 0, sizeof(compiler_mb));
				if (this_proc_file) {
					bool has_err = false;
					while (fgets(
						compiler_mb,
						sizeof(compiler_mb),
						this_proc_file)) {
						if (strfind(
							compiler_mb,
							"error", true)) {
							has_err = true;
							break;
						}
					}
					fclose(this_proc_file);
					this_proc_file = NULL;
					if (has_err) {
						if (compiler_temp2 &&
							path_access(compiler_temp2))
							remove(compiler_temp2);
						compiler_is_err = true;
					} else {
						compiler_is_err = false;
					}
				} else {
					pr_error(stdout,
						"Failed to open .watchdogs/compiler.log");
					minimal_debugging();
				}

				if (compiler_temp2)
					{
						free(compiler_temp2);
						compiler_temp2 = NULL;
					}

				escape_time = ((double)(post_end.tv_sec - pre_start.tv_sec)) +
                              ((double)(post_end.tv_nsec - pre_start.tv_nsec)) / 1e9;

				print("\n");

				if (!compiler_is_err)
					print("** Completed Tasks.\n");
    			print(DOG_COL_YELLOW "-----------------------------\n" DOG_COL_DEFAULT);

				pr_color(stdout, DOG_COL_CYAN,
					" <C> (compile-time) Complete At %.3fs (%.0f ms)\n",
					escape_time,
					escape_time * 1000.0);
				if (escape_time > 300) {
					goto _print_time;
				}
			} else {
				printf(
					"Cannot locate input: " DOG_COL_CYAN
					"%s" DOG_COL_DEFAULT
					" - No such file or directory\n",
					new_compile_args_val);
				goto compiler_end;
			}
		}

		/* Check compiler log for errors and retry logic */
		if (this_proc_file)
			fclose(this_proc_file);

		memset(compiler_mb, 0, sizeof(compiler_mb));

		this_proc_file = fopen(".watchdogs/compiler.log", "rb");

		if (!this_proc_file)
			goto compiler_end;
		if (compiler_time_issue)
			goto compiler_end;

		/* Scan log file for errors and standard library issues */
		bool
		  stdlib_fail=false;

		while (fgets(
				compiler_mb,
				sizeof(compiler_mb),
			this_proc_file) != NULL)
			{
			/* Check for compilation errors and trigger retry if needed */
			if (strfind(compiler_mb, "error",
				true) != false) {
					switch(compiler_retry_stat)
					{
					case 0:
						compiler_retry_stat = 1;
						printf(DOG_COL_BCYAN
							"** Compilation Process Exit with Failed. "
							"recompiling: "
							"%d/2\n"
							BKG_DEFAULT, compiler_retry_stat);
        				fflush(stdout);
						goto _compiler_retry_stat;
					case 1:
						compiler_retry_stat = 2;
						printf(DOG_COL_BCYAN
							"** Compilation Process Exit with Failed. "
							"recompiling: "
							"%d/2\n"
							BKG_DEFAULT, compiler_retry_stat);
        				fflush(stdout);
						goto _compiler_retry_stat;
					}
				}
		    if((strfind(compiler_mb, "a_samp" ,true)
		    	== 1 &&
		    	strfind(compiler_mb, "cannot read from file", true)
		    	== 1) ||
		        (strfind(compiler_mb, "open.mp", true)
		        == 1 &&
		        strfind(compiler_mb, "cannot read from file", true)
		        == 1))
		    {
	        	stdlib_fail = !stdlib_fail;
		    }
			}

		if (this_proc_file)
			fclose(this_proc_file);

		if (stdlib_fail == true) {
			compiler_installing_stdlib = true;
		}

		goto compiler_end;

	} else {
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

/* Cleanup and return */
compiler_end:
	dog_sef_path_revert();
	int ret = dog_find_path(".watchdogs", "*_temp", NULL);
	if (ret) {
		for (int i = 0; i < fet_sef_ent; i++) {
			remove(dogconfig.dog_sef_found_list[i]);
		}
		dog_sef_path_revert();
	}
    fflush(stdout);
    dog_free(new_compile_args_val);
	return (1);
/* Handle long-running compilation with retry */
_print_time:
    fflush(stdout);
	print(
		"** Process is taking a while..\n");
	if (compiler_time_issue == false) {
		pr_info(stdout, "Retrying..");
		compiler_time_issue = true;
		goto _compiler_retry_stat;
	}
	return (1);
}
