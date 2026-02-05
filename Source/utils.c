/*-
 * Copyright (c) 2026 Watchdogs Team and contributors
 * All rights reserved. under The 2-Clause BSD License
 * See COPYING or https://opensource.org/license/bsd-2-clause
 */

#include  "units.h"
#include  "library.h"
#include  "crypto.h"
#include  "debug.h"
#include  "compiler.h"
#include  "utils.h"

static
	char
	stock
	[DOG_MAX_PATH]
		= {0};

const char	*unit_command_list[] = {
	"help", "exit",
	"sha1", "sha256",
	"crc32", "djb2",
	"pbkdf2", "config",
	"replicate", "gamemode",
	"pawncc", "debug",
	"compile", "decompile",
	"running", "compiles",
	"stop", "restart",
	"tracker", "compress"
};

const size_t	 unit_command_len = sizeof(unit_command_list) /
									sizeof(unit_command_list[0]);

WatchdogConfig	 dogconfig = {
	.dog_os_type = CRC32_FALSE,
    .dog_is_samp = CRC32_FALSE,
	.dog_is_omp  = CRC32_FALSE,
	.dog_sef_count = RATE_SEF_EMPTY,
	.dog_sef_found_list = { { RATE_SEF_EMPTY } },
	.dog_pawncc_path = NULL,
	.dog_ptr_samp = NULL,
	.dog_ptr_omp = NULL,
	.dog_toml_os_type = NULL,
	.dog_toml_server_binary = NULL,
	.dog_toml_server_config = NULL,
	.dog_toml_server_logs = NULL,
	.dog_toml_all_flags = NULL,
	.dog_toml_root_patterns = NULL,
	.dog_toml_packages = NULL,
	.dog_toml_serv_input = NULL,
	.dog_toml_serv_output = NULL
};

const char	*toml_char_field[] = {
	"dog_toml_os_type",
	"dog_toml_server_binary",
	"dog_toml_server_config",
	"dog_toml_server_logs",
	"dog_toml_all_flags",
	"dog_toml_root_patterns",
	"dog_toml_packages",
	"dog_toml_serv_input",
	"dog_toml_serv_output"
};

char		**toml_pointers[] = {
	&dogconfig.dog_toml_os_type,
	&dogconfig.dog_toml_server_binary,
	&dogconfig.dog_toml_server_config,
	&dogconfig.dog_toml_server_logs,
	&dogconfig.dog_toml_all_flags,
	&dogconfig.dog_toml_root_patterns,
	&dogconfig.dog_toml_packages,
	&dogconfig.dog_toml_serv_input,
	&dogconfig.dog_toml_serv_output
};

void dog_sef_path_revert(void)
{
	size_t	 i, fet_sef_ent;

	fet_sef_ent
		= sizeof(dogconfig.dog_sef_found_list) /
	    sizeof(dogconfig.dog_sef_found_list[0]);

	for (i = 0; i < fet_sef_ent; i++)
		dogconfig.dog_sef_found_list[i][0] = '\0';

	dogconfig.dog_sef_count
		= RATE_SEF_EMPTY;
	memset(dogconfig.dog_sef_found_list, RATE_SEF_EMPTY,
	    sizeof(dogconfig.dog_sef_found_list));
}

#ifdef DOG_LINUX

#ifndef strlcpy
size_t
strlcpy(char *dst, const char *src, size_t size)
{
	size_t	 src_len = strlen(src);

	if (size) {
		size_t	 copy_len = (src_len >= size) ? size - 1 : src_len;
		memcpy(dst, src, copy_len);
		dst[copy_len] = '\0';
	}
	return (src_len);
}
#endif

#ifndef strlcat
size_t
strlcat(char *dst, const char *src, size_t size)
{
	size_t	 dst_len = strlen(dst);
	size_t	 src_len = strlen(src);

	if (dst_len < size) {
		size_t	 copy_len = size - dst_len - 1;

		if (copy_len > src_len)
			copy_len = src_len;
		memcpy(dst + dst_len, src, copy_len);
		dst[dst_len + copy_len] = '\0';
	}
	return (dst_len + src_len);
}
#endif

#else

size_t
w_strlcpy(char *dst, const char *src, size_t size)
{
	size_t	 len = strlen(src);

	if (size > 0) {
		size_t	 copy = (len >= size) ? size - 1 : len;

		memcpy(dst, src, copy);
		dst[copy] = 0;
	}
	return (len);
}

size_t
w_strlcat(char *dst, const char *src, size_t size)
{
	size_t	 dlen = strlen(dst);
	size_t	 slen = strlen(src);

	if (dlen < size) {
		size_t	 space = size - dlen - 1;
		size_t	 copy = (slen > space) ? space : slen;

		memcpy(dst + dlen, src, copy);
		dst[dlen + copy] = 0;
		return (dlen + slen);
	}
	return (size + slen);
}

#endif

void * dog_malloc(size_t size)
{
	void	*ptr = malloc(size);

	if (!ptr) {
		fprintf(stderr,
			"malloc failed: %zu bytes\n", size);
		minimal_debugging();
	}
	return (ptr);
}

void * dog_calloc(size_t count, size_t size)
{
	void	*ptr = calloc(count, size);

	if (!ptr) {
		fprintf(stderr,
		    "calloc failed: %zu "
			"elements x %zu bytes\n", count, size);
		return (NULL);
	}
	return (ptr);
}

void * dog_realloc(void *ptr, size_t size)
{
	void	*new_ptr
		= (ptr ? realloc(ptr, size) : malloc(size));

	if (!new_ptr) {
		fprintf(stderr,
		"realloc failed: %zu bytes\n", size);
		return (NULL);
	}
	return (new_ptr);
}

void dog_free(void *ptr)
{
	if (ptr) {
		free(ptr);
		ptr = NULL;
	}
	return;
}

bool
fet_server_env(void)
{
	if (strcmp(dogconfig.dog_is_samp, CRC32_TRUE)
		== 0) {
		return (false);
	} else if (strcmp(dogconfig.dog_is_omp, CRC32_TRUE)
		== 0) {
		return (true);
	}
	return false;
}

static
bool
is_running_in_container(void)
{
	FILE	*fp;

	if (path_access("/.dockerenv"))
		return (true);
	if (path_access("/run/.containerenv"))
		return (true);

	memset(stock, 0, sizeof(stock));

	fp = fopen("/proc/1/cgroup", "r");
	if (fp) {
		while (fgets(stock, sizeof(stock), fp)) {
			if (strstr(stock, "/docker/") ||
			    strstr(stock, "/podman/") ||
			    strstr(stock, "/containerd/"))
			{
				fclose(fp);
				return (true);
			}
		}
		fclose(fp);
	}

	return (false);
}

void
path_sep_to_posix(char *path)
{
	char	*pos;

	for (pos = path; *pos; pos++) {
		if (*pos == _PATH_CHR_SEP_WIN32)
			*pos = _PATH_CHR_SEP_POSIX;
	}
}

int
dir_exists(const char *path)
{
	struct stat	 st;

	if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
		return (1);
	return (0);
}

int
path_exists(const char *path)
{
	struct stat	 st;

	if (stat(path, &st) == 0)
		return (1);
	return (0);
}

int
dir_writable(const char *path)
{
	if (access(path, W_OK) == 0)
		return (1);
	return (0);
}

int
path_access(const char *path)
{
	if (access(path, F_OK) == 0)
		return (1);
	return (0);
}

int
file_regular(const char *path)
{
	struct stat	 st;

	if (stat(path, &st) != 0)
		return (0);
	return (S_ISREG(st.st_mode));
}

int
file_same_file(const char *a, const char *b)
{
	struct stat	 sa, sb;

	if (stat(a, &sa) != 0)
		return (0);
	if (stat(b, &sb) != 0)
		return (0);

	return (sa.st_ino == sb.st_ino && sa.st_dev == sb.st_dev);
}

const char
*lookup_path_sep(const char *sep_path) {
    if (!sep_path)
        return NULL;

    const char *_l = strrchr(sep_path, _PATH_CHR_SEP_POSIX);
    const char *_w = strrchr(sep_path, _PATH_CHR_SEP_WIN32);

    if (_l && _w)
        return (_l > _w) ? _l : _w;
    else
        return (_l ? _l : _w);
}

const char * fet_filename(const char *path)
{
	const char	*p = lookup_path_sep(path);

	return (p ? p + 1 : path);
}

char * fet_basename(const char *path)
{
    const char *filename = fet_filename(path);

    char *base = strdup(filename);
    if (!base)
        return NULL;

    char *dot = strrchr(base, '.');

    if (dot) {
        *dot = '\0';
    }

    return base;
}

char * dog_procure_pwd(void)
{
	static char	 dog_work_dir[DOG_PATH_MAX] = { 0 };

	if (dog_work_dir[0] == '\0') {
		if (getcwd(dog_work_dir, sizeof(dog_work_dir)) == NULL) {
			dog_work_dir[0] = '\0';
		}
	}
	return (dog_work_dir);
}

char *
dog_masked_text(int reveal, const char *text)
{
	char	*masked;
	int	 len, i;

	if (!text)
		return (NULL);

	len = (int)strlen(text);
	if (reveal < 0)
		reveal = 0;
	if (reveal > len)
		reveal = len;

	masked = dog_malloc((size_t)len + 1);
	if (!masked)
		unit_ret_main(NULL);

	if (reveal > 0)
		memcpy(masked, text, (size_t)reveal);

	for (i = reveal; i < len; ++i)
		masked[i] = '?';

	masked[len] = '\0';
	return (masked);
}

int dog_mkdir_recursive(const char *path)
{
	char	*p;
	size_t	 len;

	if (!path || !*path)
		return (-1);

	memset(stock, 0, sizeof(stock));

	snprintf(stock, sizeof(stock), "%s", path);
	len = strlen(stock);

	if (len > 1 && stock[len - 1] == '/')
		stock[len - 1] = '\0';

	for (p = stock + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (MKDIR(stock) != 0 && errno != EEXIST) {
				perror("mkdir");
				return (-1);
			}
			*p = '/';
		}
	}

	if (MKDIR(stock) != 0 && errno != EEXIST) {
		perror("mkdir");
		return (-1);
	}

	return (0);
}

int binary_condition_check(char *path) {
	
	int fd;
	struct stat st;

	#ifdef DOG_WINDOWS
	fd = open(path, O_RDONLY | O_BINARY);
	if (fd < 0) {
	    pr_error(stderr, "open failed");
	    minimal_debugging();
	    return (false);
	}
	HANDLE h = (HANDLE)_get_osfhandle(fd);
	SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);
	#else
	fd = open(path, O_RDONLY
	#ifdef O_NOFOLLOW
	    | O_NOFOLLOW
	#endif
	#ifdef O_CLOEXEC
	    | O_CLOEXEC
	#endif
	);
	if (fd < 0) {
	    pr_error(stderr, "open failed");
	    minimal_debugging();
	    return (false);
	}
	#endif

	if (fstat(fd, &st) != 0) {
	    pr_error(stderr, "fstat failed");
	    minimal_debugging();
	    close(fd);
	    return (false);
	}

	if (!S_ISREG(st.st_mode)) {
	    pr_error(stderr, "Not a regular file");
	    minimal_debugging();
	    close(fd);
	    return (false);
	}

	if (!(st.st_mode & S_IXUSR)) {
	    pr_error(stderr, "File not executable");
	    minimal_debugging();
	    close(fd);
	    return (false);
	}

	close(fd);

    return (true);
}

void print_restore_color(void) {

	print(BKG_DEFAULT);
	print(DOG_COL_RESET);
	print(DOG_COL_DEFAULT);

	return;
}

void println(FILE *stream, const char *format, ...) {
	va_list    args;
	va_start(args, format);
	print_restore_color();
	vfprintf(stream, format, args);
	print("\n");
	print_restore_color();
	va_end(args);
	fflush(stream);
}

void
printf_colour(FILE *stream,
			  const char *color,
			  const char *format, ...)
{
	va_list    args;
	va_start(args, format);
	print_restore_color();
	printf("%s", color);
	vfprintf(stream, format, args);
	print_restore_color();
	va_end(args);
	fflush(stream);
}

void
printf_info(FILE *stream, const char *format, ...) {
	va_list    args;
	va_start(args, format);
	print_restore_color();
	print(DOG_COL_YELLOW);
	print("@ Hey!");
	print_restore_color();
	print(": ");
	vfprintf(stream, format, args);
	print("\n");
	va_end(args);
	fflush(stream);
}

void
printf_warning(FILE *stream, const char *format, ...) {
	va_list    args;
	va_start(args, format);
	print_restore_color();
	print(DOG_COL_GREEN);
	print("@ Uh-oh!");
	print_restore_color();
	print(": ");
	vfprintf(stream, format, args);
	print("\n");
	va_end(args);
	fflush(stream);
}

void
printf_error(FILE *stream, const char *format, ...) {
	va_list    args;
	va_start(args, format);
	print_restore_color();
	print(DOG_COL_RED);
	print("@ Oops!");
	print_restore_color();
	print(": ");
	vfprintf(stream, format, args);
	print("\n");
	va_end(args);
	fflush(stream);
}

int
dog_exec_command(char *const av[])
{
    char *p;
    size_t len = 0;
    size_t i;
    size_t rem;
    int rv;
    unsigned char c;
	memset(stock, 0, sizeof(stock));

    if (av == NULL || av[0] == NULL)
        return (-1);

    for (i = 0; i < 256 && av[i] != NULL; i++) {
        if (i >= 255) {
            pr_warning(stdout,
				"too many arguments!");
            return (-1);
        }
    }

    for (i = 0; av[i] != NULL; i++) {
        for (p = av[i]; *p != '\0'; p++) {
            c = (unsigned char)*p;

            if (c == '`' || c == '$' || c == '(' || c == ')' ||
                c == '\n' || c == '|' ||
                c == '!' || c == '?' || c == '[' ||
                c == ']' || c == '{' || c == '}') {
                    pr_warning(stdout,
                    	"shell injection potent: %s", p);
                	printf("  like: file.txt; rm name.txt - potent!..\n");
            }

            if (c == '.' && p[1] == '.' && p[2] == '/') {
                pr_warning(stdout,
                    "path traversal attempt detected (../)");
            }
        }

        if (i > 0) {
            rem = sizeof(stock) - len;
            if (rem < 2) {
                pr_warning(stdout, "command buffer exhausted!");
                return (-1);
            }
            stock[len++] = ' ';
            stock[len] = '\0';
        }

        rem = sizeof(stock) - len;
        rv = snprintf(stock + len, rem, "%s", av[i]);
        if (rv < 0) {
            pr_warning(stdout, "snprintf failed!");
            return (-1);
        }
        if ((size_t)rv >= rem) {
            pr_warning(stdout, "command truncated!");
            return (-1);
        }
        len += (size_t)rv;
    }

    if (len == 0 || len >= sizeof(stock)) {
        pr_warning(stdout, "invalid command length!");
        return (-1);
    }

    char *cmd = strdup(stock);
    if (cmd == NULL) {
        pr_warning(stdout, "memory allocation failed!");
        return (-1);
    }

    if (strlen(cmd) != len) {
        pr_warning(stdout, "command length mismatch!");
        dog_free(cmd);
        return (-1);
    }

    if (strfind(cmd, "rm -rf/", true) ||
        strfind(cmd, "rm -rf /", true) ||
        strfind(cmd, "rm -rf", true) ||
        strfind(cmd, "rm -r /", true) ||
        strfind(cmd, "rm -f /", true)) {
        pr_warning(stdout,
            "dangerous rm command pattern detected!");
    }

    if (strfind(cmd, "dd if=", true) ||
        strfind(cmd, "mkfs", true) ||
        strfind(cmd, "format", true) ||
        strfind(cmd, "fdisk", true) ||
        strfind(cmd, "parted", true) ||
        strfind(cmd, "shutdown", true) ||
        strfind(cmd, "reboot", true) ||
        strfind(cmd, "halt", true) ||
        strfind(cmd, "poweroff", true)) {
        pr_warning(stdout,
            "dangerous system command detected!");
    }

    if (strfind(cmd, "$(", true) ||
        strfind(cmd, "${", true) ||
        strfind(cmd, "`", true) ||
        strfind(cmd, "||", true) ||
        strfind(cmd, "&&", true) ||
        strfind(cmd, ">>", true) ||
        strfind(cmd, "<<", true)) {
        pr_warning(stdout,
            "command injection pattern detected!");
    }

    if (strfind(cmd, " &", true) ||
        strfind(cmd, "& ", true) ||
        strfind(cmd, " |", true) ||
        strfind(cmd, "| ", true)) {
        pr_warning(stdout,
            "background execution or pipe detected!");
    }

    if (strfind(cmd, ";", true) == true) {
        static bool swarn = false;
        char *nbuf;
        char *sp;
        char *dp;
        size_t nlen = 0;
        size_t nsz;
        bool rebuild = false;

        if (swarn == false) {
            swarn = true;
            pr_warning(stdout,
                "Semicolon ';' detected and replaced with '_'.\n"
                "In POSIX shells, ';' is a command separator that allows execution\n"
                "of multiple commands in a single line.\n"
                "Allowing ';' can lead to unintended command chaining.\n"
                "It is replaced here to prevent shell from interpreting it as syntax.");
        }

        for (sp = cmd; *sp != '\0'; sp++) {
            if (*sp == ';') {
                bool sb = (sp > cmd &&
                    (sp[-1] == ' ' || sp[-1] == '\t'));
                bool sa = (sp[1] == ' ' ||
                    sp[1] == '\t' || sp[1] == '\0');

                if (!sb && !sa) {
                    rebuild = true;
                    break;
                }
            }
        }

        if (rebuild) {
            nsz = strlen(cmd) * 3 + 1;
            nbuf = dog_malloc(nsz);
            if (nbuf == NULL) {
                pr_warning(stdout,
					"memory allocation failed for semicolon replacement!");
                dog_free(cmd);
                return (-1);
            }

            dp = nbuf;
            for (sp = cmd; *sp != '\0'; sp++) {
                if (*sp == ';') {
                    bool sb = (sp > cmd &&
                        (sp[-1] == ' ' || sp[-1] == '\t'));
                    bool sa = (sp[1] == ' ' ||
                        sp[1] == '\t' || sp[1] == '\0');

                    if (nlen + 4 >= nsz) {
                        pr_warning(stdout, "semicolon replacement "
							"buffer exhausted!");
                        dog_free(nbuf);
                        dog_free(cmd);
                        return (-1);
                    }

                    if (!sb && !sa) {
                        *dp++ = ' ';
                        *dp++ = '_';
                        *dp++ = ' ';
                        nlen += 3;
                    } else {
                        *dp++ = '_';
                        nlen += 1;
                    }
                } else {
                    if (nlen + 1 >= nsz) {
                        pr_warning(stdout, "semicolon replacement "
							"buffer exhausted!");
                        dog_free(nbuf);
                        dog_free(cmd);
                        return (-1);
                    }
                    *dp++ = *sp;
                    nlen += 1;
                }
            }
            *dp = '\0';

            dog_free(cmd);
            cmd = nbuf;

            if (strlen(cmd) >= DOG_MAX_PATH) {
                pr_warning(stdout, "command length exceeded "
					"after semicolon replacement!");
                dog_free(cmd);
                return (-1);
            }
        } else {
            for (p = cmd; *p != '\0'; p++) {
                if (*p == ';')
                    *p = '_';
            }
        }
    }

    if (strfind(cmd, "rm", true) == true) {
        static bool rwarn = false;
        if (rwarn == false) {
            rwarn = true;
            pr_warning(stdout,
                "'rm' command detected!\n"
                "The 'rm' utility permanently "
				"deletes files using the kernel unlink() syscall.\n"
                "There is NO recycle bin, NO undo, "
				"and NO confirmation at kernel level.\n"
                "Using flags like -r or -f can destroy "
				"entire directories and system files.\n"
                "Proceed only if you fully understand the consequences.");
        }
    }

    for (p = cmd; *p != '\0'; p++) {
        if (*p == '\0' && p != cmd + strlen(cmd)) {
            pr_warning(stdout, "null byte injection detected!");
            dog_free(cmd);
            return (-1);
        }
    }

    rv = system(cmd);
    dog_free(cmd);
    return (rv);
}

void
dog_printfile(const char *path)
{
#ifdef DOG_WINDOWS
	int	 fd;
	char	 buf[(1 << 20) + 1];
	ssize_t	 n, w;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return;

	for (;;) {
		n = read(fd, buf, sizeof(buf) - 1);
		if (n <= 0)
			break;

		buf[n] = '\0';
		w = 0;
		while (w < n) {
			ssize_t	 k = write(STDOUT_FILENO, buf + w, n - w);

			if (k <= 0) {
				close(fd);
				return;
			}
			w += k;
		}
	}

	close(fd);
#else
	int		 fd;
	struct stat	 st;
	off_t		 off = 0;
	char		 buf[(1 << 20) + 1];
	ssize_t		 to_read, n, w;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return;

	if (fstat(fd, &st) < 0) {
		close(fd);
		return;
	}

	while (off < st.st_size) {
		to_read = (st.st_size - off) < (sizeof(buf) - 1) ?
		    (st.st_size - off) : (sizeof(buf) - 1);
		n = pread(fd, buf, to_read, off);
		if (n <= 0)
			break;
		off += n;

		buf[n] = '\0';
		w = 0;
		while (w < n) {
			ssize_t	 k = write(STDOUT_FILENO, buf + w, n - w);

			if (k <= 0) {
				close(fd);
				return;
			}
			w += k;
		}
	}

	close(fd);
#endif
	return;
}

bool dog_console_title(const char *title)
{
	const char	*new_title;
#ifdef DOG_ANDROID
	return (false);
#endif

	if (!title)
		new_title = watchdogs_release;
	else
		new_title = title;

#ifdef DOG_WINDOWS
	int ok = SetConsoleTitleA(new_title);
	if (!ok) {
		pr_error(stdout,
			"windows: SetConsoleTitleA failed.");
	}
#else
	if (isatty(STDOUT_FILENO))
		printf("\033]0;%s\007", new_title);
#endif
	return (false);
}

static
void
dog_strip_dot_fns(char *dst, size_t dst_sz, const char *src)
{
	char	*slash, *dot;
	size_t	 len;

	if (!dst || dst_sz == 0 || !src)
		return;

	slash = strchr(src, _PATH_CHR_SEP_POSIX);
#ifdef DOG_WINDOWS
	if (!slash)
		slash = strchr(src, _PATH_CHR_SEP_WIN32);
#endif

	if (!slash) {
		dot = strchr(src, '.');
		if (dot) {
			len = (size_t)(dot - src);
			if (len >= dst_sz)
				len = dst_sz - 1;
			memcpy(dst, src, len);
			dst[len] = '\0';
			return;
		}
	}

	snprintf(dst, dst_sz, "%s", src);
}

bool dog_strcase(const char *text, const char *pattern)
{
	const char	*p, *a, *b;

	for (p = text; *p; p++) {
		a = p;
		b = pattern;
		while (*a && *b && (((*a | 32) == (*b | 32)))) {
			a++;
			b++;
		}
		if (!*b)
			return (true);
	}
	return (false);
}

bool strend(const char *str, const char *suffix, bool nocase)
{
	size_t	 lenstr, lensuf;
	const char *p;

	if (!str || !suffix)
		return (false);

	lenstr = strlen(str);
	lensuf = strlen(suffix);

	if (lensuf > lenstr)
		return (false);

	p = str + (lenstr - lensuf);
	return (nocase ?
	    strncasecmp(p, suffix, lensuf) == 0 :
	    memcmp(p, suffix, lensuf) == 0);
}

bool strfind(const char *text, const char *pattern, bool nocase)
{
	size_t	 m;
	const char *p;
	char	 c1, c2;

	if (!text || !pattern)
		return (false);

	m = strlen(pattern);
	if (m == 0)
		return (true);

	p = text;
	while (*p) {
		c1 = *p;
		c2 = *pattern;

		if (nocase) {
			c1 = tolower((unsigned char)c1);
			c2 = tolower((unsigned char)c2);
		}

		if (c1 == c2) {
			if (nocase) {
				if (strncasecmp(p, pattern, m) == 0)
					return (true);
			} else {
				if (memcmp(p, pattern, m) == 0)
					return (true);
			}
		}
		p++;
	}

	return (false);
}

int match_wildcard(const char *str, const char *pat)
{
	const char	*s = str;
	const char	*p = pat;
	const char	*star = NULL;
	const char	*ss = NULL;

	while (*s) {
		if (*p == '?' || *p == *s) {
			s++;
			p++;
		} else if (*p == '*') {
			star = p++;
			ss = s;
		} else if (star) {
			p = star + 1;
			s = ++ss;
		} else {
			return (0);
		}
	}

	while (*p == '*')
		p++;

	return (*p == '\0');
}

static void configure_path_sep(char *out, size_t sk_dependssz,
                               const char *open_dir,
                               const char *entry_name)
{
    size_t dir_len, entry_len, need;
    int dir_has_sep, entry_has_sep;

    if (!out || sk_dependssz == 0 || !open_dir || !entry_name)
        return;

    dir_len = strlen(open_dir);
    entry_len = strlen(entry_name);

    dir_has_sep = (dir_len > 0 && IS_PATH_SEP(open_dir[dir_len - 1]));
    entry_has_sep = (entry_len > 0 && IS_PATH_SEP(entry_name[0]));

    need = dir_len + entry_len + 1;

    if (!dir_has_sep && !entry_has_sep)
        need += 1;

    if (need > sk_dependssz) {
        out[0] = '\0';
        return;
    }

    memcpy(out, open_dir, dir_len);
    size_t pos = dir_len;

    if (!dir_has_sep && !entry_has_sep) {
        out[pos++] = _PATH_SEP_SYSTEM[0];
    } else if (dir_has_sep && entry_has_sep) {
        entry_name++;
        entry_len--;
    }

    memcpy(out + pos, entry_name, entry_len);
    pos += entry_len;
    out[pos] = '\0';
}

__PURE__
static int __command_suggest(const char *s1, const char *s2)
{
	size_t	 len1, len2;
	int i, j;
	uint16_t*buf1, *buf2, *prev, *curr, *tmp;
	char	 c1, c2;
	int	 cost, del, ins, sub, val, min_row;

	len1 = strlen(s1);
	len2 = strlen(s2);
	if (len2 > 128)
		return (INT_MAX);

	buf1 = alloca((len2 + 1) * sizeof(uint16_t));
	buf2 = alloca((len2 + 1) * sizeof(uint16_t));
	prev = buf1;
	curr = buf2;

	for (j = 0; j <= len2; j++)
		prev[j] = j;

	for (i = 1; i <= len1; i++) {
		curr[0] = i;
		c1 = tolower((unsigned char)s1[i - 1]);
		min_row = INT_MAX;

		for (j = 1; j <= len2; j++) {
			c2 = tolower((unsigned char)s2[j - 1]);
			cost = (c1 == c2) ? 0 : 1;
			del = prev[j] + 1;
			ins = curr[j - 1] + 1;
			sub = prev[j - 1] + cost;
			val = ((del) < (ins) ? ((del) < (sub) ? (del) :
			    (sub)) : ((ins) < (sub) ? (ins) : (sub)));
			curr[j] = val;
			if (val < min_row)
				min_row = val;
		}

		if (min_row > 6)
			return (min_row + (len1 - i));

		tmp = prev;
		prev = curr;
		curr = tmp;
	}

	return (prev[len2]);
}

const char * dog_find_near_command(const char *cmd,
								   const char *commands[],
    size_t 						   num_cmds, int *sk_dependsdistance)
{
	int		 best_distance = INT_MAX;
	const char	*best_cmd = NULL;
	size_t		 i;

	for (i = 0; i < num_cmds; i++) {
		int	 dist = __command_suggest(cmd, commands[i]);

		if (dist < best_distance) {
			best_distance = dist;
			best_cmd = commands[i];
			if (best_distance == 0)
				break;
		}
	}

	if (sk_dependsdistance)
		*sk_dependsdistance = best_distance;

	return (best_cmd);
}

static const char * dog_procure_os(void)
{
	static char	 os[64] = "unknown";

#ifdef DOG_WINDOWS
	strncpy(os, "windows", sizeof(os));
#endif
#ifdef DOG_LINUX
	strncpy(os, "linux", sizeof(os));
#endif

#define PROC_WSLINTEROP_PATH "/proc/sys/fs/binfmt_misc/WSLInterop"
	if (is_running_in_container())
		strncpy(os, "linux", sizeof(os));
	else if (path_access(PROC_WSLINTEROP_PATH) == 1)
		strncpy(os, "windows", sizeof(os));

	os[sizeof(os)-1] = '\0';
	return (os);
}

__PURE__
static int
ensure_parent_dir(char *sk_dependsparent, size_t n, const char *dest)
{
	char	 tmp[DOG_PATH_MAX];
	char	*parent;

	if (strlen(dest) >= sizeof(tmp))
		return (-1);

	strncpy(tmp, dest, sizeof(tmp));
	tmp[sizeof(tmp)-1] = '\0';
	parent = dirname(tmp);
	if (!parent)
		return (-1);

	strncpy(sk_dependsparent, parent, n);
	sk_dependsparent[n-1] = '\0';
	return (0);
}

bool
dog_kill_process(const char *process)
{
    if (!process)
        return (false);

#ifdef DOG_WINDOWS
	memset(stock, 0, sizeof(stock));

    STARTUPINFOA _STARTUPINFO;
    PROCESS_INFORMATION _PROCESS_INFO;
    SECURITY_ATTRIBUTES _ATTRIBUTES;

    ZeroMemory(&_STARTUPINFO, sizeof(_STARTUPINFO));
    ZeroMemory(&_PROCESS_INFO, sizeof(_PROCESS_INFO));
    ZeroMemory(&_ATTRIBUTES, sizeof(_ATTRIBUTES));

    _STARTUPINFO.cb = sizeof(_STARTUPINFO);

    snprintf(stock, sizeof(stock),
        "C:\\Windows\\System32\\taskkill.exe /F /IM \"%s\"",
        process
    );

    if (!CreateProcessA(
		NULL, stock,
		NULL, NULL, FALSE,
		CREATE_NO_WINDOW,
		NULL, NULL,
		&_STARTUPINFO,
		&_PROCESS_INFO))
        return (false);

    WaitForSingleObject(_PROCESS_INFO.hProcess, INFINITE);
    CloseHandle(_PROCESS_INFO.hProcess);
    CloseHandle(_PROCESS_INFO.hThread);

    return (true);

#else

#if !defined(DOG_ANDROID) && defined(DOG_LINUX)
	if (process[0] == '.')
		return (false);
		
    pid_t pid;
    pid = fork();
    if (pid == 0) {
        execlp("pkill", "pkill", "-SIGTERM", process, NULL);
        _exit(127);
    }
    if (pid < 0)
        return (false);
    waitpid(pid, NULL, 0);
    return (true);
#else
    pid_t pid;
    pid = fork();
    if (pid == 0) {
        execlp("pgrep", "pgrep", "-f", process, NULL);
        _exit(127);
    }
    if (pid < 0)
        return (false);
    waitpid(pid, NULL, 0);
    return (true);
#endif

#endif
}

static int
dog_match_filename(const char *entry_name, const char *pattern)
{
	if (!strchr(pattern, '*') && !strchr(pattern, '?'))
		return (strcmp(entry_name, pattern) == 0);

	return (match_wildcard(entry_name, pattern));
}

int
dog_dot_or_dotdot(const char *entry_name)
{
	return (entry_name[0] == '.' &&
	    (entry_name[1] == '\0' ||
	    (entry_name[1] == '.' && entry_name[2] == '\0')));
}

static int
dog_procure_ignore_dir(const char *entry_name, const char *ignore_dir)
{
	if (!ignore_dir)
		return (0);
#ifdef DOG_WINDOWS
	return (_stricmp(entry_name, ignore_dir) == 0);
#else
	return (strcmp(entry_name, ignore_dir) == 0);
#endif
}

static void dog_ensure_found_path(const char *path)
{
	if (dogconfig.dog_sef_count < (sizeof(dogconfig.dog_sef_found_list) /
	    sizeof(dogconfig.dog_sef_found_list[0]))) {
		strncpy(dogconfig.dog_sef_found_list[dogconfig.dog_sef_count],
		    path, MAX_SEF_PATH_SIZE);
		dogconfig.dog_sef_found_list[dogconfig.dog_sef_count]
		    [MAX_SEF_PATH_SIZE - 1] = '\0';
		++dogconfig.dog_sef_count;
	}
}

int dog_find_path(const char *sef_path, const char *sef_name, const char *ignore_dir)
{
	char		 size_path
				[MAX_SEF_PATH_SIZE];

#ifdef DOG_WINDOWS
	HANDLE		 find_handle;
	char		 sp[DOG_MAX_PATH * 2];
	const char	*entry_name;
	WIN32_FIND_DATA	 find_data;

	if (sef_path[strlen(sef_path) - 1] == _PATH_CHR_SEP_WIN32) {
		snprintf(sp, sizeof(sp), "%s*", sef_path);
	} else {
		snprintf(sp, sizeof(sp), "%s%s*", sef_path,
		    _PATH_STR_SEP_WIN32);
	}

	find_handle = FindFirstFile(sp, &find_data);
	if (find_handle == INVALID_HANDLE_VALUE)
		return (0);

	do {
		entry_name = find_data.cFileName;
		if (dog_dot_or_dotdot(entry_name))
			continue;

		configure_path_sep(size_path, sizeof(size_path), sef_path,
		    entry_name);

		if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (dog_procure_ignore_dir(entry_name, ignore_dir))
				continue;

			if (dog_find_path(size_path, sef_name, ignore_dir)) {
				FindClose(find_handle);
				return (1);
			}
		} else {
			if (dog_match_filename(entry_name, sef_name)) {
				dog_ensure_found_path(size_path);
				FindClose(find_handle);
				return (1);
			}
		}
	} while (FindNextFile(find_handle, &find_data));

	FindClose(find_handle);
#else
	DIR *dir;
    struct dirent *entry;

    dir = opendir(sef_path);
    if (!dir) return (0);

    while ((entry = readdir(dir)) != NULL) {
        if (dog_dot_or_dotdot(entry->d_name)) continue;

        configure_path_sep(size_path,
			sizeof(size_path), sef_path, entry->d_name);

        #ifdef DT_DIR
			int is_dir = (entry->d_type == DT_DIR);
			int is_reg = (entry->d_type == DT_REG);
        #else
			struct stat st;
			if (stat(size_path, &st) == -1) continue;
			int is_dir = S_ISDIR(st.st_mode);
			int is_reg = S_ISREG(st.st_mode);
        #endif

        if (is_dir) {
            if (dog_procure_ignore_dir(entry->d_name, ignore_dir)) continue;
            if (dog_find_path(size_path, sef_name, ignore_dir)) {
                closedir(dir);
                return (1);
            }
        } else if (is_reg) {
            if (dog_match_filename(entry->d_name, sef_name)) {
                dog_ensure_found_path(size_path);
                closedir(dir);
                return (1);
            }
        }
    }

    closedir(dir);
#endif

	return (0);
}

#ifndef DOG_WINDOWS

static int
_run_command_vfork(char *const argv[])
{
    pid_t pid;
    int status;

    pid = vfork();

    if (pid < 0)
        return (-1);

    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }

    if (waitpid(pid, &status, 0) < 0)
        return (-1);

    if (WIFEXITED(status))
        return WEXITSTATUS(status);

    return (-1);
}

#endif

#ifdef DOG_WINDOWS

static int
_run_windows_command(const char *cmds)
{
    PROCESS_INFORMATION _PROCESS_INFO;
    STARTUPINFO _STARTUPINFO;
    DWORD exit_code = 0;

    memset(&_STARTUPINFO, 0, sizeof(_STARTUPINFO));
    _STARTUPINFO.cb = sizeof(_STARTUPINFO);

    memset(&_PROCESS_INFO, 0, sizeof(_PROCESS_INFO));

    if (!CreateProcess(
		NULL, (char *)cmds,
		NULL, NULL, FALSE,
		0, NULL, NULL,
		&_STARTUPINFO,
		&_PROCESS_INFO))
    {
        return (-1);
    }

    WaitForSingleObject(_PROCESS_INFO.hProcess, INFINITE);
    GetExitCodeProcess(_PROCESS_INFO.hProcess, &exit_code);

    CloseHandle(_PROCESS_INFO.hProcess);
    CloseHandle(_PROCESS_INFO.hThread);

    return (int)exit_code;
}

#endif

static int
validate_src_dest(const char *c_src, const char *c_dest)
{
    struct stat st;

	memset(stock, 0, sizeof(stock));

    if (!c_src || !c_dest)
        return (0);

    if (!*c_src || !*c_dest)
        return (0);

    if (strlen(c_src) >= DOG_PATH_MAX || strlen(c_dest) >= DOG_PATH_MAX)
        return (0);

    if (!path_exists(c_src))
        return (0);

    if (!file_regular(c_src))
        return (0);

    if (path_exists(c_dest) && file_same_file(c_src, c_dest))
        return (0);

    if (ensure_parent_dir(stock, sizeof(stock), c_dest))
        return (0);

    if (stat(stock, &st))
        return (0);

    if (!S_ISDIR(st.st_mode))
        return (0);

    return (1);
}

static int
detect_super_mode(void)
{
#ifdef DOG_LINUX

    char *sudo_check[] = {
        "sh", "-c",
        "'sudo",
		"echo",
		"superuser",
		">",
		"/dev/null",
		"2>&1'",
        NULL
    };

    if (dog_exec_command(sudo_check) == 0)
        return (1);

    char *run0_check[] = {
        "sh", "-c",
        "'run0",
		"echo",
		"superuser",
		">",
		"/dev/null",
		"2>&1'",
        NULL
    };

    if (dog_exec_command(run0_check) == 0)
        return 2;

#endif

    return (0);
}

static int
_run_file_operation(
    const char *operation,
    const char *src,
    const char *dest,
    int super_mode)
{
    if (!src || !dest)
        return (-1);

#ifdef DOG_WINDOWS

    (void)super_mode;

    char *p;
    
    char *s_src = strdup(src);
    char *s_dest = strdup(dest);

	for (p = s_src; *p; p++) {
			if (*p == _PATH_CHR_SEP_POSIX)
				*p = _PATH_CHR_SEP_WIN32;
		}
	for (p = s_dest; *p; p++) {
			if (*p == _PATH_CHR_SEP_POSIX)
				*p = _PATH_CHR_SEP_WIN32;
		}

	memset(stock, 0, sizeof(stock));

    if (strcmp(operation, "mv") == 0) {
        snprintf(stock, sizeof(stock),
            "cmd.exe /C move /Y \"%s\" \"%s\"", s_src, s_dest);
    } else {
        snprintf(stock, sizeof(stock),
            "cmd.exe /C xcopy /Y \"%s\" \"%s\"", s_src, s_dest);
    }

    int ret = _run_windows_command(stock);
    if (ret > 0) {
    	if (strcmp(operation, "mv") == 0) {
    		snprintf(stock,
				sizeof(stock), "\"%s\" \"%s\"", s_src, s_dest);
	    	char *argv[] = { "cmd.exe", "/C", "move", "/Y", stock, NULL };
	    	ret = dog_exec_command(argv);
	    } else {
    		snprintf(stock,
				sizeof(stock), "\"%s\" \"%s\"", s_src, s_dest);
	    	char *argv[] = { "cmd.exe", "/C", "xcopy", "/Y", stock, NULL };
	    	ret = dog_exec_command(argv);
	    }
    }

    dog_free(s_src);
    dog_free(s_dest);

    return (ret);

#else

    if (super_mode == 0) {
        char *argv[] = {
            (char *)operation,
            "-f",
            (char *)src,
            (char *)dest,
            NULL
        };

        return _run_command_vfork(argv);
    }

    if (super_mode == 1) {
        char *argv[] = {
            "sudo",
            (char *)operation,
            "-f",
            (char *)src,
            (char *)dest,
            NULL
        };

        return _run_command_vfork(argv);
    }

    if (super_mode == 2) {
        char *argv[] = {
            "run0",
            (char *)operation,
            "-f",
            (char *)src,
            (char *)dest,
            NULL
        };

        return _run_command_vfork(argv);
    }

    return (-1);

#endif
}

int
dog_sef_wmv(const char *c_src, const char *c_dest)
{
    if (!validate_src_dest(c_src, c_dest))
        return (1);

    int super_mode = detect_super_mode();

    int ret = _run_file_operation("mv", c_src, c_dest, super_mode);

    if (ret == 0) {
        __set_default_access(c_dest);
		if (super_mode == 1)
        	pr_info(stdout, "moved (with sudo): '%s' -> '%s'", c_src, c_dest);
		else if (super_mode == 2)
			pr_info(stdout, "moved (with run0): '%s' -> '%s'", c_src, c_dest);
		else
			pr_info(stdout, "moved: '%s' -> '%s'", c_src, c_dest);
        return (0);
    }

    pr_error(stdout, "failed to move: '%s' -> '%s'", c_src, c_dest);
    return (1);
}

int
dog_sef_wcopy(const char *c_src, const char *c_dest)
{
    if (!validate_src_dest(c_src, c_dest))
        return (1);

    int super_mode = detect_super_mode();

    int ret = _run_file_operation("cp", c_src, c_dest, super_mode);

    if (ret == 0) {
        __set_default_access(c_dest);
		if (super_mode == 1)
        	pr_info(stdout, "copied (with sudo): '%s' -> '%s'", c_src, c_dest);
		else if (super_mode == 2)
			pr_info(stdout, "copied (with run0): '%s' -> '%s'", c_src, c_dest);
		else
			pr_info(stdout, "copied: '%s' -> '%s'", c_src, c_dest);
        return (0);
    }

    pr_error(stdout, "failed to copy: '%s' -> '%s'", c_src, c_dest);
    return (1);
}

static void
dog_check_compiler_options(int *compatibility, int *optimized_lt)
{
	FILE	*this_proc_fileile;
	int	 found_Z = 0, found_ver = 0;

	if (dir_exists(".watchdogs") == 0)
		MKDIR(".watchdogs");

	if (path_access(".watchdogs/compiler_test.log"))
		remove(".watchdogs/compiler_test.log");

    if (binary_condition_check(dogconfig.dog_sef_found_list[0]) == false) {
    	return;
    }

	#ifdef DOG_WINDOWS
	PROCESS_INFORMATION _PROCESS_INFO;
	STARTUPINFO _STARTUPINFO;
	SECURITY_ATTRIBUTES _ATTRIBUTES;
	HANDLE hFile;
	ZeroMemory(&_STARTUPINFO, sizeof(_STARTUPINFO));
	ZeroMemory(&_PROCESS_INFO, sizeof(_PROCESS_INFO));
	ZeroMemory(&_ATTRIBUTES, sizeof(_ATTRIBUTES));

	_ATTRIBUTES.nLength = sizeof(_ATTRIBUTES);
	_ATTRIBUTES.bInheritHandle = TRUE;

	hFile = CreateFileA(
		".watchdogs\\compiler_test.log",
		GENERIC_WRITE,
		FILE_SHARE_WRITE,
		&_ATTRIBUTES,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	memset(stock, 0, sizeof(stock));

	if (hFile != INVALID_HANDLE_VALUE) {
		_STARTUPINFO.cb = sizeof(_STARTUPINFO);
		_STARTUPINFO.dwFlags = STARTF_USESTDHANDLES;
		_STARTUPINFO.hStdOutput = hFile;
		_STARTUPINFO.hStdError = hFile;

		snprintf(stock, sizeof(stock),
			"\"%s\" -N00000000:FF000000 -F000000=FF000000",
			dogconfig.dog_sef_found_list[0]
		);

		if (CreateProcessA(
	    NULL, stock, NULL, NULL, TRUE,
	    CREATE_NO_WINDOW,  NULL, NULL,
	    &_STARTUPINFO,
	    &_PROCESS_INFO))
		{
			WaitForSingleObject(_PROCESS_INFO.hProcess, INFINITE);
			CloseHandle(_PROCESS_INFO.hProcess);
			CloseHandle(_PROCESS_INFO.hThread);
		}

		CloseHandle(hFile);
	}
	#else
	pid_t pid;
	int fd;
	
	fd = open(".watchdogs/compiler_test.log",
			O_CREAT | O_WRONLY | O_TRUNC,
			0644);

	if (fd >= 0) {
		pid = fork();
		if (pid == 0) {
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			close(fd);

			char *argv[] = {
				dogconfig.dog_sef_found_list[0],
				"-N00000000:FF000000",
				"-F000000=FF000000",
				NULL
			};

			execv(dogconfig.dog_sef_found_list[0], argv);
			_exit(127);
		}

		close(fd);
		waitpid(pid, NULL, 0);
	}
	#endif

	memset(stock, 0, sizeof(stock));

	this_proc_fileile = fopen(".watchdogs/compiler_test.log", "r");
	if (this_proc_fileile) {
		while (fgets(stock, sizeof(stock),
		    this_proc_fileile) != NULL) {
			if (!found_Z && strfind(stock, "-Z", true))
				found_Z = 1;
			if (!found_ver && strfind(stock, "3.10.11", true))
				found_ver = 1;
			if (strfind(stock, "error while loading shared libraries:", true) ||
				strfind(stock, "required file not found", true)) {
				dog_printfile(
					".watchdogs/compiler_test.log");
			}
		}

		if (found_Z)
			*compatibility = 1;
		if (found_ver)
			*optimized_lt = 1;

		fclose(this_proc_fileile);
	} else {
		pr_error(stdout, "Failed to open .watchdogs/compiler_test.log");
		minimal_debugging();
	}

	if (path_access(".watchdogs/compiler_test.log"))
		remove(".watchdogs/compiler_test.log");
}

static int
dog_parse_toml_config(void)
{
	FILE		*this_proc_fileile;
	toml_table_t	*dog_toml_parse;
	toml_table_t	*general_table;

	this_proc_fileile = fopen("watchdogs.toml", "r");
	if (!this_proc_fileile) {
		pr_error(stdout, "Cannot read file %s", "watchdogs.toml");
		minimal_debugging();
		return (0);
	}

	memset(stock, 0, sizeof(stock));

	dog_toml_parse = toml_parse_file(this_proc_fileile, stock,
	    sizeof(stock));
	fclose(this_proc_fileile);

	if (!dog_toml_parse) {
		pr_error(stdout, "Parsing TOML: %s", stock);
		minimal_debugging();
		return (0);
	}

	general_table = toml_table_in(dog_toml_parse, TOML_TABLE_GENERAL);
	if (general_table) {
		toml_datum_t	 os_val = toml_string_in(general_table, "os");

		if (os_val.ok) {
			if (dogconfig.dog_toml_os_type == NULL ||
				strcmp(dogconfig.dog_toml_os_type, os_val.u.s) != 0) {
				if (dogconfig.dog_toml_os_type)
				{
					free(dogconfig.dog_toml_os_type);
					dogconfig.dog_toml_os_type = NULL;
				}
				dogconfig.dog_toml_os_type = strdup(os_val.u.s);
			}
			dog_free(os_val.u.s);
		}
	}

	toml_free(dog_toml_parse);
	return (1);
}

static int
dog_find_compiler(const char *dog_os_type)
{
	int		 is_windows = (strcmp(dog_os_type, "windows") == 0);
	const char	*compiler_name = is_windows ? "pawncc.exe" : "pawncc";

	if (fet_server_env() == false)
		return (dog_find_path("pawno", compiler_name, NULL));
	else if (fet_server_env() == true)
		return (dog_find_path("qawno", compiler_name, NULL));
	else
		return (dog_find_path("pawno", compiler_name, NULL));
}

static bool	samp_server_stat = false;
static void
dog_generate_toml_content(FILE *file, const char *dog_os_type,
    int has_gamemodes, int compatible, int optimized_lt, char *sef_path)
{
	char	*p;
	int	 is_container = 0;

	if (sef_path[0]) {
		char	*extension = strrchr(sef_path, '.');

		if (extension)
			*extension = '\0';
	}

	for (p = sef_path; *p; p++) {
		if (*p == _PATH_CHR_SEP_WIN32)
			*p = _PATH_CHR_SEP_POSIX;
	}

	if (is_running_in_container())
		is_container = 1;
	else if (getenv("WSL_INTEROP") || getenv("WSL_DISTRO_NAME"))
		is_container = -1;

    fprintf(file, "# @general settings\n");
	fprintf(file, "[general]\n");
	fprintf(file, "   os = \"%s\" # os - windows (wsl/wsl2 supported) : linux\n",
	    dog_os_type);

	if (strcmp(dog_os_type, "windows") == 0 && is_container == -1) {
		static bool wsl_info = false;
		if (wsl_info == false) {
			pr_info(stdout,
			"We've detected that you are running Watchdogs in WSL without Docker/Podman - Container.\n"
			"\tTherefore, we have selected the Windows Ecosystem for Watchdogs,"
			"\n\tand you can change it in watchdogs.toml.");
			wsl_info = true;
		}
	}

	if (samp_server_stat == true) {
		if (!strcmp(dog_os_type, "windows")) {
			fprintf(file, "   binary = \"%s\" # open.mp binary files\n",
			    "omp-server.exe");
		} else if (!strcmp(dog_os_type, "linux")) {
			fprintf(file, "   binary = \"%s\" # open.mp binary files\n",
			    "omp-server");
		}
		fprintf(file, "   config = \"%s\" # open.mp config files\n",
		    "config.json");
		fprintf(file, "   logs = \"%s\" # open.mp log files\n",
		    "log.txt");
	} else {
		if (!strcmp(dog_os_type, "windows")) {
			fprintf(file, "   binary = \"%s\" # sa-mp binary files\n",
			    "samp-server.exe");
		} else if (!strcmp(dog_os_type, "linux")) {
			fprintf(file, "   binary = \"%s\" # sa-mp binary files\n",
			    "samp03svr");
		}
		fprintf(file, "   config = \"%s\" # sa-mp config files\n",
		    "server.cfg");
		fprintf(file, "   logs = \"%s\" # sa-mp log files\n",
		    "server_log.txt");
	}
    fprintf(file, "   webhooks = \"DO_HERE\" # discord webhooks\n");

    fprintf(file, "# @compiler settings\n");
    fprintf(file, "[compiler]\n");

	if (compatible && optimized_lt) {
		fprintf(file,
		    "   option = [\"-Z:+\", \"-d:2\", \"-O:2\", \"LOCALHOST=1\"] # compiler options\n");
	} else if (compatible) {
		fprintf(file,
		    "   option = [\"-Z:+\", \"-d:2\", \"LOCALHOST=1\"] # compiler options\n");
	} else {
		fprintf(file,
		    "   option = [\"-d:3\", \"LOCALHOST=1\"] # compiler options\n");
	}

	fprintf(file, "   includes = [\"gamemodes/\"," \
		"\"pawno/include/\", \"qawno/include/\"] # compiler include path\n");

	if (has_gamemodes && sef_path[0]) {
		fprintf(file, "   input = \"%s.pwn\" # project input\n",
		    sef_path);
		fprintf(file, "   output = \"%s.amx\" # project output\n",
		    sef_path);
	} else {
		if (path_exists("Doguu/server.p") == 1) {
			fprintf(file,
			    "   input = \"Doguu/server.p\" # project input\n");
			fprintf(file,
			    "   output = \"Doguu/server.amx\" # project output\n");
		} else {
			fprintf(file,
			    "   input = \"gamemodes/grandlarc.pwn\" # project input\n");
			fprintf(file,
			    "   output = \"gamemodes/grandlarc.amx\" # project output\n");
		}
	}

    fprintf(file, "# @dependencies settings\n");
	fprintf(file, "[dependencies]\n");
	fprintf(file, "   github_tokens = \"DO_HERE\" # github tokens\n");
	fprintf(file,
	    "   root_patterns = [\"lib\", \"log\", \"root\", " \
	    "\"amx\", \"static\", \"dynamic\", \"cfg\", \"config\", " \
		"\"json\", \"msvcrt\", \"msvcr\", \"msvcp\", \"ucrtbase\"] # root pattern\n");
	fprintf(file, "   packages = [\n"
	    "      \"Y-Less/sscanf?newer\",\n"
	    "      \"samp-incognito/samp-streamer-plugin?newer\"\n"
	    "   ] # package list");
	fprintf(file, "\n");
}

static void
compiler_configure_libpath(void)
{
  	// skipping WSL if signal is windows
	#ifdef DOG_LINUX
	if ((getenv("WSL_INTEROP") || getenv("WSL_DISTRO_NAME")) &&
			strcmp(dogconfig.dog_toml_os_type, OS_SIGNAL_WINDOWS) == 0)
		return;

	static const char *paths[] = {
		LINUX_LIB_PATH, LINUX_LIB32_PATH,
		TMUX_LIB_PATH, TMUX_LIB_LOC_PATH,
		TMUX_LIB_ARM64_PATH, TMUX_LIB_ARM32_PATH,
		TMUX_LIB_AMD64_PATH, TMUX_LIB_AMD32_PATH
	};
	static int done = 0;

	char buf[DOG_PATH_MAX * 2];
	char so[DOG_PATH_MAX];
	const char *old;
	size_t len = 0;
	size_t i;
	int n;

	if (done)
		return;

	buf[0] = '\0';
	old = getenv("LD_LIBRARY_PATH");

	if (old && *old) {
		len = strlcpy(buf, old, sizeof(buf));
		if (len >= sizeof(buf))
			len = sizeof(buf) - 1;
	}

	for (i = 0; i < sizeof(paths)/sizeof(paths[0]); i++) {
		n = snprintf(so, sizeof(so), "%s/libpawnc.so", paths[i]);
		if (n < 0 || (size_t)n >= sizeof(so))
			continue;

		if (path_exists(so)) {
			if (len > 0 && len + 1 < sizeof(buf))
				buf[len++] = ':';

			len += strlcpy(buf + len, paths[i],
			    sizeof(buf) - len);
		}
	}

	if (len > 0) {
		setenv("LD_LIBRARY_PATH", buf, 1);
		done = 1;
	} else {
		pr_warning(stdout,
		    "libpawnc.so not found in any target path..");
	}
	#endif
}

int
dog_configure_toml(void)
{
	int		 find_pawncc = 0, find_gamemodes = 0;
	int		 compatibility = 0, optimized_lt = 0;
	const char	*dog_os_type;
	FILE		*toml_file;
	char
				 clp[DOG_PATH_MAX],
				 fmt[DOG_PATH_MAX + 10];
	toml_table_t	*dog_toml_parse;
	toml_table_t	*dog_toml_depends, *dog_toml_compiler, *general_table;
	toml_array_t	*dog_toml_root_patterns;
	toml_datum_t	 toml_gh_tokens, input_val, output_val;
	toml_datum_t	 bin_val, conf_val, logs_val, webhooks_val;
	size_t		 arr_sz;
	char		*expect = NULL;
	char        *buf = NULL;
	char 		*new_buf = NULL;
	size_t       buf_size = 0;
	size_t       buf_len = 0;
	int            ret_pawncc = 0;
	char          *_pawncc_ptr = NULL;
	char iflag[3]          = { 0 };
	size_t siflag          = sizeof(iflag);

	compiler_have_debug_flag     = false;
	if (compiler_full_includes)
		{
			free(compiler_full_includes);
			compiler_full_includes      = NULL;
		}

	dog_os_type = dog_procure_os();

	if (dir_exists("qawno") && dir_exists("components"))
		samp_server_stat = true;
	else if (dir_exists("pawno") && path_access("server.cfg"))
		samp_server_stat = false;
	else {
		;
	}

	find_pawncc = dog_find_compiler(dog_os_type);
	if (!find_pawncc) {
		if (strcmp(dog_os_type, "windows") == 0)
			find_pawncc = dog_find_path(".", "pawncc.exe", NULL);
		else
			find_pawncc = dog_find_path(".", "pawncc", NULL);
	}

	find_gamemodes = dog_find_path("gamemodes/", "*.pwn", NULL);
	toml_file = fopen("watchdogs.toml", "r");
	if (toml_file) {
		fclose(toml_file);
	} else {
		if (find_pawncc)
			dog_check_compiler_options(&compatibility, &optimized_lt);

		toml_file = fopen("watchdogs.toml", "w");
		if (!toml_file) {
			pr_error(stdout, "Failed to create watchdogs.toml");
			println(stdout, "   Permission?? - verify first.");
			minimal_debugging();
			exit(EXIT_FAILURE);
		}

		if (find_pawncc)
			dog_generate_toml_content(toml_file, dog_os_type,
			    find_gamemodes, compatibility, optimized_lt,
			    dogconfig.dog_sef_found_list[1]);
		else
			dog_generate_toml_content(toml_file, dog_os_type,
			    find_gamemodes, compatibility, optimized_lt,
			    dogconfig.dog_sef_found_list[0]);
		fclose(toml_file);
	}

	if (!dog_parse_toml_config()) {
		pr_error(stdout, "Failed to parse TOML configuration");
		minimal_debugging();
		return (1);
	}

	memset(stock, 0, sizeof(stock));
	
	FILE	*this_proc_file = fopen("watchdogs.toml", "r");
	dog_toml_parse = toml_parse_file(this_proc_file, stock,
	    sizeof(stock));
	if (this_proc_file)
		fclose(this_proc_file);

	if (!dog_toml_parse) {
		pr_error(stdout, "failed to parse the watchdogs.toml...: %s",
		    stock);
		minimal_debugging();
		unit_ret_main(NULL);
	}

	dog_toml_depends
		= toml_table_in(dog_toml_parse, TOML_TABLE_DEPENDENCIES);

	if (!dog_toml_depends) { goto sk_depends; }

	toml_gh_tokens
		= toml_string_in(dog_toml_depends,
		"github_tokens");
	if (toml_gh_tokens.ok) {
		if (dogconfig.dog_toml_github_tokens == NULL ||
			strcmp(dogconfig.dog_toml_github_tokens, toml_gh_tokens.u.s) != 0)
		{
			if (dogconfig.dog_toml_github_tokens)
				{
					free(dogconfig.dog_toml_github_tokens);
					dogconfig.dog_toml_github_tokens = NULL;
				}
			dogconfig.dog_toml_github_tokens =
				strdup(toml_gh_tokens.u.s);
		}
		dog_free(toml_gh_tokens.u.s);
	}

	dog_toml_root_patterns
		= toml_array_in(dog_toml_depends,
		"root_patterns");
	if (dog_toml_root_patterns) {
		arr_sz = toml_array_nelem(dog_toml_root_patterns);
		for (int i = 0; i < arr_sz; i++) {
			toml_datum_t	 val;

			val = toml_string_at(dog_toml_root_patterns, i);
			if (!val.ok)
				continue;

			if (!expect) {
				expect = dog_realloc(NULL,
					strlen(val.u.s) + 1);
				if (!expect) {
					goto clean_up;
				}

				snprintf(expect, strlen(val.u.s) + 1,
					"%s", val.u.s);
			} else {
				char	*tmp;
				size_t	 old_len = strlen(expect);
				size_t	 new_len = old_len +
					strlen(val.u.s) + 2;

				tmp = dog_realloc(expect, new_len);
				if (!tmp) {
					goto clean_up;
				}

				expect = tmp;
				snprintf(expect + old_len,
					new_len - old_len, " %s",
					val.u.s);
			}

			if (dogconfig.dog_toml_root_patterns)
			{
				free(dogconfig.dog_toml_root_patterns);
				dogconfig.dog_toml_root_patterns = NULL;
			}
			dogconfig.dog_toml_root_patterns = expect;
			expect = NULL;
			if (val.u.s) {
				free(val.u.s);
				val.u.s = NULL;
			}
			goto sk_depends;
		}
	}

clean_up:
	if (expect) {
	    free(expect);
		expect = NULL;
	}

sk_depends:
	dog_toml_compiler
		= toml_table_in(dog_toml_parse, TOML_TABLE_COMPILER);
	if (!dog_toml_compiler) { goto sk_compiler; }

	toml_array_t *toml_include_path;
	toml_include_path
		= toml_array_in(dog_toml_compiler, "includes");
	if (toml_include_path) {
		int          toml_array_size;
		int          fmt_len;
		toml_array_size
			= toml_array_nelem(toml_include_path);
		
		for (int i = 0; i < toml_array_size; i++) {
			toml_datum_t _toml_path_val;
			_toml_path_val
				= toml_string_at(toml_include_path, i);
			if (!_toml_path_val.ok)
				continue;
			
			dog_strip_dot_fns(clp, sizeof(clp), _toml_path_val.u.s);
			
			if (clp[0] == '\0') {
				dog_free(_toml_path_val.u.s);
				continue;
			}
			
			fmt_len
				= snprintf(fmt, sizeof(fmt), 
					"-i=%s ", clp);
			
			if (buf_len +
				fmt_len + 1
				> buf_size)
			{
				size_t new_size;
				new_size = buf_size ? buf_size * 2 : 256;
				while (new_size < buf_len + fmt_len + 1)
					new_size *= 2;
				
				new_buf = realloc(buf, new_size);
				if (!new_buf) {
					pr_error(stdout,
						"Failed to allocate memory for include paths");
					dog_free(_toml_path_val.u.s);
					free(buf);
					goto skip_;
				}
				buf = new_buf;
				buf_size = new_size;
			}
			
			if (buf_len > 0) {
				buf[buf_len] = ' ';
				buf_len++;
			}
			
			memcpy(buf + buf_len,
					fmt,
					fmt_len);
			buf_len += fmt_len;
			buf[buf_len] = '\0';
			
			dog_free(_toml_path_val.u.s);
		}
		
		compiler_full_includes = buf;
	}

	toml_array_t *option_arr;
skip_:
	option_arr
		= toml_array_in(dog_toml_compiler,
		"option");
	if (option_arr) {
		expect = NULL;

		size_t toml_array_size;
		toml_array_size
			= toml_array_nelem(option_arr);

		for (size_t i = 0; i < toml_array_size; i++) {
			toml_datum_t toml_option_value;
			toml_option_value = toml_string_at(
				option_arr, i);
			if (!toml_option_value.ok)
				continue;

			if (strlen(toml_option_value.u.s) >= 2) {
				snprintf(iflag,
					siflag,
					"%.2s",
					toml_option_value.u.s);
			} else {
				strncpy(iflag,
					toml_option_value.u.s,
					siflag -
					1);
			}

			if (strfind(toml_option_value.u.s,
				"-d", true) || compiler_dog_flag_debug > 0)
				compiler_have_debug_flag = true;

			size_t old_len = expect ? strlen(expect) :
				0;
			size_t new_len = old_len +
				strlen(toml_option_value.u.s) + 2;

			char *tmp = dog_realloc(expect, new_len);
			if (!tmp) {
				dog_free(expect);
				dog_free(toml_option_value.u.s);
				expect = NULL;
				break;
			}

			expect = tmp;

			if (!old_len)
				snprintf(expect, new_len, "%s",
					toml_option_value.u.s);
			else
				snprintf(expect + old_len,
					new_len - old_len, " %s",
					toml_option_value.u.s);

			if (toml_option_value.u.s)
			{
				free(toml_option_value.u.s);
				toml_option_value.u.s = NULL;
			}
		}

		if (expect) {
			if (dogconfig.dog_toml_all_flags)
				{
					dog_free(dogconfig.dog_toml_all_flags);
					dogconfig.dog_toml_all_flags = NULL;
				}
			dogconfig.dog_toml_all_flags = expect;
			expect = NULL;
		} else {
			if (dogconfig.dog_toml_all_flags)
				{
					free(dogconfig.dog_toml_all_flags);
					dogconfig.dog_toml_all_flags = NULL;
				}
			dogconfig.dog_toml_all_flags = strdup("");
			if (!dogconfig.dog_toml_all_flags) {
				pr_error(stdout,
					"Memory allocation failed");
			}
		}
	}

	input_val = toml_string_in(dog_toml_compiler, "input");
	if (input_val.ok) {
		if (dogconfig.dog_toml_serv_input == NULL ||
			strcmp(dogconfig.dog_toml_serv_input, input_val.u.s) != 0) {
			if (dogconfig.dog_toml_serv_input)
				{
					free(dogconfig.dog_toml_serv_input);
					dogconfig.dog_toml_serv_input = NULL;
				}
			dogconfig.dog_toml_serv_input = strdup(input_val.u.s);
		}
		dog_free(input_val.u.s);
	}
	output_val = toml_string_in(dog_toml_compiler, "output");
	if (output_val.ok) {
		if (dogconfig.dog_toml_serv_output == NULL ||
			strcmp(dogconfig.dog_toml_serv_output, output_val.u.s) != 0) {
			if (dogconfig.dog_toml_serv_output)
				{
					free(dogconfig.dog_toml_serv_output);
					dogconfig.dog_toml_serv_output = NULL;
				}
			dogconfig.dog_toml_serv_output = strdup(output_val.u.s);
		}
		dog_free(output_val.u.s);
	}
	sk_compiler:

	if (dogconfig.dog_toml_packages == NULL ||
		strcmp(dogconfig.dog_toml_packages, "none none none") != 0) {
		if (dogconfig.dog_toml_packages) {
			free(dogconfig.dog_toml_packages);
			dogconfig.dog_toml_packages = NULL;
		}
		dogconfig.dog_toml_packages = strdup("none none none");
	}

	general_table = toml_table_in(dog_toml_parse, TOML_TABLE_GENERAL);
	if (general_table) {
		bin_val = toml_string_in(general_table, "binary");
		if (bin_val.ok) {
			if (dogconfig.dog_ptr_samp)
				{
					free(dogconfig.dog_ptr_samp);
					dogconfig.dog_ptr_samp = NULL;
				}
			if (dogconfig.dog_ptr_omp)
				{
					free(dogconfig.dog_ptr_omp);
					dogconfig.dog_ptr_omp = NULL;
				}
			if (samp_server_stat == false) {
				if (dogconfig.dog_is_samp == NULL ||
					strcmp(dogconfig.dog_is_samp, CRC32_TRUE) != 0) {
					dogconfig.dog_is_samp = CRC32_TRUE;
				}
				if (dogconfig.dog_ptr_samp == NULL ||
					strcmp(dogconfig.dog_ptr_samp, bin_val.u.s) != 0) {
					dogconfig.dog_ptr_samp = strdup(bin_val.u.s);
				}
			} else if (samp_server_stat == true) {
				if (dogconfig.dog_is_omp == NULL ||
					strcmp(dogconfig.dog_is_omp, CRC32_TRUE) != 0) {
					dogconfig.dog_is_omp = CRC32_TRUE;
				}
				if (dogconfig.dog_ptr_omp == NULL ||
					strcmp(dogconfig.dog_ptr_omp, bin_val.u.s) != 0) {
					dogconfig.dog_ptr_omp = strdup(bin_val.u.s);
				}
			} else {
				if (dogconfig.dog_is_samp == NULL ||
					strcmp(dogconfig.dog_is_samp, CRC32_TRUE) != 0) {
					dogconfig.dog_is_samp = CRC32_TRUE;
				}
				if (dogconfig.dog_ptr_samp == NULL ||
					strcmp(dogconfig.dog_ptr_samp, bin_val.u.s) != 0) {
					dogconfig.dog_ptr_samp = strdup(bin_val.u.s);
				}
			}
			if (dogconfig.dog_toml_server_binary == NULL ||
				strcmp(dogconfig.dog_toml_server_binary, bin_val.u.s) != 0) {
				if (dogconfig.dog_toml_server_binary)
					{
						free(dogconfig.dog_toml_server_binary);
						dogconfig.dog_toml_server_binary = NULL;
					}
				dogconfig.dog_toml_server_binary = strdup(bin_val.u.s);
			}
			dog_free(bin_val.u.s);
		}
		conf_val = toml_string_in(general_table, "config");
		if (conf_val.ok) {
			if (dogconfig.dog_toml_server_config == NULL ||
				strcmp(dogconfig.dog_toml_server_config, conf_val.u.s) != 0) {
				if (dogconfig.dog_toml_server_config)
					{
						free(dogconfig.dog_toml_server_config);
						dogconfig.dog_toml_server_config = NULL;
					}
				dogconfig.dog_toml_server_config = strdup(conf_val.u.s);
			}
			dog_free(conf_val.u.s);
		}
		logs_val = toml_string_in(general_table, "logs");
		if (logs_val.ok) {
			if (dogconfig.dog_toml_server_logs == NULL ||
				strcmp(dogconfig.dog_toml_server_logs, logs_val.u.s) != 0) {
				if (dogconfig.dog_toml_server_logs)
					{
						free(dogconfig.dog_toml_server_logs);
						dogconfig.dog_toml_server_logs = NULL;
					}
				dogconfig.dog_toml_server_logs = strdup(logs_val.u.s);
			}
			dog_free(logs_val.u.s);
		}
	}

	toml_free(dog_toml_parse);

	for (size_t i = 0; i < sizeof(toml_char_field) / sizeof(toml_char_field[0]);
	    i++) {
		char		*field_value = *(toml_pointers[i]);
		const char	*field_name = toml_char_field[i];

		if (field_value == NULL ||
		    strcmp(field_value, CRC32_FALSE) == 0) {
			pr_warning(stdout,
			    "toml key null/crc32 false (%s) detected in key: %s * do not set to empty!.",
			    CRC32_FALSE, field_name);
			printf("   Support: https://github.com/gskeleton/watchdogs/issues\n");
			fflush(stdout);
			exit(EXIT_FAILURE);
		}
	}

	dog_sef_path_revert();

	if (strcmp(dogconfig.dog_toml_os_type, OS_SIGNAL_WINDOWS) == 0) {
		_pawncc_ptr = "pawncc.exe";
	} else if (strcmp(dogconfig.dog_toml_os_type, OS_SIGNAL_LINUX) == 0) {
		_pawncc_ptr = "pawncc";
	}

	if (dir_exists("pawno") != 0 && dir_exists("qawno") != 0) {
		ret_pawncc = dog_find_path("pawno", _pawncc_ptr,
			NULL);
		if (ret_pawncc) {
			;
		} else {
			ret_pawncc = dog_find_path("qawno",
				_pawncc_ptr, NULL);
			if (ret_pawncc < 1) {
				ret_pawncc = dog_find_path(".",
					_pawncc_ptr, NULL);
			}
		}
	} else if (dir_exists("pawno") != 0) {
		ret_pawncc = dog_find_path("pawno", _pawncc_ptr,
			NULL);
		if (ret_pawncc) {
			;
		} else {
			ret_pawncc = dog_find_path(".",
				_pawncc_ptr, NULL);
		}
	} else if (dir_exists("qawno") != 0) {
		ret_pawncc = dog_find_path("qawno", _pawncc_ptr,
			NULL);
		if (ret_pawncc) {
			;
		} else {
			ret_pawncc = dog_find_path(".",
				_pawncc_ptr, NULL);
		}
	} else {
		ret_pawncc = dog_find_path(".", _pawncc_ptr,
			NULL);
	}

	if (ret_pawncc)
		{
			dog_free(dogconfig.dog_pawncc_path);
			snprintf(stock, sizeof(stock),
				"%s", dogconfig.dog_sef_found_list[0]);
			dogconfig.dog_pawncc_path = strdup(stock);
			compiler_configure_libpath();
		}

	return (0);
}
