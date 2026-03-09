#include  "units.h"
#include  "library.h"
#include  "crypto.h"
#include  "debug.h"
#include  "compiler.h"
#include  "curl.h"
#include  "utils.h"

static char pbuf[DOG_MAX_PATH];

const char	*unit_command_list[] = {
	"help", "exit",
	"sha1", "sha256",
	"crc32", "djb2", "pbkdf2",
	"base64encode", "base64decode",
	"aesencrypt", "aesdecrypt",
	"config", "replicate", "gamemode",
	"pawncc", "debug",
	"compile", "decompile",
	"running", "compiles", "pawnruns",
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
	.dog_toml_full_opt = NULL,
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
	"dog_toml_full_opt",
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
	&dogconfig.dog_toml_full_opt,
	&dogconfig.dog_toml_root_patterns,
	&dogconfig.dog_toml_packages,
	&dogconfig.dog_toml_serv_input,
	&dogconfig.dog_toml_serv_output
};

void _sef_restore(void)
{
	size_t	 i, fet_sef_ent;

	fet_sef_ent
		= sizeof(dogconfig.dog_sef_found_list) /
	    sizeof(dogconfig.dog_sef_found_list[0]);

    /* Clear each SEF entry */
	for (i = 0; i < fet_sef_ent; i++) {
		dogconfig.dog_sef_found_list[i][0] = '\0';
	} /* for */

	dogconfig.dog_sef_count = RATE_SEF_EMPTY;
	memset(dogconfig.dog_sef_found_list, RATE_SEF_EMPTY,
	    sizeof(dogconfig.dog_sef_found_list));
} /* _sef_restore */

#ifdef DOG_LINUX

#ifndef strlcpy
size_t
strlcpy(char *dst, const char *src, size_t size)
{
	size_t	 src_len = strlen(src);
	size_t   copy_len = 0;

	if (size > 0) {
		copy_len = (src_len >= size) ? size - 1 : src_len;
		memcpy(dst, src, copy_len);
		dst[copy_len] = '\0';
	} /* if */
	
	return (src_len);
} /* strlcpy */
#endif

#ifndef strlcat
size_t
strlcat(char *dst, const char *src, size_t size)
{
	size_t	 dst_len = strlen(dst);
	size_t	 src_len = strlen(src);
	size_t	 copy_len = 0;

	if (dst_len < size) {
		copy_len = size - dst_len - 1;

		if (copy_len > src_len) {
			copy_len = src_len;
		} /* if */
		
		memcpy(dst + dst_len, src, copy_len);
		dst[dst_len + copy_len] = '\0';
	} /* if */
	
	return (dst_len + src_len);
} /* strlcat */
#endif

#else

size_t
w_strlcpy(char *dst, const char *src, size_t size)
{
	size_t	 len = strlen(src);
	size_t   copy = 0;

	if (size > 0) {
		copy = (len >= size) ? size - 1 : len;
		memcpy(dst, src, copy);
		dst[copy] = 0;
	} /* if */
	
	return (len);
} /* w_strlcpy */

size_t
w_strlcat(char *dst, const char *src, size_t size)
{
	size_t	 dlen = strlen(dst);
	size_t	 slen = strlen(src);
	size_t	 space = 0;
	size_t	 copy = 0;

	if (dlen < size) {
		space = size - dlen - 1;
		copy = (slen > space) ? space : slen;
		memcpy(dst + dlen, src, copy);
		dst[dlen + copy] = 0;
		return (dlen + slen);
	} /* if */
	
	return (size + slen);
} /* w_strlcat */

#endif

void * dog_malloc(size_t size)
{
	void	*ptr = malloc(size);

	if (!ptr) {
		fprintf(stderr,
			"malloc failed: %zu bytes\n", size);
		minimal_debugging();
	} /* if */
	
	return (ptr);
} /* dog_malloc */

void * dog_calloc(size_t count, size_t size)
{
	void	*ptr = calloc(count, size);

	if (!ptr) {
		fprintf(stderr,
		    "calloc failed: %zu "
			"elements x %zu bytes\n", count, size);
		return (NULL);
	} /* if */
	
	return (ptr);
} /* dog_calloc */

void * dog_realloc(void *ptr, size_t size)
{
	void	*new_ptr = NULL;

	new_ptr = (ptr ? realloc(ptr, size) : malloc(size));

	if (!new_ptr) {
		fprintf(stderr,
		"realloc failed: %zu bytes\n", size);
		return (NULL);
	} /* if */
	
	return (new_ptr);
} /* dog_realloc */

void dog_free(void *ptr)
{
	if (ptr) {
		free(ptr);
		ptr = NULL;
	} /* if */
	
	return;
} /* dog_free */

bool
fet_server_env(void)
{
	bool result = false;

	if (strcmp(dogconfig.dog_is_samp, CRC32_TRUE) == 0) {
		result = false;
	} else if (strcmp(dogconfig.dog_is_omp, CRC32_TRUE) == 0) {
		result = true;
	} /* if */
	
	return result;
} /* fet_server_env */

static
bool
is_running_in_container(void)
{
	FILE	*fp = NULL;
    bool    result = false;

	if (path_access("/.dockerenv") == 1) {
		return (true);
    } /* if */
	
	if (path_access("/run/.containerenv") == 1) {
		return (true);
    } /* if */

	pbuf[0] = '\0';

	fp = fopen("/proc/1/cgroup", "r");
	if (fp != NULL) {
		while (fgets(pbuf, sizeof(pbuf), fp) != NULL) {
			if (strstr(pbuf, "/docker/") ||
			    strstr(pbuf, "/podman/") ||
			    strstr(pbuf, "/containerd/"))
			{
				fclose(fp);
				return (true);
			} /* if */
		} /* while */
		fclose(fp);
	} /* if */

	return (false);
} /* is_running_in_container */

void
path_sep_to_posix(char *path)
{
	char	*pos;
    int     converted = 0;

    if (path == NULL) {
        pr_error(stdout, "path_sep_to_posix: path is NULL");
        return;
    } /* if */

	for (pos = path; *pos; pos++) {
		if (*pos == _PATH_CHR_SEP_WIN32) {
			*pos = _PATH_CHR_SEP_POSIX;
            converted++;
        } /* if */
	} /* for */
	
    if (converted > 0) {
		;
    } /* if */
} /* path_sep_to_posix */

void
path_sep_to_win32(char *path)
{
	char    *pos;
    int     converted = 0;

    if (path == NULL) {
        pr_error(stdout, "path_sep_to_win32: path is NULL");
        return;
    } /* if */

	for (pos = path; *pos; pos++) {
		if (*pos == _PATH_CHR_SEP_POSIX) {
			*pos = _PATH_CHR_SEP_WIN32;
            converted++;
        } /* if */
	} /* for */
	
    if (converted > 0) {
		;
    } /* if */
} /* path_sep_to_win32 */

int
dir_exists(const char *path)
{
	struct stat	 st;
    int         result = 0;

    if (path == NULL) {
        pr_error(stdout, "dir_exists: path is NULL");
        return (0);
    } /* if */

	if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
		result = 1;
    } /* if */

	return (result);
} /* dir_exists */

int
path_exists(const char *path)
{
	struct stat	 st;
    int         result = 0;

    if (path == NULL) {
        pr_error(stdout, "path_exists: path is NULL");
        return (0);
    } /* if */

	if (stat(path, &st) == 0) {
		result = 1;
    } /* if */
	
	return (result);
} /* path_exists */

int
dir_writable(const char *path)
{
    int result = 0;

    if (path == NULL) {
        pr_error(stdout, "dir_writable: path is NULL");
        return (0);
    } /* if */

	if (access(path, W_OK) == 0) {
		result = 1;
    } /* if */
	
	return (result);
} /* dir_writable */

int
path_access(const char *path)
{
    int result = 0;

    if (path == NULL) {
        pr_error(stdout, "path_access: path is NULL");
        return (0);
    } /* if */

	if (access(path, F_OK) == 0) {
		result = 1;
    } /* if */
	
	return (result);
} /* path_access */

int
file_regular(const char *path)
{
	struct stat	 st;
    int         result = 0;

    if (path == NULL) {
        pr_error(stdout, "file_regular: path is NULL");
        return (0);
    } /* if */

	if (stat(path, &st) != 0) {
        pr_info(stdout, "file_regular: stat failed for %s", path);
		return (0);
	} /* if */
	
	result = S_ISREG(st.st_mode);
	return (result);
} /* file_regular */

int
file_same_file(const char *a, const char *b)
{
	struct stat	 sa, sb;
    int         result = 0;

    if (a == NULL || b == NULL) {
        pr_error(stdout, "file_same_file: NULL argument");
        return (0);
    } /* if */

	if (stat(a, &sa) != 0) {
        pr_info(stdout, "file_same_file: stat failed for %s", a);
		return (0);
	} /* if */
	
	if (stat(b, &sb) != 0) {
        pr_info(stdout, "file_same_file: stat failed for %s", b);
		return (0);
	} /* if */

	result = (sa.st_ino == sb.st_ino && sa.st_dev == sb.st_dev);
	return (result);
} /* file_same_file */

const char
*lookup_path_sep(const char *sep_path) {
    const char *_l = NULL;
    const char *_w = NULL;

    if (!sep_path) {
        pr_error(stdout, "lookup_path_sep: path is NULL");
        return NULL;
    } /* if */

    _l = strrchr(sep_path, _PATH_CHR_SEP_POSIX);
    _w = strrchr(sep_path, _PATH_CHR_SEP_WIN32);

    if (_l && _w) {
        return (_l > _w) ? _l : _w;
    } else {
        return (_l ? _l : _w);
    } /* if */
} /* lookup_path_sep */

const char * fet_filename(const char *path)
{
	const char	*p = NULL;

    if (path == NULL) {
        pr_error(stdout, "fet_filename: path is NULL");
        return NULL;
    } /* if */

	p = lookup_path_sep(path);
	return (p ? p + 1 : path);
} /* fet_filename */

char * fet_basename(const char *path)
{
    const char *filename = NULL;
    char *base = NULL;
    char *dot = NULL;

    if (path == NULL) {
        pr_error(stdout, "fet_basename: path is NULL");
        return NULL;
    } /* if */

    filename = fet_filename(path);
    base = strdup(filename);
    
    if (!base) {
        pr_error(stdout, "fet_basename: strdup failed");
        return NULL;
    } /* if */

    dot = strrchr(base, '.');

    if (dot != NULL) {
        *dot = '\0';
    } /* if */

    return base;
} /* fet_basename */

char * dog_procure_pwd(void)
{
	static char	 dog_work_dir[DOG_PATH_MAX] = { 0 };

	if (dog_work_dir[0] == '\0') {
		if (getcwd(dog_work_dir, sizeof(dog_work_dir)) == NULL) {
            pr_error(stdout, "dog_procure_pwd: getcwd failed: %s", strerror(errno));
			dog_work_dir[0] = '\0';
		} /* if */
	} /* if */
	
	return (dog_work_dir);
} /* dog_procure_pwd */

char *
dog_masked_text(int reveal, const char *text)
{
	char	*masked = NULL;
	int	 len, i;

	if (!text) {
        pr_error(stdout, "dog_masked_text: text is NULL");
		return (NULL);
	} /* if */

	len = (int)strlen(text);
	
	if (reveal < 0) {
		reveal = 0;
    } /* if */
	
	if (reveal > len) {
		reveal = len;
    } /* if */

	masked = dog_malloc((size_t)len + 1);
	if (!masked) {
        pr_error(stdout, "dog_masked_text: memory allocation failed");
		unit_ret_main(NULL);
	} /* if */

	if (reveal > 0) {
		memcpy(masked, text, (size_t)reveal);
    } /* if */

	for (i = reveal; i < len; ++i) {
		masked[i] = '?';
    } /* for */

	masked[len] = '\0';
	return (masked);
} /* dog_masked_text */

int dog_mkdir_recursive(const char *path)
{
	char	*p = NULL;
	size_t	 len = 0;
    int     ret = 0;

	if (!path || !*path) {
        pr_error(stdout, "dog_mkdir_recursive: invalid path");
		return (-1);
	} /* if */

	pbuf[0] = '\0';

	(void)snprintf(pbuf, sizeof(pbuf), "%s", path);
	len = strlen(pbuf);

	if (len > 1 && pbuf[len - 1] == '/') {
		pbuf[len - 1] = '\0';
    } /* if */

	for (p = pbuf + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (MKDIR(pbuf) != 0 && errno != EEXIST) {
				perror("mkdir");
				return (-1);
			} /* if */
			*p = '/';
		} /* if */
	} /* for */

	if (MKDIR(pbuf) != 0 && errno != EEXIST) {
		perror("mkdir");
		return (-1);
	} /* if */

	return (0);
} /* dog_mkdir_recursive */

int is_binary_file(char *path) {
	
    unsigned char  buffer[512] = {0};
	int      fd = -1;
	ssize_t  i, bytes_read = 0;
	int      n_printable = 0;
	struct   stat st;
    int      result = 0;

    if (path == NULL) {
        pr_error(stdout, "is_binary_file: path is NULL");
        return false;
    } /* if */

	#ifdef DOG_WINDOWS
	fd = open(path, O_RDONLY | O_BINARY);
	#else
	fd = open(path, O_RDONLY
	#ifdef O_NOFOLLOW
	    | O_NOFOLLOW
	#endif
	#ifdef O_CLOEXEC
	    | O_CLOEXEC
	#endif
	);
	#endif

	if (fd < 0) {
	    pr_error(stderr, "open failed for %s: %s", path, strerror(errno));
	    minimal_debugging();
	    return false;
	} /* if */

	if (fstat(fd, &st) != 0) {
	    pr_error(stderr, "fstat failed for %s: %s", path, strerror(errno));
	    minimal_debugging();
	    close(fd);
	    return false;
	} /* if */

	if (!S_ISREG(st.st_mode)) {
	    pr_error(stderr, "Not a regular file: %s", path);
	    minimal_debugging();
	    close(fd);
	    return false;
	} /* if */

    bytes_read = read(fd, buffer, sizeof(buffer));
    if (bytes_read < 0) {
        pr_error(stderr, "read failed for %s: %s", path, strerror(errno));
        minimal_debugging();
        close(fd);
        return false;
    } /* if */

	for (i = 0; i < bytes_read; i++) {
	    if (buffer[i] == 0) {
	        close(fd);
	        return true;
	    } /* if */
	    
	    if (buffer[i] < 7
			|| (buffer[i] > 14
			&& buffer[i] < 32))
		{
	        n_printable++;
	    } /* if */
	} /* for */

	close(fd);

	if (n_printable > bytes_read * 0.3) {
	    result = true;
    } /* if */

	return result;
} /* is_binary_file */

void print_restore_color(void) {

	print(BKG_DEFAULT);
	print(DOG_COL_RESET);
	print(DOG_COL_DEFAULT);

	return;
} /* print_restore_color */

void println(FILE *stream, const char *format, ...) {
	va_list    args;

    if (stream == NULL) {
        stream = stdout;
    } /* if */
    
    if (format == NULL) {
        return;
    } /* if */

	va_start(args, format);
	print_restore_color();
	vfprintf(stream, format, args);
	(void)putchar('\n');
	print_restore_color();
	va_end(args);
	fflush(stream);
} /* println */

void
printf_colour(FILE *stream,
			  const char *color,
			  const char *format, ...)
{
	va_list    args;

    if (stream == NULL) {
        stream = stdout;
    } /* if */
    
    if (color == NULL || format == NULL) {
        return;
    } /* if */

	va_start(args, format);
	print_restore_color();
	printf("%s", color);
	vfprintf(stream, format, args);
	print_restore_color();
	va_end(args);
	fflush(stream);
} /* printf_colour */

void
printf_info(FILE *stream, const char *format, ...) {
	va_list    args;

    if (stream == NULL) {
        stream = stdout;
    } /* if */
    
    if (format == NULL) {
        return;
    } /* if */

	va_start(args, format);
	print_restore_color();
	print(DOG_COL_YELLOW);
	print("@ Hey!");
	print_restore_color();
	print(": ");
	vfprintf(stream, format, args);
	(void)putchar('\n');
	va_end(args);
	fflush(stream);
} /* printf_info */

void
printf_warning(FILE *stream, const char *format, ...) {
	va_list    args;

    if (stream == NULL) {
        stream = stdout;
    } /* if */
    
    if (format == NULL) {
        return;
    } /* if */

	va_start(args, format);
	print_restore_color();
	print(DOG_COL_GREEN);
	print("@ Uh-oh!");
	print_restore_color();
	print(": ");
	vfprintf(stream, format, args);
	(void)putchar('\n');
	va_end(args);
	fflush(stream);
} /* printf_warning */

void
printf_error(FILE *stream, const char *format, ...) {
	va_list    args;

    if (stream == NULL) {
        stream = stdout;
    } /* if */
    
    if (format == NULL) {
        return;
    } /* if */

	va_start(args, format);
	print_restore_color();
	print(DOG_COL_RED);
	print("@ Oops!");
	print_restore_color();
	print(": ");
	vfprintf(stream, format, args);
	(void)putchar('\n');
	va_end(args);
	fflush(stream);
} /* printf_error */

static char *build_cmdline(char *const av[])
{
    size_t len = 0;
    int i;
    char *cmd = NULL;

    if (av == NULL) {
        pr_error(stdout, "build_cmdline: argv is NULL");
        return NULL;
    } /* if */

    for (i = 0; av[i] != NULL; i++) {
        len += strlen(av[i]) + 3;
    } /* for */

    cmd = malloc(len + 1);
    if (!cmd) {
        pr_error(stdout, "build_cmdline: malloc failed for %zu bytes", len + 1);
        return NULL;
    } /* if */

    cmd[0] = '\0';

    for (i = 0; av[i] != NULL; i++) {
        strcat(cmd, "\"");
        strcat(cmd, av[i]);
        strcat(cmd, "\"");
        if (av[i+1] != NULL) {
            strcat(cmd, " ");
        } /* if */
    } /* for */

    return cmd;
} /* build_cmdline */

int
dog_user_command(char *const av[])
{
    int result = -1;

    if (av == NULL || av[0] == NULL) {
        pr_error(stdout, "dog_user_command: invalid arguments");
        return (-1);
    } /* if */
    
	if (strlen(av[0]) >= DOG_MAX_PATH) {
        pr_error(stdout, "dog_user_command: command too long");
		return (-1);
    } /* if */

#ifdef DOG_LINUX
	pbuf[0] = '\0';
	(void)snprintf(pbuf, sizeof(pbuf),
		"which %s > /dev/null 2>&1", av[0]);
		
	if (system(pbuf) > 0) {
		fprintf(stderr,
			"dog: %s: command not found\n", av[0]);
		fflush(stderr);
		return (-1);
	} /* if */

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork failed");
        return (-1);
    } /* if */

    if (pid == 0) {
        execvp(av[0], av);
        _exit(127);
    } /* if */

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid failed");
        return (-1);
    } /* if */

    if (WIFEXITED(status)) {
        result = WEXITSTATUS(status);
    } /* if */

    return result;
#else
    char *cmdline = build_cmdline(av);
    if (!cmdline) {
        return (-1);
    } /* if */

    STARTUPINFO         _STARTUPINFO  = {0};
    PROCESS_INFORMATION _PROCESS_INFO = {0};

    _STARTUPINFO.cb = sizeof(_STARTUPINFO);

    pbuf[0] = '\0';

    (void)snprintf(pbuf, sizeof(pbuf), "cmd.exe /C %s", cmdline);

    BOOL ok = CreateProcess(
        NULL, pbuf, NULL, NULL,
        FALSE, 0, NULL, NULL,
        &_STARTUPINFO, &_PROCESS_INFO
    );

    free(cmdline);

    if (!ok) {
        fprintf(stdout,
            "failed to CreateProcess..");
        minimal_debugging();
        return -1;
    } /* if */

    WaitForSingleObject(_PROCESS_INFO.hProcess, INFINITE);

    DWORD exit_code = 0;
    GetExitCodeProcess(_PROCESS_INFO.hProcess, &exit_code);

    CloseHandle(_PROCESS_INFO.hProcess);
    CloseHandle(_PROCESS_INFO.hThread);

    result = (int)exit_code;
    return result;
#endif
} /* dog_user_command */

void
dog_printfile(const char *path)
{
    if (path == NULL) {
        pr_error(stdout, "dog_printfile: path is NULL");
        return;
    } /* if */

#ifdef DOG_WINDOWS
	int	 fd = -1;
	char	 buf[(1 << 20) + 1];
	ssize_t	 n, w, k;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
        pr_error(stdout, "dog_printfile: failed to open %s", path);
		return;
    } /* if */

	for (;;) {
		n = read(fd, buf, sizeof(buf) - 1);
		if (n <= 0) {
			break;
        } /* if */

		buf[n] = '\0';
		w = 0;
		while (w < n) {
			k = write(STDOUT_FILENO,
					  buf + w, n - w);
			if (k <= 0) {
				close(fd);
				return;
			} /* if */
			w += k;
		} /* while */
	} /* for */

	close(fd);
#else
	int		 fd = -1;
	struct stat	 st;
	off_t		 off = 0;
	char		 buf[(1 << 20) + 1];
	ssize_t		 to_read, n, w, k;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
        pr_error(stdout, "dog_printfile: failed to open %s", path);
		return;
    } /* if */

	if (fstat(fd, &st) < 0) {
        pr_error(stdout, "dog_printfile: fstat failed for %s", path);
		close(fd);
		return;
	} /* if */

	while (off < st.st_size) {
		to_read = (st.st_size - off) < (sizeof(buf) - 1) ?
		    (st.st_size - off) : (sizeof(buf) - 1);
		n = pread(fd, buf, to_read, off);
		if (n <= 0) {
			break;
        } /* if */
		off += n;

		buf[n] = '\0';
		w = 0;
		while (w < n) {
			k = write(STDOUT_FILENO,
					  buf + w, n - w);
			if (k <= 0) {
				close(fd);
				return;
			} /* if */
			w += k;
		} /* while */
	} /* while */

	close(fd);
#endif
	return;
} /* dog_printfile */

bool dog_console_title(const char *title)
{
	const char	*new_title = NULL;
    bool        result = false;
    
#ifdef DOG_ANDROID
	return (false);
#endif

	if (!title) {
		new_title = watchdogs_release;
    } else {
		new_title = title;
    } /* if */

#ifdef DOG_WINDOWS
	int ok = SetConsoleTitleA(new_title);
	if (!ok) {
        pr_info(stdout, "dog_console_title: SetConsoleTitleA failed");
	} /* if */
#else
	if (isatty(STDOUT_FILENO)) {
		printf("\033]0;%s\007", new_title);
        result = true;
    } /* if */
#endif
	return (result);
} /* dog_console_title */

static
void
dog_strip_dot_fns(char *dst, size_t dst_sz, const char *src)
{
	char	*slash = NULL, *dot = NULL;
	size_t	 len = 0;

	if (!dst || dst_sz == 0 || !src) {
        pr_error(stdout, "dog_strip_dot_fns: invalid parameters");
		return;
    } /* if */

	slash = strchr(src, _PATH_CHR_SEP_POSIX);
#ifdef DOG_WINDOWS
	if (!slash) {
		slash = strchr(src, _PATH_CHR_SEP_WIN32);
    } /* if */
#endif

	if (!slash) {
		dot = strchr(src, '.');
		if (dot) {
			len = (size_t)(dot - src);
			if (len >= dst_sz) {
				len = dst_sz - 1;
            } /* if */
			memcpy(dst, src, len);
			dst[len] = '\0';
			return;
		} /* if */
	} /* if */

	(void)snprintf(dst, dst_sz, "%s", src);
} /* dog_strip_dot_fns */

bool dog_strcase(const char *text, const char *pattern)
{
	const char	*p, *a, *b;

    if (text == NULL || pattern == NULL) {
        return false;
    } /* if */

	for (p = text; *p; p++) {
		a = p;
		b = pattern;
		while (*a && *b && (((*a | 32) == (*b | 32)))) {
			a++;
			b++;
		} /* while */
		if (!*b) {
			return (true);
        } /* if */
	} /* for */
	
	return (false);
} /* dog_strcase */

bool strend(const char *str, const char *suffix, bool nocase)
{
	size_t	 lenstr, lensuf;
	const char *p;
    bool    result = false;

	if (!str || !suffix) {
        pr_error(stdout, "strend: NULL argument");
		return (false);
	} /* if */

	lenstr = strlen(str);
	lensuf = strlen(suffix);

	if (lensuf > lenstr) {
		return (false);
    } /* if */

	p = str + (lenstr - lensuf);
	
    if (nocase) {
	    result = (strncasecmp(p, suffix, lensuf) == 0);
    } else {
	    result = (memcmp(p, suffix, lensuf) == 0);
    } /* if */
    
    return result;
} /* strend */

bool strfind(const char *text, const char *pattern, bool nocase)
{
	size_t	 m;
	const char *p;
	char	 c1, c2;

	if (!text || !pattern) {
        pr_error(stdout, "strfind: NULL argument");
		return (false);
	} /* if */

	m = strlen(pattern);
	if (m == 0) {
		return (true);
    } /* if */

	p = text;
	while (*p) {
		c1 = *p;
		c2 = *pattern;

		if (nocase) {
			c1 = tolower((unsigned char)c1);
			c2 = tolower((unsigned char)c2);
		} /* if */

		if (c1 == c2) {
			if (nocase) {
				if (strncasecmp(p, pattern, m) == 0) return (true);
			} else {
				if (memcmp(p, pattern, m) == 0) return (true);
			} /* if */
		} /* if */
		p++;
	} /* while */

	return (false);
} /* strfind */

int match_wildcard(const char *str, const char *pat)
{
	const char	*s = str;
	const char	*p = pat;
	const char	*star = NULL;
	const char	*ss = NULL;

    if (str == NULL || pat == NULL) {
        return 0;
    } /* if */

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
		} /* if */
	} /* while */

	while (*p == '*') {
		p++;
    } /* while */

	return (*p == '\0');
} /* match_wildcard */

void normalize_spaces(char *str)
{
    char *src = str;
    char *dst = str;
    int space = 0;

    if (str == NULL) {
        pr_error(stdout, "normalize_spaces: str is NULL");
        return;
    } /* if */

    while (*src) {
        if (isspace((unsigned char)*src)) {
            if (!space) {
                *dst++ = ' ';
                space = 1;
            } /* if */
        } else {
            *dst++ = *src;
            space = 0;
        } /* if */
        src++;
    } /* while */

    if (dst > str && *(dst - 1) == ' ') {
        dst--;
    } /* if */

    *dst = '\0';
} /* normalize_spaces */

static void configure_path_sep(char *out, size_t sk_dependssz,
                               const char *open_dir,
                               const char *entry_name)
{
    size_t dir_len, entry_len, need;
    int dir_has_sep, entry_has_sep;
    size_t pos = 0;

    if (!out || sk_dependssz == 0 || !open_dir || !entry_name) {
        pr_error(stdout, "configure_path_sep: invalid parameters");
        return;
    } /* if */

    dir_len = strlen(open_dir);
    entry_len = strlen(entry_name);

    dir_has_sep = (dir_len > 0 && IS_PATH_SEP(open_dir[dir_len - 1]));
    entry_has_sep = (entry_len > 0 && IS_PATH_SEP(entry_name[0]));

    need = dir_len + entry_len + 1;

    if (!dir_has_sep && !entry_has_sep) {
        need += 1;
    } /* if */

    if (need > sk_dependssz) {
        out[0] = '\0';
        return;
    } /* if */

    memcpy(out, open_dir, dir_len);
    pos = dir_len;

    if (!dir_has_sep && !entry_has_sep) {
        out[pos++] = _PATH_SEP_SYSTEM[0];
    } else if (dir_has_sep && entry_has_sep) {
        entry_name++;
        entry_len--;
    } /* if */

    memcpy(out + pos, entry_name, entry_len);
    pos += entry_len;
    out[pos] = '\0';
} /* configure_path_sep */

__PURE__
static int __command_suggest(const char *s1, const char *s2)
{
	size_t	 len1, len2;
	int i, j;
	uint16_t*buf1 = NULL, *buf2 = NULL, *prev = NULL, *curr = NULL, *tmp = NULL;
	char	 c1, c2;
	int	 cost, del, ins, sub, val, min_row;

    if (s1 == NULL || s2 == NULL) {
        return INT_MAX;
    } /* if */

	len1 = strlen(s1);
	len2 = strlen(s2);
	
	if (len2 > 128) {
		return (INT_MAX);
    } /* if */

	buf1 = alloca((len2 + 1) * sizeof(uint16_t));
	buf2 = alloca((len2 + 1) * sizeof(uint16_t));
	prev = buf1;
	curr = buf2;

	for (j = 0; j <= len2; j++) {
		prev[j] = j;
    } /* for */

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
			if (val < min_row) {
				min_row = val;
            } /* if */
		} /* for */

		if (min_row > 6) {
			return (min_row + (len1 - i));
        } /* if */

		tmp = prev;
		prev = curr;
		curr = tmp;
	} /* for */

	return (prev[len2]);
} /* __command_suggest */

const char * dog_find_near_command(const char *cmd,
								   const char *commands[],
    size_t 						   num_cmds, int *sk_dependsdistance)
{
	int		 best_distance = INT_MAX;
	const char	*best_cmd = NULL;
	size_t		 i;

    if (cmd == NULL || commands == NULL) {
        return NULL;
    } /* if */

	for (i = 0; i < num_cmds; i++) {
        if (commands[i] == NULL) {
            continue;
        } /* if */
        
		int	 dist = __command_suggest(cmd, commands[i]);

		if (dist < best_distance) {
			best_distance = dist;
			best_cmd = commands[i];
			if (best_distance == 0) {
				break;
            } /* if */
		} /* if */
	} /* for */

	if (sk_dependsdistance) {
		*sk_dependsdistance = best_distance;
    } /* if */

	return (best_cmd);
} /* dog_find_near_command */

static const char * dog_procure_os(void)
{
	static char	 os[64] = "unknown";

#define PROC_WSL_INTEROP_PATH "/proc/sys/fs/binfmt_misc/WSLInterop"
	
    if (is_running_in_container()) {
        strncpy(os, "linux", sizeof(os));
		os[sizeof(os) - 1] = '\0';
		return (os);
    } else if (path_access(PROC_WSL_INTEROP_PATH) == 1) {
        strncpy(os, "windows", sizeof(os));
		os[sizeof(os) - 1] = '\0';
		return (os);
    } /* if */

#ifdef DOG_WINDOWS
	strncpy(os, "windows", sizeof(os));
#else
	strncpy(os, "linux", sizeof(os));
#endif

	os[sizeof(os)-1] = '\0';
	return (os);
} /* dog_procure_os */

__PURE__
static int
ensure_parent_dir(char *sk_dependsparent, size_t n, const char *dest)
{
	char	 tmp[DOG_PATH_MAX] = {0};
	char	*parent = NULL;
    int     result = -1;

    if (sk_dependsparent == NULL || dest == NULL) {
        return (-1);
    } /* if */

	if (strlen(dest) >= sizeof(tmp)) {
		return (-1);
    } /* if */

	strncpy(tmp, dest, sizeof(tmp));
	tmp[sizeof(tmp)-1] = '\0';
	parent = dirname(tmp);
	if (!parent) {
		return (-1);
    } /* if */

	strncpy(sk_dependsparent, parent, n);
	sk_dependsparent[n-1] = '\0';
    result = 0;
    
	return (result);
} /* ensure_parent_dir */

bool
dog_kill_process(const char *process)
{
    if (!process) {
        pr_error(stdout, "dog_kill_process: process name is NULL");
        return (false);
    } /* if */

#ifdef DOG_WINDOWS
	pbuf[0] = '\0';

    STARTUPINFOA        _STARTUPINFO  = {0};
    PROCESS_INFORMATION _PROCESS_INFO = {0};

    _STARTUPINFO.cb = sizeof(_STARTUPINFO);

    (void)snprintf(pbuf, sizeof(pbuf),
        "C:\\Windows\\System32\\taskkill.exe "
		"/F /IM \"%s\"",
        process
    );

    if (!CreateProcessA(
		NULL, pbuf,
		NULL, NULL, FALSE,
		CREATE_NO_WINDOW,
		NULL, NULL,
		&_STARTUPINFO,
		&_PROCESS_INFO))
	{
        pr_error(stdout, "dog_kill_process: CreateProcess failed");
        return (false);
	} /* if */

    WaitForSingleObject(_PROCESS_INFO.hProcess, INFINITE);
    CloseHandle(_PROCESS_INFO.hProcess);
    CloseHandle(_PROCESS_INFO.hThread);

    return (true);

#else

#if !defined(DOG_ANDROID) && defined(DOG_LINUX)
	if (process[0] == '.') {
		return (false);
    } /* if */
		
    pid_t pid = fork();
    if (pid == 0) {
        execlp("pkill", "pkill", "-SIGTERM", process, NULL);
        _exit(127);
    } /* if */
    
    if (pid < 0) {
        pr_error(stdout, "dog_kill_process: fork failed");
        return (false);
    } /* if */
    
    waitpid(pid, NULL, 0);
    return (true);
#else
    pid_t pid = fork();
    if (pid == 0) {
        execlp("pgrep", "pgrep", "-f", process, NULL);
        _exit(127);
    } /* if */
    
    if (pid < 0) {
        pr_error(stdout, "dog_kill_process: fork failed");
        return (false);
    } /* if */
    
    waitpid(pid, NULL, 0);
    return (true);
#endif

#endif
} /* dog_kill_process */

static int
dog_match_filename(const char *entry_name, const char *pattern)
{
    int result = 0;

    if (entry_name == NULL || pattern == NULL) {
        return 0;
    } /* if */

	if (!strchr(pattern, '*') && !strchr(pattern, '?')) {
		result = (strcmp(entry_name, pattern) == 0);
    } else {
		result = match_wildcard(entry_name, pattern);
    } /* if */
    
    return result;
} /* dog_match_filename */

int
dog_dot_or_dotdot(const char *entry_name)
{
    int result = 0;

    if (entry_name == NULL) {
        return 0;
    } /* if */

	result = (entry_name[0] == '.' &&
	    (entry_name[1] == '\0' ||
	    (entry_name[1] == '.' && entry_name[2] == '\0')));
    
    return result;
} /* dog_dot_or_dotdot */

static int
dog_procure_ignore_dir(const char *entry_name, const char *ignore_dir)
{
    int result = 0;

    if (entry_name == NULL || ignore_dir == NULL) {
        return 0;
    } /* if */

#ifdef DOG_WINDOWS
	result = (_stricmp(entry_name, ignore_dir) == 0);
#else
	result = (strcmp(entry_name, ignore_dir) == 0);
#endif

    return result;
} /* dog_procure_ignore_dir */

static void dog_ensure_found_path(const char *path)
{
	size_t    sef_found =
		sizeof(dogconfig.dog_sef_found_list) /
		sizeof(dogconfig.dog_sef_found_list[0]);
		
	if (dogconfig.dog_sef_count < sef_found)
	{
		strncpy(dogconfig.dog_sef_found_list[dogconfig.dog_sef_count],
		    path, MAX_SEF_PATH_SIZE);
		dogconfig.dog_sef_found_list[dogconfig.dog_sef_count]
		    [MAX_SEF_PATH_SIZE - 1] = '\0';
		++dogconfig.dog_sef_count;
	} /* if */
} /* dog_ensure_found_path */

int dog_find_path(const char *sef_path, const char *sef_name, const char *ignore_dir)
{
	char		 size_path[MAX_SEF_PATH_SIZE] = {0};
    int          found = 0;

    if (strlen(sef_path) < 1 && strlen(sef_name) < 1) {
        pr_error(stdout, "dog_find_path: invalid parameters");
        return 0;
    } /* if */

#ifdef DOG_WINDOWS
	HANDLE		 find_handle;
	char		 sp[DOG_MAX_PATH * 2] = {0};
	const char	*entry_name = NULL;
	WIN32_FIND_DATA	 find_data = {0};

	if (sef_path[strlen(sef_path) - 1] == _PATH_CHR_SEP_WIN32) {
		(void)snprintf(sp, sizeof(sp), "%s*", sef_path);
	} else {
		(void)snprintf(sp, sizeof(sp), "%s%s*", sef_path,
		    _PATH_STR_SEP_WIN32);
	} /* if */

	find_handle = FindFirstFile(sp, &find_data);
	if (find_handle == INVALID_HANDLE_VALUE) {
        pr_info(stdout, "dog_find_path: FindFirstFile failed for %s", sp);
		return (0);
    } /* if */

	do {
		entry_name = find_data.cFileName;
		if (dog_dot_or_dotdot(entry_name)) {
			continue;
        } /* if */

		configure_path_sep(size_path, sizeof(size_path), sef_path,
		    entry_name);

		if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (dog_procure_ignore_dir(entry_name, ignore_dir)) {
				continue;
            } /* if */

			if (dog_find_path(size_path, sef_name, ignore_dir)) {
				FindClose(find_handle);
				return (1);
			} /* if */
		} else {
			if (dog_match_filename(entry_name, sef_name)) {
				dog_ensure_found_path(size_path);
				FindClose(find_handle);
				return (1);
			} /* if */
		} /* if */
	} while (FindNextFile(find_handle, &find_data) != 0);

	FindClose(find_handle);
#else
	DIR *dir = NULL;
    struct dirent *entry = NULL;

    dir = opendir(sef_path);
    if (!dir) {
        pr_info(stdout, "dog_find_path: opendir failed for %s", sef_path);
        return 0;
    } /* if */

    while ((entry = readdir(dir)) != NULL) {
        if (dog_dot_or_dotdot(entry->d_name)) {
            continue;
        } /* if */

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
            if (dog_procure_ignore_dir(entry->d_name, ignore_dir)) {
                continue;
            } /* if */
            if (dog_find_path(size_path, sef_name, ignore_dir)) {
                closedir(dir);
                return (1);
            } /* if */
        } else if (is_reg) {
            if (dog_match_filename(entry->d_name, sef_name)) {
                dog_ensure_found_path(size_path);
                closedir(dir);
                return (1);
            } /* if */
        } /* if */
    } /* while */

    closedir(dir);
#endif

	return (0);
} /* dog_find_path */

int equals(const char *a, const char *b) {
    if (a == NULL || b == NULL) {
        return (a == b);
    } /* if */
    
    while (*a && *b) {
        if (tolower((unsigned char)*a) !=
            tolower((unsigned char)*b)) {
            return 0;
        } /* if */
        a++; b++;
    } /* while */
    
    return *a == *b;
} /* equals */

#ifndef DOG_WINDOWS

static int
_run_command_vfork(char *const argv[])
{
    pid_t pid;
    int status;
    int result = -1;

    if (argv == NULL || argv[0] == NULL) {
        return (-1);
    } /* if */

    pid = vfork();

    if (pid < 0) {
        return (-1);
    } /* if */

    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    } /* if */

    if (waitpid(pid, &status, 0) < 0) {
        return (-1);
    } /* if */

    if (WIFEXITED(status)) {
        result = WEXITSTATUS(status);
    } /* if */

    return result;
} /* _run_command_vfork */

#endif

#ifdef DOG_WINDOWS

static int
_run_windows_command(const char *cmds)
{
    DWORD exit_code = 0;
    STARTUPINFO         _STARTUPINFO  = {0};
    PROCESS_INFORMATION _PROCESS_INFO = {0};
    int result = -1;

    if (cmds == NULL) {
        return (-1);
    } /* if */

    _STARTUPINFO.cb = sizeof(_STARTUPINFO);

    if (!CreateProcess(
		NULL, (char *)cmds,
		NULL, NULL, FALSE,
		0, NULL, NULL,
		&_STARTUPINFO,
		&_PROCESS_INFO))
    {
        pr_error(stdout, "_run_windows_command: CreateProcess failed");
        return (-1);
    } /* if */

    WaitForSingleObject(_PROCESS_INFO.hProcess, INFINITE);
    GetExitCodeProcess(_PROCESS_INFO.hProcess, &exit_code);

    CloseHandle(_PROCESS_INFO.hProcess);
    CloseHandle(_PROCESS_INFO.hThread);

    result = (int)exit_code;
    return result;
} /* _run_windows_command */

#endif

static int
validate_src_dest(const char *c_src, const char *c_dest)
{
    struct stat st = {0};
    int valid = 0;

    if (!c_src || !c_dest) {
        pr_error(stdout, "validate_src_dest: NULL argument");
        return (0);
    } /* if */

    if (!*c_src || !*c_dest) {
        pr_error(stdout, "validate_src_dest: empty string");
        return (0);
    } /* if */

    if (strlen(c_src) >= DOG_PATH_MAX || strlen(c_dest) >= DOG_PATH_MAX) {
        pr_error(stdout, "validate_src_dest: path too long");
        return (0);
    } /* if */

    if (!path_exists(c_src)) {
        pr_error(stdout, "validate_src_dest: source does not exist: %s", c_src);
        return (0);
    } /* if */

    if (!file_regular(c_src)) {
        pr_error(stdout, "validate_src_dest: source not a regular file: %s", c_src);
        return (0);
    } /* if */

    if (path_exists(c_dest) && file_same_file(c_src, c_dest)) {
        pr_error(stdout, "validate_src_dest: source and destination are same file");
        return (0);
    } /* if */

    pbuf[0] = '\0';
    if (ensure_parent_dir(pbuf, sizeof(pbuf), c_dest) != 0) {
        pr_error(stdout, "validate_src_dest: ensure_parent_dir failed");
        return (0);
    } /* if */

    if (stat(pbuf, &st) != 0) {
        pr_error(stdout, "validate_src_dest: stat failed for parent dir");
        return (0);
    } /* if */

    if (!S_ISDIR(st.st_mode)) {
        pr_error(stdout, "validate_src_dest: parent not a directory");
        return (0);
    } /* if */

    valid = 1;
    return valid;
} /* validate_src_dest */

static int
detect_super_mode(void)
{
#ifdef DOG_LINUX
    if (system("sh -c 'sudo echo superuser > /dev/null 2>&1'") == 0) {
        return (1);
    } /* if */

    if (system("sh -c 'run0 echo superuser > /dev/null 2>&1'") == 0) {
        return 2;
    } /* if */
#endif

    return (0);
} /* detect_super_mode */

static int
_run_file_operation(
    const char *operation,
    const char *src,
    const char *dest,
    int super_mode)
{
    int ret = -1;

    if (!src || !dest) {
        return (-1);
    } /* if */

#ifdef DOG_WINDOWS
    char *p = NULL;
    
    char *s_src = strdup(src);
    char *s_dest = strdup(dest);
    
    if (s_src == NULL || s_dest == NULL) {
        if (s_src) free(s_src);
        if (s_dest) free(s_dest);
        return (-1);
    } /* if */

	path_sep_to_posix(s_src);
	pbuf[0] = '\0';

    if (strcmp(operation, "mv") == 0) {
        (void)snprintf(pbuf, sizeof(pbuf),
            "cmd.exe /C move /Y \"%s\" \"%s\"", s_src, s_dest);
    } else {
        (void)snprintf(pbuf, sizeof(pbuf),
            "cmd.exe /C xcopy /Y \"%s\" \"%s\"", s_src, s_dest);
    } /* if */

    ret = _run_windows_command(pbuf);
    if (ret > 0) {
    	if (strcmp(operation, "mv") == 0) {
    		(void)snprintf(pbuf,
				sizeof(pbuf),
				"cmd.exe /C move /Y \"%s\" \"%s\" >nul 2>&1",
				s_src, s_dest);
	    	ret = system(pbuf);
	    } else {
    		(void)snprintf(pbuf,
				sizeof(pbuf),
				"cmd.exe /C xcopy /Y \"%s\" \"%s\" >nul 2>&1",
				s_src, s_dest);
	    	ret = system(pbuf);
	    } /* if */
    } /* if */

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
        ret = _run_command_vfork(argv);
    } else if (super_mode == 1) {
        char *argv[] = {
            "sudo",
            (char *)operation,
            "-f",
            (char *)src,
            (char *)dest,
            NULL
        };
        ret = _run_command_vfork(argv);
    } else if (super_mode == 2) {
        char *argv[] = {
            "run0",
            (char *)operation,
            "-f",
            (char *)src,
            (char *)dest,
            NULL
        };
        ret = _run_command_vfork(argv);
    } /* if */

    return ret;

#endif
} /* _run_file_operation */

int
dog_sef_wmv(const char *c_src, const char *c_dest)
{
    int super_mode = 0;
    int ret = -1;

    if (!validate_src_dest(c_src, c_dest)) {
        return (1);
    } /* if */

#ifdef DOG_ANDROID
	goto super_mode_check_done;
#endif

	if (strfind(c_dest, "/usr/", true) == false) {
		goto super_mode_check_done;
	} /* if */
	
    super_mode = detect_super_mode();

super_mode_check_done:
    ret = _run_file_operation("mv", c_src, c_dest, super_mode);

    if (ret == 0) {
        __set_default_access(c_dest);
		print(DOG_COL_DEFAULT);
		
		if (super_mode == 1) {
        	pr_info(stdout,
				"teleported (with sudo): "
				"'" DOG_COL_YELLOW "%s" DOG_COL_DEFAULT
				"' to '" DOG_COL_YELLOW "%s" DOG_COL_DEFAULT "'", c_src, c_dest);
		} else if (super_mode == 2) {
			pr_info(stdout,
				"teleported (with run0): "
				"'" DOG_COL_YELLOW "%s" DOG_COL_DEFAULT
				"' to '" DOG_COL_YELLOW "%s" DOG_COL_DEFAULT "'", c_src, c_dest);
		} else {
			pr_info(stdout,
				"teleported: "
				"'" DOG_COL_YELLOW "%s" DOG_COL_DEFAULT
				"' to '" DOG_COL_YELLOW "%s" DOG_COL_DEFAULT "'", c_src, c_dest);
		} /* if */
        return (0);
    } /* if */

    pr_error(stdout,
		"failed to move: "
		"'" DOG_COL_YELLOW "%s" DOG_COL_DEFAULT
		"' to '" DOG_COL_YELLOW "%s" DOG_COL_DEFAULT "'", c_src, c_dest);
    return (1);
} /* dog_sef_wmv */

int
dog_sef_wcopy(const char *c_src, const char *c_dest)
{
    int super_mode = 0;
    int ret = -1;

    if (!validate_src_dest(c_src, c_dest)) {
        return (1);
    } /* if */

#ifdef DOG_ANDROID
	goto super_mode_check_done;
#endif

	if (strfind(c_dest, "/usr/", true) == false) {
		goto super_mode_check_done;
	} /* if */
	
    super_mode = detect_super_mode();

super_mode_check_done:
    ret = _run_file_operation("cp", c_src, c_dest, super_mode);

    if (ret == 0) {
        __set_default_access(c_dest);
		
		if (super_mode == 1) {
        	pr_info(stdout,
				"teleported (with sudo): "
				"'" DOG_COL_YELLOW "%s" DOG_COL_DEFAULT
				"' to '" DOG_COL_YELLOW "%s" DOG_COL_DEFAULT "'", c_src, c_dest);
		} else if (super_mode == 2) {
			pr_info(stdout,
				"teleported (with run0): "
				"'" DOG_COL_YELLOW "%s" DOG_COL_DEFAULT
				"' to '" DOG_COL_YELLOW "%s" DOG_COL_DEFAULT "'", c_src, c_dest);
		} else {
			pr_info(stdout,
				"teleported: "
				"'" DOG_COL_YELLOW "%s" DOG_COL_DEFAULT
				"' to '" DOG_COL_YELLOW "%s" DOG_COL_DEFAULT "'", c_src, c_dest);
		} /* if */
        return (0);
    } /* if */

    pr_error(stdout, "failed to copy: '%s' -> '%s'", c_src, c_dest);
    return (1);
} /* dog_sef_wcopy */

static void
dog_check_pc_options(int *compatibility, int *optimized_lt)
{
	FILE	*fpile = NULL;
	int	 found_Z = 0, found_ver = 0;

    if (compatibility == NULL || optimized_lt == NULL) {
        return;
    } /* if */

	if (dir_exists(".watchdogs") == 0) {
		MKDIR(".watchdogs");
    } /* if */

	if (path_access(".watchdogs/pawnc_test.log") == 1) {
		remove(".watchdogs/pawnc_test.log");
    } /* if */

    if (dogconfig.dog_sef_count == 0 || 
        is_binary_file(dogconfig.dog_sef_found_list[0]) == false) {
    	return;
    } /* if */

	pc_configure_libpath();

	#ifdef DOG_WINDOWS
	HANDLE hFile = INVALID_HANDLE_VALUE;
	STARTUPINFO         _STARTUPINFO  = {0};
	PROCESS_INFORMATION _PROCESS_INFO = {0};
	SECURITY_ATTRIBUTES _ATTRIBUTES   = {0};

	_ATTRIBUTES.nLength = sizeof(_ATTRIBUTES);
	_ATTRIBUTES.bInheritHandle = TRUE;

	hFile = CreateFileA(
		".watchdogs\\pawnc_test.log",
		GENERIC_WRITE,
		FILE_SHARE_WRITE,
		&_ATTRIBUTES,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	pbuf[0] = '\0';

	if (hFile != INVALID_HANDLE_VALUE) {
		_STARTUPINFO.cb         = sizeof(_STARTUPINFO);
		_STARTUPINFO.dwFlags    = STARTF_USESTDHANDLES;
		_STARTUPINFO.hStdOutput = hFile;
		_STARTUPINFO.hStdError  = hFile;

		(void)snprintf(pbuf, sizeof(pbuf),
			"\"%s\" -ddd -ddd",
			dogconfig.dog_sef_found_list[0]
		);

		if (CreateProcessA(
			NULL, pbuf, NULL, NULL, TRUE,
			CREATE_NO_WINDOW,  NULL, NULL,
			&_STARTUPINFO,
			&_PROCESS_INFO))
		{
			WaitForSingleObject(_PROCESS_INFO.hProcess, INFINITE);
			CloseHandle(_PROCESS_INFO.hProcess);
			CloseHandle(_PROCESS_INFO.hThread);
		} /* if */

		CloseHandle(hFile);
	} /* if */
	#else
	pid_t pid;
	int fd = -1;
	
	fd = open(".watchdogs/pawnc_test.log",
			O_CREAT | O_WRONLY | O_TRUNC,
			0644);

	if (fd >= 0) {
		pid = fork();
		if (pid == 0) {
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			close(fd);

			char *argv[] = {
				dogconfig.dog_sef_found_list[0], "-dddd", "-dddd",
				NULL
			};

			execv(dogconfig.dog_sef_found_list[0], argv);
			_exit(127);
		} /* if */

		close(fd);
		waitpid(pid, NULL, 0);
	} /* if */
	#endif

	pbuf[0] = '\0';

	fpile = fopen(".watchdogs/pawnc_test.log", "r");
	if (fpile != NULL) {
		while (fgets(pbuf, sizeof(pbuf), fpile) != NULL) {
			if (!found_Z && strfind(pbuf, "-Z", true)) {
				found_Z = 1;
            } /* if */
			if (!found_ver && strfind(pbuf, "3.10.11", true)) {
				found_ver = 1;
            } /* if */
			if (strfind(pbuf, "error while loading shared libraries:", true) ||
				strfind(pbuf, "required file not found", true)) {
				dog_printfile(".watchdogs/pawnc_test.log");
			} /* if */
		} /* while */

		if (found_Z) {
			*compatibility = 1;
        } /* if */
		if (found_ver) {
			*optimized_lt = 1;
        } /* if */

		fclose(fpile);
	} else {
		pr_error(stdout, "Failed to open .watchdogs/pawnc_test.log");
		minimal_debugging();
	} /* if */

	if (path_access(".watchdogs/pawnc_test.log") == 1) {
		remove(".watchdogs/pawnc_test.log");
    } /* if */
} /* dog_check_pc_options */

static int
dog_parse_toml_config(void)
{
	FILE		*fpile = NULL;
	toml_table_t	*dog_toml_parse = NULL;
	toml_table_t	*general_table = NULL;
    int             success = 0;

	fpile = fopen("watchdogs.toml", "r");
	if (!fpile) {
		pr_error(stdout, "Cannot read file %s", "watchdogs.toml");
		minimal_debugging();
		return (0);
	} /* if */

	pbuf[0] = '\0';

	dog_toml_parse = toml_parse_file(fpile, pbuf, sizeof(pbuf));
	fclose(fpile);

	if (!dog_toml_parse) {
		pr_error(stdout, "Parsing TOML: %s", pbuf);
		minimal_debugging();
		return (0);
	} /* if */

	general_table = toml_table_in(dog_toml_parse, TOML_TABLE_GENERAL);
	if (general_table != NULL) {
		toml_datum_t	 os_val = toml_string_in(general_table, "os");

		if (os_val.ok && os_val.u.s[0] != '\0') {
			if (dogconfig.dog_toml_os_type == NULL ||
				strcmp(dogconfig.dog_toml_os_type, os_val.u.s) != 0) {
				if (dogconfig.dog_toml_os_type != NULL) {
					free(dogconfig.dog_toml_os_type);
					dogconfig.dog_toml_os_type = NULL;
				} /* if */
				dogconfig.dog_toml_os_type = strdup(os_val.u.s);
			} /* if */
			dog_free(os_val.u.s);
		} /* if */
	} /* if */

	toml_free(dog_toml_parse);
	success = 1;
	return (success);
} /* dog_parse_toml_config */

static int
dog_find_compiler(const char *dog_os_type)
{
	int		 is_windows = 0;
	const char	*pc_name = NULL;
    int         found = 0;

    if (dog_os_type == NULL) {
        return 0;
    } /* if */

	is_windows = (strcmp(dog_os_type, "windows") == 0);
	pc_name = is_windows ? "pawncc.exe" : "pawncc";

	if (fet_server_env() == false) {
		found = dog_find_path("pawno", pc_name, NULL);
    } else if (fet_server_env() == true) {
		found = dog_find_path("qawno", pc_name, NULL);
    } else {
		found = dog_find_path("pawno", pc_name, NULL);
    } /* if */
    
    return found;
} /* dog_find_compiler */

static bool	samp_server_stat = false;
static void
dog_generate_toml_content(FILE *file, const char *dog_os_type,
    int has_gamemodes, int compatible, int optimized_lt, char *sef_path)
{
	char	*p = NULL;
	int	 is_container = 0;

    if (file == NULL || dog_os_type == NULL || sef_path == NULL) {
        return;
    } /* if */

	if (sef_path[0] != '\0') {
		char	*extension = strrchr(sef_path, '.');

		if (extension != NULL) {
			*extension = '\0';
        } /* if */
	} /* if */

	#ifdef DOG_LINUX
	path_sep_to_posix(sef_path);
	#else
	path_sep_to_win32(sef_path);
	#endif
	
	if (is_running_in_container()) {
		is_container = 1;
    } else if (getenv("WSL_INTEROP") || getenv("WSL_DISTRO_NAME")) {
		is_container = -1;
    } /* if */

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
		} /* if */
	} /* if */

	if (samp_server_stat == true) {
		if (!strcmp(dog_os_type, "windows")) {
			fprintf(file, "   binary = \"%s\" # open.mp binary files\n",
			    "omp-server.exe");
		} else if (!strcmp(dog_os_type, "linux")) {
			fprintf(file, "   binary = \"%s\" # open.mp binary files\n",
			    "omp-server");
		} /* if */
		fprintf(file, "   config = \"%s\" # open.mp config files\n",
		    "config.json");
		fprintf(file, "   logs = \"%s\" # open.mp log files\n",
		    "log.txt");
	} else {
		if (!strcmp(dog_os_type, "windows")) {
			fprintf(file, "   binary = \"%s\" # SA-MP binary files\n",
			    "samp-server.exe");
		} else if (!strcmp(dog_os_type, "linux")) {
			fprintf(file, "   binary = \"%s\" # SA-MP binary files\n",
			    "samp03svr");
		} /* if */
		fprintf(file, "   config = \"%s\" # SA-MP config files\n",
		    "server.cfg");
		fprintf(file, "   logs = \"%s\" # SA-MP log files\n",
		    "server_log.txt");
	} /* if */
    
    fprintf(file, "   webhooks = \"DO_HERE\" # discord webhooks\n");

    fprintf(file, "# @compiler settings\n");
    fprintf(file, "[compiler]\n");

	if (compatible && optimized_lt) {
		if (samp_server_stat == true) {
			fprintf(file,
				"   option = [\"-Z:+\", \"-d:2\", \"-O:2\", \"-;+\", \"-(+\", \"LOCALHOST=1\", 'SERVER=\"Never DM\"'] # compiler options\n");
		} else {
			fprintf(file,
				"   option = [\"-Z:+\", \"-d:2\", \"-O:1\", \"-;+\", \"-(+\", \"LOCALHOST=1\", 'SERVER=\"Never DM\"'] # compiler options\n");
        } /* if */
	} else if (compatible) {
		fprintf(file,
		    "   option = [\"-Z:+\", \"-d:2\", \"-;+\", \"-(+\", \"LOCALHOST=1\", 'SERVER=\"Never DM\"'] # compiler options\n");
	} else {
		fprintf(file,
		    "   option = [\"-d:3\", \"-;+\", \"-(+\", \"LOCALHOST=1\", 'SERVER=\"Never DM\"'] # compiler options\n");
	} /* if */

	fprintf(file, "   includes = [\"gamemodes/\"," \
		"\"pawno/include/\", \"qawno/include/\"] # compiler include path\n");

	if (has_gamemodes && sef_path[0] != '\0') {
		fprintf(file, "   input = \"%s.pwn\" # project input\n",
		    sef_path);
		fprintf(file, "   output = \"%s.amx\" # project output\n",
		    sef_path);
	} else {
		if (path_exists("Doguu/hellonworld.pwn") == 1) {
			fprintf(file,
			    "   input = \"Doguu/hellonworld.pwn\" # project input\n");
			fprintf(file,
			    "   output = \"Doguu/hellonworld.amx\" # project output\n");
		} else {
			fprintf(file,
			    "   input = \"gamemodes/grandlarc.pwn\" # project input\n");
			fprintf(file,
			    "   output = \"gamemodes/grandlarc.amx\" # project output\n");
		} /* if */
	} /* if */

    fprintf(file, "# @dependencies settings\n");
	fprintf(file, "[dependencies]\n");
	fprintf(file, "   github_tokens = \"DO_HERE\" # github tokens\n");
	fprintf(file,
	    "   root_patterns = [\"lib\", \"log\", \"root\", " \
	    "\"amx\", \"static\", \"dynamic\", \"cfg\"] # root pattern\n");
	fprintf(file, "   packages = [\n"
	    "      \"Y-Less/sscanf?newer\",\n"
	    "      \"samp-incognito/samp-streamer-plugin?newer\"\n"
	    "   ] # package list");
	fprintf(file, "\n");
} /* dog_generate_toml_content */

void
pc_configure_libpath(void)
{
	#ifdef DOG_LINUX
	if ((getenv("WSL_INTEROP") || getenv("WSL_DISTRO_NAME")) &&
			strcmp(dogconfig.dog_toml_os_type, OS_SIGNAL_WINDOWS) == 0) {
		return;
    } /* if */

	static const char *paths[] = {
		LINUX_LIB_PATH, LINUX_LIB32_PATH,
		TMUX_LIB_PATH, TMUX_LIB_LOC_PATH,
		TMUX_LIB_ARM64_PATH, TMUX_LIB_ARM32_PATH,
		TMUX_LIB_AMD64_PATH, TMUX_LIB_AMD32_PATH
	};
	static int done = 0;

	char buf[DOG_PATH_MAX * 2] = {0};
	char so[DOG_PATH_MAX] = {0};
	const char *old = NULL;
	size_t len = 0;
	size_t i;
	int n;

	if (done) {
		return;
    } /* if */

	buf[0] = '\0';
	old = getenv("LD_LIBRARY_PATH");

	if (old && *old) {
		len = strlcpy(buf, old, sizeof(buf));
		if (len >= sizeof(buf)) {
			len = sizeof(buf) - 1;
        } /* if */
	} /* if */

	for (i = 0; i < sizeof(paths)/sizeof(paths[0]); i++) {
		n = snprintf(so, sizeof(so), "%s/libpawnc.so", paths[i]);
		if (n < 0 || (size_t)n >= sizeof(so)) {
			continue;
        } /* if */

		if (path_exists(so) == 1) {
			if (len > 0 && len + 1 < sizeof(buf)) {
				buf[len++] = ':';
            } /* if */
			len += strlcpy(buf + len, paths[i],
			    sizeof(buf) - len);
		} /* if */
	} /* for */

	if (len > 0) {
		setenv("LD_LIBRARY_PATH", buf, 1);
		done = 1;
        pr_info(stdout, "pc_configure_libpath: set LD_LIBRARY_PATH to %s", buf);
	} else {
		static bool n = false;
		if (!n) {
			n = !n;
			pr_warning(stdout,
				"libpawnc.so not found in any target path..");
		} /* if */
	} /* if */
	#endif
} /* pc_configure_libpath */

int
dog_configure_toml(void)
{
	int			 find_pawncc = 0, find_gamemodes = 0;
	int			 compatibility = 0, optimized_lt = 0;
	int			 ret = 0;
	int			 toml_array_size = 0;
	int			 fmt_len = 0;
	int			 i;
	const char		*dog_os_type = NULL;
	char			 clp[DOG_PATH_MAX] = {0};
	char			 fmt[DOG_PATH_MAX + 10] = {0};
	char			*expect = NULL;
	char			*buf = NULL;
	char			*new_buf = NULL;
	char			*ptr = NULL;
	char			 appended_flags[300] = {0};
	size_t			 arr_sz = 0;
	size_t			 buf_size = 0;
	size_t			 buf_len = 0;
	FILE			*toml_file = NULL;
	FILE			*fp = NULL;
	toml_table_t		*dog_toml_parse = NULL;
	toml_table_t		*dog_toml_depends = NULL;
	toml_table_t		*dog_toml_compiler = NULL;
	toml_table_t		*general_table = NULL;
	toml_array_t		*dog_toml_root_patterns = NULL;
	toml_datum_t		 toml_gh_tokens, input_val, output_val;
	toml_datum_t		 bin_val, conf_val, logs_val, webhooks_val;
	toml_datum_t		 toml_option_value;
	toml_array_t		*toml_include_path = NULL;
	toml_array_t		*option_arr = NULL;
	toml_datum_t		 _toml_path_val;
	io_compilers		*pctx = &all_pc_field;

	/* initializations */
	pc_debug_options = false;
	if (pc_full_includes != NULL) {
		free(pc_full_includes);
		pc_full_includes = NULL;
	} /* if */

	dog_os_type = dog_procure_os();

	if (dir_exists("qawno") == 1 && dir_exists("components") == 1) {
		samp_server_stat = true;
	} else if (dir_exists("pawno") == 1 && path_access("server.cfg") == 1) {
		samp_server_stat = false;
	} /* if */

	if (path_exists("gamemodes") == 0) {
		ret = MKDIR("gamemodes");
		if (ret == 0) {
			FILE *fp = fopen("gamemodes/.gitkeep", "w");
			if (fp) {
				fclose(fp);
			} /* if */
		} /* if */
	} /* if */

	if (path_exists("npcmodes") == 0) {
		ret = MKDIR("npcmodes");
		if (ret == 0) {
			FILE *fp = fopen("npcmodes/.gitkeep", "w");
			if (fp) {
				fclose(fp);
			} /* if */
		} /* if */
	} /* if */

	if (path_exists("filterscripts") == 0) {
		ret = MKDIR("filterscripts");
		if (ret == 0) {
			FILE *fp = fopen("filterscripts/.gitkeep", "w");
			if (fp) {
				fclose(fp);
			} /* if */
		} /* if */
	} /* if */

	if (path_exists("scriptfiles") == 0) {
		ret = MKDIR("scriptfiles");
		if (ret == 0) {
			FILE *fp = fopen("scriptfiles/.gitkeep", "w");
			if (fp) {
				fclose(fp);
			} /* if */
		} /* if */
	} /* if */

	toml_file = fopen("watchdogs.toml", "r");
	if (toml_file != NULL) {
		fclose(toml_file);
	} else {
		find_pawncc = dog_find_compiler(dog_os_type);
		if (!find_pawncc) {
			if (strcmp(dog_os_type, "windows") == 0) {
				find_pawncc = dog_find_path(".", "pawncc.exe", NULL);
			} else {
				find_pawncc = dog_find_path(".", "pawncc", NULL);
			} /* if */
		} /* if */

		find_gamemodes = dog_find_path("gamemodes/", "*.pwn", NULL);

		if (find_pawncc) {
			dog_check_pc_options(&compatibility, &optimized_lt);
		} /* if */

		toml_file = fopen("watchdogs.toml", "w");
		if (!toml_file) {
			pr_error(stdout, "Failed to create watchdogs.toml");
			minimal_debugging();
			exit(EXIT_FAILURE);
		} /* if */

		if (find_pawncc) {
			dog_generate_toml_content(toml_file, dog_os_type,
			    find_gamemodes, compatibility, optimized_lt,
			    dogconfig.dog_sef_found_list[1]);
		} else {
			dog_generate_toml_content(toml_file, dog_os_type,
			    find_gamemodes, compatibility, optimized_lt,
			    dogconfig.dog_sef_found_list[0]);
		} /* if */

		fclose(toml_file);

		/* print configuration file */
		dog_printfile("watchdogs.toml");
	} /* if */

	if (!dog_parse_toml_config()) {
		pr_error(stdout, "Failed to parse TOML configuration");
		minimal_debugging();
		return (1);
	} /* if */

	pbuf[0] = '\0';

	fp = fopen("watchdogs.toml", "r");
	dog_toml_parse = toml_parse_file(fp, pbuf, sizeof(pbuf));
	if (fp) {
		fclose(fp);
	} /* if */

	if (!dog_toml_parse) {
		pr_error(stdout, "failed to parse the watchdogs.toml...: %s", pbuf);
		minimal_debugging();
		unit_ret_main(NULL);
	} /* if */

	dog_toml_depends = toml_table_in(dog_toml_parse, TOML_TABLE_DEPENDENCIES);

	if (dog_toml_depends != NULL) {
		toml_gh_tokens = toml_string_in(dog_toml_depends, "github_tokens");

		if (toml_gh_tokens.ok) {
			if (dogconfig.dog_toml_github_tokens == NULL ||
			    strcmp(dogconfig.dog_toml_github_tokens, toml_gh_tokens.u.s) != 0) {
				if (dogconfig.dog_toml_github_tokens != NULL) {
					free(dogconfig.dog_toml_github_tokens);
					dogconfig.dog_toml_github_tokens = NULL;
				} /* if */
				dogconfig.dog_toml_github_tokens = strdup(toml_gh_tokens.u.s);
			} /* if */
			dog_free(toml_gh_tokens.u.s);
		} /* if */

		dog_toml_root_patterns = toml_array_in(dog_toml_depends, "root_patterns");

		if (dog_toml_root_patterns != NULL) {
			arr_sz = toml_array_nelem(dog_toml_root_patterns);
			for (i = 0; i < arr_sz; i++) {
				toml_datum_t val = toml_string_at(dog_toml_root_patterns, i);
				if (!val.ok) {
					continue;
				} /* if */

				if (!expect) {
					expect = dog_realloc(NULL, strlen(val.u.s) + 1);
					if (!expect) {
						if (val.u.s)
							free(val.u.s);
						goto clean_up;
					} /* if */
					(void)snprintf(expect, strlen(val.u.s) + 1, "%s", val.u.s);
				} else {
					char *tmp = NULL;
					size_t old_len = strlen(expect);
					size_t new_len = old_len + strlen(val.u.s) + 2;

					tmp = dog_realloc(expect, new_len);
					if (!tmp) {
						if (val.u.s)
							free(val.u.s);
						goto clean_up;
					} /* if */

					expect = tmp;
					(void)snprintf(expect + old_len, new_len - old_len, " %s", val.u.s);
				} /* if */

				if (dogconfig.dog_toml_root_patterns != NULL) {
					free(dogconfig.dog_toml_root_patterns);
					dogconfig.dog_toml_root_patterns = NULL;
				} /* if */

				dogconfig.dog_toml_root_patterns = expect;
				expect = NULL;

				if (val.u.s) {
					free(val.u.s);
					val.u.s = NULL;
				} /* if */

				goto skip_depends;
			} /* for */
		} /* if */
	} /* if */

clean_up:
	if (expect != NULL) {
		free(expect);
		expect = NULL;
	} /* if */

skip_depends:
	dog_toml_compiler = toml_table_in(dog_toml_parse, TOML_TABLE_COMPILER);

	if (dog_toml_compiler != NULL) {
		toml_include_path = toml_array_in(dog_toml_compiler, "includes");

		if (toml_include_path != NULL) {
			toml_array_size = toml_array_nelem(toml_include_path);

			for (i = 0; i < toml_array_size; i++) {
				_toml_path_val = toml_string_at(toml_include_path, i);

				if (!_toml_path_val.ok) {
					continue;
				} /* if */

				dog_strip_dot_fns(clp, sizeof(clp), _toml_path_val.u.s);

				if (clp[0] == '\0') {
					dog_free(_toml_path_val.u.s);
					continue;
				} /* if */

				fmt_len = snprintf(fmt, sizeof(fmt), "-i=\"%s\" ", clp);

				if (buf_len + fmt_len + 1 > buf_size) {
					size_t new_size = buf_size ? buf_size * 2 : 256;
					while (new_size < buf_len + fmt_len + 1) {
						new_size *= 2;
					} /* while */

					new_buf = realloc(buf, new_size);
					if (!new_buf) {
						pr_error(stdout, "Failed to allocate memory");
						minimal_debugging();
						dog_free(_toml_path_val.u.s);
						free(buf);
						goto skip_;
					} /* if */

					buf = new_buf;
					buf_size = new_size;
				} /* if */

				if (buf_len > 0) {
					buf[buf_len] = ' ';
					buf_len++;
				} /* if */

				memcpy(buf + buf_len, fmt, fmt_len);
				buf_len += fmt_len;
				buf[buf_len] = '\0';

				dog_free(_toml_path_val.u.s);
			} /* for */

			pc_full_includes = buf;
		} /* if */

		option_arr = toml_array_in(dog_toml_compiler, "option");

skip_:
		if (option_arr != NULL) {
			expect = NULL;

			toml_array_size = toml_array_nelem(option_arr);

			for (i = 0; i < toml_array_size; i++) {
				toml_option_value = toml_string_at(option_arr, i);

				if (!toml_option_value.ok) {
					continue;
				} /* if */

				if (strfind(toml_option_value.u.s, "-d", true) ||
				    pctx->flag_debug > 0) {
					pc_debug_options = true;
				} /* if */

				size_t old_len = expect ? strlen(expect) : 0;
				size_t new_len = old_len + strlen(toml_option_value.u.s) + 2;

				char *tmp = dog_realloc(expect, new_len);
				if (!tmp) {
					dog_free(toml_option_value.u.s);
					dog_free(expect);
					expect = NULL;
					break;
				} /* if */

				expect = tmp;

				if (!old_len) {
					snprintf(expect, new_len, "%s", toml_option_value.u.s);
				} else {
					snprintf(expect + old_len, new_len - old_len, " %s",
					    toml_option_value.u.s);
				} /* if */

				dog_free(toml_option_value.u.s);
			} /* for */

			if (expect != NULL) {
				if (dogconfig.dog_toml_full_opt != NULL) {
					dog_free(dogconfig.dog_toml_full_opt);
					dogconfig.dog_toml_full_opt = NULL;
				} /* if */
				dogconfig.dog_toml_full_opt = expect;
				expect = NULL;
			} else {
				if (dogconfig.dog_toml_full_opt != NULL) {
					free(dogconfig.dog_toml_full_opt);
					dogconfig.dog_toml_full_opt = NULL;
				} /* if */
				dogconfig.dog_toml_full_opt = strdup("");
				if (!dogconfig.dog_toml_full_opt) {
					pr_error(stdout, "Memory allocation failed");
				} /* if */
			} /* if */
		} /* if */

		input_val = toml_string_in(dog_toml_compiler, "input");
		if (input_val.ok) {
			if (dogconfig.dog_toml_serv_input == NULL ||
			    strcmp(dogconfig.dog_toml_serv_input, input_val.u.s) != 0) {
				if (dogconfig.dog_toml_serv_input != NULL) {
					free(dogconfig.dog_toml_serv_input);
					dogconfig.dog_toml_serv_input = NULL;
				} /* if */
				dogconfig.dog_toml_serv_input = strdup(input_val.u.s);
			} /* if */
			dog_free(input_val.u.s);
		} /* if */

		output_val = toml_string_in(dog_toml_compiler, "output");
		if (output_val.ok) {
			if (dogconfig.dog_toml_serv_output == NULL ||
			    strcmp(dogconfig.dog_toml_serv_output, output_val.u.s) != 0) {
				if (dogconfig.dog_toml_serv_output != NULL) {
					free(dogconfig.dog_toml_serv_output);
					dogconfig.dog_toml_serv_output = NULL;
				} /* if */
				dogconfig.dog_toml_serv_output = strdup(output_val.u.s);
			} /* if */
			dog_free(output_val.u.s);
		} /* if */
	} /* if */

skip_compiler:

	if (dogconfig.dog_toml_packages == NULL ||
	    strcmp(dogconfig.dog_toml_packages, "none none none") != 0) {
		if (dogconfig.dog_toml_packages != NULL) {
			free(dogconfig.dog_toml_packages);
			dogconfig.dog_toml_packages = NULL;
		} /* if */
		dogconfig.dog_toml_packages = strdup("none none none");
	} /* if */

	general_table = toml_table_in(dog_toml_parse, TOML_TABLE_GENERAL);
	if (general_table != NULL) {
		bin_val = toml_string_in(general_table, "binary");
		if (bin_val.ok) {
			if (dogconfig.dog_ptr_samp != NULL) {
				free(dogconfig.dog_ptr_samp);
				dogconfig.dog_ptr_samp = NULL;
			} /* if */

			if (dogconfig.dog_ptr_omp != NULL) {
				free(dogconfig.dog_ptr_omp);
				dogconfig.dog_ptr_omp = NULL;
			} /* if */

			if (samp_server_stat == false) {
				if (dogconfig.dog_is_samp == NULL ||
				    strcmp(dogconfig.dog_is_samp, CRC32_TRUE) != 0) {
					dogconfig.dog_is_samp = CRC32_TRUE;
				} /* if */
				if (dogconfig.dog_ptr_samp == NULL ||
				    strcmp(dogconfig.dog_ptr_samp, bin_val.u.s) != 0) {
					dogconfig.dog_ptr_samp = strdup(bin_val.u.s);
				} /* if */
			} else if (samp_server_stat == true) {
				if (dogconfig.dog_is_omp == NULL ||
				    strcmp(dogconfig.dog_is_omp, CRC32_TRUE) != 0) {
					dogconfig.dog_is_omp = CRC32_TRUE;
				} /* if */
				if (dogconfig.dog_ptr_omp == NULL ||
				    strcmp(dogconfig.dog_ptr_omp, bin_val.u.s) != 0) {
					dogconfig.dog_ptr_omp = strdup(bin_val.u.s);
				} /* if */
			} else {
				if (dogconfig.dog_is_samp == NULL ||
				    strcmp(dogconfig.dog_is_samp, CRC32_TRUE) != 0) {
					dogconfig.dog_is_samp = CRC32_TRUE;
				} /* if */
				if (dogconfig.dog_ptr_samp == NULL ||
				    strcmp(dogconfig.dog_ptr_samp, bin_val.u.s) != 0) {
					dogconfig.dog_ptr_samp = strdup(bin_val.u.s);
				} /* if */
			} /* if */

			if (dogconfig.dog_toml_server_binary == NULL ||
			    strcmp(dogconfig.dog_toml_server_binary, bin_val.u.s) != 0) {
				if (dogconfig.dog_toml_server_binary != NULL) {
					free(dogconfig.dog_toml_server_binary);
					dogconfig.dog_toml_server_binary = NULL;
				} /* if */
				dogconfig.dog_toml_server_binary = strdup(bin_val.u.s);
			} /* if */
			dog_free(bin_val.u.s);
		} /* if */

		conf_val = toml_string_in(general_table, "config");
		if (conf_val.ok) {
			if (dogconfig.dog_toml_server_config == NULL ||
			    strcmp(dogconfig.dog_toml_server_config, conf_val.u.s) != 0) {
				if (dogconfig.dog_toml_server_config != NULL) {
					free(dogconfig.dog_toml_server_config);
					dogconfig.dog_toml_server_config = NULL;
				} /* if */
				dogconfig.dog_toml_server_config = strdup(conf_val.u.s);
			} /* if */
			dog_free(conf_val.u.s);
		} /* if */

		logs_val = toml_string_in(general_table, "logs");
		if (logs_val.ok) {
			if (dogconfig.dog_toml_server_logs == NULL ||
			    strcmp(dogconfig.dog_toml_server_logs, logs_val.u.s) != 0) {
				if (dogconfig.dog_toml_server_logs != NULL) {
					free(dogconfig.dog_toml_server_logs);
					dogconfig.dog_toml_server_logs = NULL;
				} /* if */
				dogconfig.dog_toml_server_logs = strdup(logs_val.u.s);
			} /* if */
			dog_free(logs_val.u.s);
		} /* if */
	} /* if */

	toml_free(dog_toml_parse);

	/* Validate TOML fields and set defaults if needed */
	for (i = 0; i < sizeof(toml_char_field) / sizeof(toml_char_field[0]); i++) {
		char		*field_value = *(toml_pointers[i]);
		const char	*field_name = toml_char_field[i];

		if (field_value == NULL || strcmp(field_value, CRC32_FALSE) == 0) {
			pr_warning(stdout,
			    "toml key null/crc32 false (%s) detected in key: %s * do not set to empty! (fix first).",
			    CRC32_FALSE, field_name);
			printf("   Support: https://github.com/gskeleton/watchdogs/issues\n");
			fflush(stdout);

#ifdef DOG_LINUX
			if (strfind(field_name, "dog_toml_os_type", true) == true) {
				dogconfig.dog_toml_os_type = strdup("linux");
			} /* if */
#else
			if (strfind(field_name, "dog_toml_os_type", true) == true) {
				dogconfig.dog_toml_os_type = strdup("windows");
			} /* if */
#endif

			if (strfind(field_name, "dog_toml_server_binary", true) == true) {
				dogconfig.dog_toml_server_binary = strdup("samp03svr");
			} /* if */

			if (strfind(field_name, "dog_toml_server_config", true) == true) {
				dogconfig.dog_toml_server_config = strdup("server.cfg");
			} /* if */

			if (strfind(field_name, "dog_toml_server_logs", true) == true) {
				dogconfig.dog_toml_server_logs = strdup("server_log.txt");
			} /* if */

			if (strfind(field_name, "dog_toml_full_opt", true) == true) {
				dogconfig.dog_toml_full_opt = strdup("-Z+");
			} /* if */

			if (strfind(field_name, "dog_toml_root_patterns", true) == true) {
				dogconfig.dog_toml_root_patterns = strdup("linux windows");
			} /* if */

			if (strfind(field_name, "dog_toml_packages", true) == true) {
				dogconfig.dog_toml_packages = strdup("Y-Less/sscanf?newer");
			} /* if */

			if (strfind(field_name, "dog_toml_serv_input", true) == true) {
				dogconfig.dog_toml_serv_input = strdup("none.pwn");
			} /* if */

			if (strfind(field_name, "dog_toml_serv_output", true) == true) {
				dogconfig.dog_toml_serv_output = strdup("none.amx");
			} /* if */
		} /* if */
	} /* for */

	_sef_restore();

	if (strcmp(dogconfig.dog_toml_os_type, OS_SIGNAL_WINDOWS) == 0) {
		ptr = "pawncc.exe";
	} else if (strcmp(dogconfig.dog_toml_os_type, OS_SIGNAL_LINUX) == 0) {
		ptr = "pawncc";
	} else {
		ptr = "pawncc";
	} /* if */

	if (dogconfig.dog_pawncc_path == NULL) {
		dogconfig.dog_pawncc_path = strdup("");
	} /* if */

	if (dogconfig.dog_pawncc_path[0] != '\0') {
		return (0);
	} /* if */

	/* Find Pawn compiler in various locations */
	if (dir_exists("pawno") != 0 && dir_exists("qawno") != 0) {
		ret = dog_find_path("pawno", ptr, NULL);
		if (ret) {
			/* found in pawno */
		} else {
			ret = dog_find_path("qawno", ptr, NULL);
			if (ret < 1) {
				ret = dog_find_path(".", ptr, NULL);
			} /* if */
		} /* if */
	} else if (dir_exists("pawno") != 0) {
		ret = dog_find_path("pawno", ptr, NULL);
		if (ret) {
			/* found in pawno */
		} else {
			ret = dog_find_path(".", ptr, NULL);
		} /* if */
	} else if (dir_exists("qawno") != 0) {
		ret = dog_find_path("qawno", ptr, NULL);
		if (ret) {
			/* found in qawno */
		} else {
			ret = dog_find_path(".", ptr, NULL);
		} /* if */
	} else {
		ret = dog_find_path(".", ptr, NULL);
	} /* if */

	if (ret) {
		pbuf[0] = '\0';
		(void)snprintf(pbuf, sizeof(pbuf), "%s",
		    dogconfig.dog_sef_found_list[0]);
		dogconfig.dog_pawncc_path = strdup(pbuf);
		pc_configure_libpath();
	} else {
		pr_info(stdout,
		    "We couldn't find a suitable compiler here; "
		    "installing compiler v3.10.7.");
		installing_pawncc = true;

		if ((getenv("WSL_INTEROP") || getenv("WSL_DISTRO_NAME")) &&
		    strcmp(dogconfig.dog_toml_os_type, OS_SIGNAL_WINDOWS) == 0) {
			dog_download_file(
			    "https://github.com/pawn-lang/compiler/releases/download/v3.10.7/pawnc-3.10.7-windows.zip",
			    "pawncc-windows-37.zip");
			return (0);
		} /* if */

#ifdef DOG_WINDOWS
		dog_download_file(
		    "https://github.com/pawn-lang/compiler/releases/download/v3.10.7/pawnc-3.10.7-windows.zip",
		    "pawncc-windows-37.zip");
		return (0);
#endif

#if defined(DOG_ANDROID)
		{
			struct utsname u;

			if (uname(&u) != 0) {
				perror("uname");
				return 1;
			} /* if */

			if (strcmp(u.machine, "aarch64") == 0) {
				pr_info(stdout, "Downloading PawnCC for aarch64..");
				dog_download_file(
				    "https://github.com/gskeleton/compiler/releases/download/v3.10.7/arm64-v8a.zip",
				    "pawncc-termux-37.zip");
			} else if (strcmp(u.machine, "armv7l") == 0) {
				pr_info(stdout, "Downloading PawnCC for armv7l..");
				dog_download_file(
				    "https://github.com/gskeleton/compiler/releases/download/v3.10.7/armeabi-v7a.zip",
				    "pawncc-termux-37.zip");
			} else {
				pr_info(stdout, "Downloading PawnCC for aarch64..");
				dog_download_file(
				    "https://github.com/gskeleton/compiler/releases/download/v3.10.7/arm64-v8a.zip",
				    "pawncc-termux-37.zip");
			} /* if */
		}
		return (0);
#elif !defined(DOG_ANDROID) && defined(DOG_LINUX)
		dog_download_file(
		    "https://github.com/gskeleton/gcompiler/releases/download/v3.10.7/pawnc-3.10.7-linux.tar.gz",
		    "pawncc-linux-37.tar.gz");
		return (0);
#endif
	} /* if */

	return (0);
} /* dog_configure_toml */