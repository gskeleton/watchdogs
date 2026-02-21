#include  "utils.h"
#include  "crypto.h"
#include  "archive.h"
#include  "replicate.h"
#include  "compiler.h"
#include  "units.h"
#include  "debug.h"
#include  "library.h"
#include  "curl.h"

static char
* pawncc_dir_source = NULL;
static bool
cacert_notice = false;
bool
compiling_gamemode = false;

void
curl_verify_cacert_pem(CURL* curl)
{
	int platform_specific = 0;
#ifdef DOG_ANDROID
	platform_specific = 1;
#elif defined(DOG_LINUX)
	platform_specific = 2;
#elif defined(DOG_WINDOWS)
	platform_specific = 3;
#endif

	if (platform_specific == 3) {
		/* Windows: check local and system paths */
		if (path_access("cacert.pem") != 0)
			curl_easy_setopt(curl, CURLOPT_CAINFO, "cacert.pem");
		else if (access("C:/libdog/cacert.pem", F_OK) == 0)
			curl_easy_setopt(curl, CURLOPT_CAINFO,
				"C:/libdog/cacert.pem");
		else {
			if (cacert_notice != true) {
				pr_color(stdout, DOG_COL_GREEN,
					" * cURL: can't locate cacert.pem - "
					"SSL verification may fail.\n");
				cacert_notice = true;
			}
		}
	}
	else if (platform_specific == 1) {
		/* Android/Termux: check common paths */
		const char* prefix = getenv("PREFIX");
		if (!prefix || prefix[0] == '\0') {
			prefix = "/data/data/com.termux/files/usr";
		}

		char ca1[DOG_PATH_MAX], ca2[DOG_PATH_MAX];

		(void)snprintf(ca1, sizeof(ca1),
			"%s/etc/tls/cert.pem", prefix);
		(void)snprintf(ca2, sizeof(ca2),
			"%s/etc/ssl/certs/ca-certificates.crt", prefix);

		if (access(ca1, F_OK) == 0)
			curl_easy_setopt(curl, CURLOPT_CAINFO, ca1);
		else if (access(ca2, F_OK) == 0)
			curl_easy_setopt(curl, CURLOPT_CAINFO, ca2);
		else {
			pr_color(stdout, DOG_COL_GREEN,
				" * cURL: can't locate cacert.pem - "
				"SSL verification may fail.\n");
		}
	}
	else if (platform_specific == 2) {
		/* Linux: check common system certificate locations */
		if (access("cacert.pem", F_OK) == 0)
			curl_easy_setopt(curl, CURLOPT_CAINFO, "cacert.pem");
		else if (access("/etc/ssl/certs/cacert.pem", F_OK) == 0)
			curl_easy_setopt(curl, CURLOPT_CAINFO,
				"/etc/ssl/certs/cacert.pem");
		else {
			if (cacert_notice != true) {
				pr_color(stdout, DOG_COL_GREEN,
					" * cURL: can't locate cacert.pem - "
					"SSL verification may fail.\n");
				cacert_notice = true;
			}
		}
	}
}

void
buf_init(struct buf* b)
{
	b->data = dog_malloc(DOG_MAX_PATH);
	if (!b->data) {
		unit_ret_main(NULL);
	}
	b->len = 0;
	b->allocated = (b->data) ? DOG_MAX_PATH : 0;
}

void
buf_free(struct buf* b)
{
	if (b->data) {
		dog_free(b->data);
		b->data = NULL;
	}
	b->len = 0;
	b->allocated = 0;
}

size_t
write_callbacks(void* ptr, size_t size, size_t nmemb, void* userdata)
{
	struct buf* b = userdata;

	/* Check alignment */
	if (b->data && ((uintptr_t)b->data & 0x7)) {
		return (0);
	}

	size_t total = size * nmemb;

	if (total > 0xFFFFFFF)
		return (0);

	size_t required = b->len + total + 1;

	/* Reallocate if needed */
	if (required > b->allocated) {
		size_t new_alloc = (b->allocated * 3) >> 1;
		new_alloc = (required > new_alloc) ? required : new_alloc;
		new_alloc = (new_alloc < 0x4000000) ? new_alloc : 0x4000000;

		char* p = realloc(b->data, new_alloc);
		if (!p) {
#if defined(_DBG_PRINT)
			fprintf(stderr,
				" Realloc failed for %zu bytes\n",
				new_alloc);
#endif
			if (b->data) {
				dog_free(b->data);
				b->data = NULL;
				b->allocated = 0;
				b->len = 0;
			}
			return (0);
		}

		b->data = p;
		b->allocated = new_alloc;
	}

	memcpy(b->data + b->len, ptr, total);
	b->len += total;
	b->data[b->len] = 0;

	return (total);
}

void
memory_struct_init(struct memory_struct* mem)
{
	mem->memory = dog_malloc(DOG_MAX_PATH);
	if (!mem->memory) {
		unit_ret_main(NULL);
	}
	mem->size = 0;
	mem->allocated = mem->memory ? DOG_MAX_PATH : 0;
}

void
memory_struct_free(struct memory_struct* mem)
{
	if (mem->memory) {
		free(mem->memory);
		mem->memory = NULL;
	}
	mem->size = 0;
	mem->allocated = 0;
}

size_t
write_memory_callback(void* contents, size_t size, size_t nmemb, void* userp)
{
	struct memory_struct* mem = userp;
	size_t realsize = size * nmemb;

	if (!contents || !mem || realsize > 0x10000000)
		return (0);

	size_t required = mem->size + realsize + 1;

	if (required > mem->allocated) {
		size_t new_alloc = mem->allocated ? (mem->allocated * 2) :
			0x1000;
		if (new_alloc < required)
			new_alloc = required;
		if (new_alloc > 0x8000000)
			new_alloc = 0x8000000;

		char* ptr = realloc(mem->memory, new_alloc);
		if (!ptr) {
#if defined(_DBG_PRINT)
			fprintf(stdout,
				" Memory exhausted at %zu bytes\n", new_alloc);
#endif
			return (0);
		}
		mem->memory = ptr;
		mem->allocated = new_alloc;
	}

	memcpy(mem->memory + mem->size, contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = '\0';

	return (realsize);
}

/* Username variations for social media tracking */
const char* __track_suffixes[] = {
	"!", "@",
	"#", "$",
	"%", "^",
	"_", "-",
	".",
	NULL
};

void
tracker_discrepancy(const char* base,
	char discrepancy[][MAX_USERNAME_LEN],
	int* cnt)
{
	int i, j;
	size_t base_len;
	char temp[MAX_USERNAME_LEN];

	if (!base || !discrepancy || !cnt || *cnt >= MAX_VARIATIONS)
		return;

	base_len = strlen(base);
	if (base_len == 0 || base_len >= MAX_USERNAME_LEN)
		return;

	/* Add original username */
	(void)strlcpy(discrepancy[(*cnt)++], base, MAX_USERNAME_LEN);

	/* Duplicate characters at each position */
	for (i = 0;
		i < (int)base_len &&
		*cnt < MAX_VARIATIONS &&
		base_len + 1 < MAX_USERNAME_LEN;
		i++)
	{
		(void)memcpy(temp, base, (size_t)i);

		temp[i] = base[i];
		temp[i + 1] = base[i];

		(void)strlcpy(temp + i + 2,
			base + i + 1,
			sizeof(temp) - (size_t)(i + 2));

		(void)strlcpy(discrepancy[(*cnt)++], temp, MAX_USERNAME_LEN);
	}

	/* Repeat last character 2-5 times */
	for (i = 2;
		i <= 5 &&
		*cnt < MAX_VARIATIONS;
		i++)
	{
		size_t len = base_len;

		if (len + (size_t)i >= MAX_USERNAME_LEN)
			break;

		(void)memcpy(temp, base, len);

		for (j = 0; j < i; j++)
			temp[len + (size_t)j] = base[base_len - 1];

		temp[len + (size_t)i] = '\0';

		(void)strlcpy(discrepancy[(*cnt)++], temp, MAX_USERNAME_LEN);
	}

	/* Add common suffixes */
	for (i = 0;
		__track_suffixes[i] &&
		*cnt < MAX_VARIATIONS;
		i++)
	{
		(void)snprintf(temp,
			sizeof(temp),
			"%s%s",
			base,
			__track_suffixes[i]);

		(void)strlcpy(discrepancy[(*cnt)++], temp, MAX_USERNAME_LEN);
	}
}

/**
 * Track username across social media platforms
 */
void
tracking_username(CURL* curl, const char* username)
{
	CURLcode res;
	struct memory_struct response;
	struct curl_slist* headers = NULL;

	headers = curl_slist_append(headers, "User-Agent: Mozilla/5.0");

	for (int i = 0; social_site_list[i].site_name != NULL; i++) {
		char url[512];

		(void)snprintf(url, sizeof(url),
			social_site_list[i].url_template,
			username);

		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

		memory_struct_init(&response);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
			write_memory_callback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

		curl_verify_cacert_pem(curl);

		res = curl_easy_perform(curl);

		if (res != CURLE_OK) {
			printf("* [%s] %s -> ERROR %s\n",
				social_site_list[i].site_name,
				url,
				curl_easy_strerror(res));
		}
		else {
			long status;
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE,
				&status);

			if (status == 200 || (status >= 300 && status < 400)) {
				println(stdout, "* [%s] %s -> FOUND (%ld)",
					social_site_list[i].site_name, url,
					status);
			}
			else {
				println(stdout, "* [%s] %s -> NOT FOUND (%ld)",
					social_site_list[i].site_name, url,
					status);
			}
		}

		memory_struct_free(&response);
	}

	curl_slist_free_all(headers);
}

/**
 * Check if URL is accessible (for package verification)
 */
int package_url_checking(const char* url, const char* github_token)
{
	CURL* pkg_curl = curl_easy_init();
	if (!pkg_curl)
		return (0);

	CURLcode res;
	long response_code = 0;
	struct curl_slist* headers = NULL;
	char dog_error_buffer[CURL_ERROR_SIZE] = { 0 };

	fprintf(stdout,
		"\tCreate & Checking URL: %s...\t\t[V]\n", url);

	/* Add GitHub token if available */
	if (strfind(dogconfig.dog_toml_github_tokens, "DO_HERE", true) ||
		dogconfig.dog_toml_github_tokens == NULL ||
		strlen(dogconfig.dog_toml_github_tokens) < 1)
	{
		pr_color(stdout, DOG_COL_GREEN,
			"Can't read Github token.. skipping\n");
	}
	else {
		char auth_header[DOG_PATH_MAX];
		(void)snprintf(auth_header, sizeof(auth_header),
			"Authorization: token %s", github_token);
		headers = curl_slist_append(headers, auth_header);
	}

	headers = curl_slist_append(headers,
		"User-Agent: watchdogs/1.0");
	headers = curl_slist_append(headers,
		"Accept: application/vnd.github.v3+json");
	curl_easy_setopt(pkg_curl,
		CURLOPT_HTTPHEADER, headers);

	curl_easy_setopt(pkg_curl,
		CURLOPT_URL, url);
	curl_easy_setopt(pkg_curl,
		CURLOPT_NOBODY, 1L);  /* HEAD request only */
	curl_easy_setopt(pkg_curl,
		CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(pkg_curl,
		CURLOPT_TIMEOUT, 30L);

	print("   Try Connecting... ");

	res = curl_easy_perform(pkg_curl);
	curl_easy_getinfo(pkg_curl, CURLINFO_RESPONSE_CODE, &response_code);

	curl_easy_setopt(pkg_curl, CURLOPT_ERRORBUFFER, dog_error_buffer);

	curl_verify_cacert_pem(pkg_curl);

	res = curl_easy_perform(pkg_curl);
	curl_easy_getinfo(pkg_curl, CURLINFO_RESPONSE_CODE, &response_code);

	fflush(stdout);

	curl_easy_cleanup(pkg_curl);
	curl_slist_free_all(headers);

	return (response_code >= 200 && response_code < 300);
}

/**
 * Download content from URL to memory buffer
 */
int
package_http_get_content(const char* url, const char* github_token, char** out_html)
{
	CURL* pkg_curl;
	CURLcode res;
	struct curl_slist* headers = NULL;
	struct memory_struct buffer = { 0 };

	pkg_curl = curl_easy_init();
	if (!pkg_curl)
		return (0);

	/* Add authentication if token provided */
	if (github_token && strlen(github_token) > 0 &&
		!strfind(github_token, "DO_HERE", true)) {
		char auth_header[512];
		(void)snprintf(auth_header, sizeof(auth_header),
			"Authorization: token %s", github_token);
		headers = curl_slist_append(headers, auth_header);
	}

	headers = curl_slist_append(headers,
		"User-Agent: watchdogs/1.0");
	curl_easy_setopt(pkg_curl, CURLOPT_HTTPHEADER, headers);

	curl_easy_setopt(pkg_curl, CURLOPT_URL, url);

	memory_struct_init(&buffer);
	curl_easy_setopt(pkg_curl,
		CURLOPT_WRITEFUNCTION, write_memory_callback);
	curl_easy_setopt(pkg_curl,
		CURLOPT_WRITEDATA, (void*)&buffer);
	curl_easy_setopt(pkg_curl,
		CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(pkg_curl,
		CURLOPT_CONNECTTIMEOUT, 15L);
	curl_easy_setopt(pkg_curl, CURLOPT_TIMEOUT, 60L);

	curl_verify_cacert_pem(pkg_curl);

	res = curl_easy_perform(pkg_curl);
	curl_easy_cleanup(pkg_curl);
	curl_slist_free_all(headers);

	if (res != CURLE_OK || buffer.size == 0) {
		memory_struct_free(&buffer);
		return (0);
	}

	*out_html = buffer.memory;

	return (1);
}

/**
 * Find Pawn compiler tools in various locations
 */
static void
find_pc_tools(int* found_pawncc_exe, int* found_pawncc,
	int* found_pawndisasm_exe, int* found_pawndisasm,
	int* found_pawnc_dll, int* found_PAWNC_DLL, int* found_pawnruns, int* found_pawnruns_exe)
{
	const char* ignore_dir = NULL;

	*found_pawncc_exe = dog_find_path(pawncc_dir_source, "pawncc.exe",
		ignore_dir);
	*found_pawncc = dog_find_path(pawncc_dir_source, "pawncc", ignore_dir);
	*found_pawndisasm_exe = dog_find_path(pawncc_dir_source,
		"pawndisasm.exe", ignore_dir);
	*found_pawndisasm = dog_find_path(pawncc_dir_source, "pawndisasm",
		ignore_dir);
	*found_PAWNC_DLL = dog_find_path(pawncc_dir_source, "PAWNC.dll",
		ignore_dir);
	*found_pawnc_dll = dog_find_path(pawncc_dir_source, "pawnc.dll",
		ignore_dir);
	*found_pawnruns = dog_find_path(pawncc_dir_source, "pawnruns",
		ignore_dir);
	*found_pawnruns_exe = dog_find_path(pawncc_dir_source, "pawnruns.exe",
		ignore_dir);

	/* Fallback to current directory */
	if (*found_pawncc_exe < 1 && *found_pawncc < 1) {
		*found_pawncc_exe = dog_find_path(".", "pawncc.exe",
			ignore_dir);
		*found_pawncc = dog_find_path(".", "pawncc", ignore_dir);
		*found_PAWNC_DLL = dog_find_path(".", "PAWNC.dll", ignore_dir);
		*found_pawnc_dll = dog_find_path(".", "pawnc.dll", ignore_dir);
		*found_pawndisasm_exe = dog_find_path(".", "pawndisasm.exe",
			ignore_dir);
		*found_pawndisasm = dog_find_path(".", "pawndisasm", ignore_dir);
	}
	/* Fallback to bin directory */
	if (*found_pawncc_exe < 1 && *found_pawncc < 1) {
		*found_pawncc_exe = dog_find_path("bin/", "pawncc.exe",
			ignore_dir);
		*found_pawncc = dog_find_path("bin/", "pawncc", ignore_dir);
		*found_PAWNC_DLL = dog_find_path("bin/", "PAWNC.dll",
			ignore_dir);
		*found_pawnc_dll = dog_find_path("bin/", "pawnc.dll",
			ignore_dir);
		*found_pawndisasm_exe = dog_find_path("bin/", "pawndisasm.exe",
			ignore_dir);
		*found_pawndisasm = dog_find_path("bin/", "pawndisasm",
			ignore_dir);
	}
}

/**
 * Get Pawn compiler installation directory
 */
static const char*
get_pc_directory(void)
{
	const char* dir_path = NULL;

	if (path_exists("pawno")) {
		dir_path = "pawno";
	}
	else if (path_exists("qawno")) {
		dir_path = "qawno";
	}
	else {
		if (dog_mkdir_recursive("pawno/include") == 0)
			dir_path = "pawno";
	}

	return (dir_path);
}

/**
 * Copy compiler tool to destination
 */
static void
copy_pc_tool(const char* src_path, const char* tool_name,
	const char* dest_dir)
{
	char dest_path[DOG_PATH_MAX];

	(void)snprintf(dest_path, sizeof(dest_path),
		"%s" "%s" "%s", dest_dir, _PATH_STR_SEP_POSIX, tool_name);

	dog_sef_wmv(src_path, dest_path);
}

/**
 * Setup Linux shared library for Pawn compiler
 */
static int setup_linux_library(void)
{
#ifdef DOG_WINDOWS
	return (0);
#endif
	const char* libpawnc_path = NULL;
	char        dest_path[DOG_PATH_MAX];
	char        libpawnc_src[DOG_PATH_MAX];
	char        _hexdump[DOG_PATH_MAX + 28];
	size_t      i;
	int         found_lib;

	/* Common library paths */
	const char* free_usr_path[] = {
	LINUX_LIB_PATH, LINUX_LIB32_PATH, TMUX_LIB_PATH,
	TMUX_LIB_LOC_PATH, TMUX_LIB_ARM64_PATH, TMUX_LIB_ARM32_PATH,
	TMUX_LIB_AMD64_PATH, TMUX_LIB_AMD32_PATH
	};
	size_t s_free_usr_path = sizeof(free_usr_path),
		s_free_usr_path_zero = sizeof(free_usr_path[0]);

	/* Find libpawnc.so */
	found_lib = dog_find_path(pawncc_dir_source, "libpawnc.so", NULL);

	if (found_lib < 1) {
		found_lib = dog_find_path(".", "libpawnc.so", NULL);
		if (found_lib < 1)
			found_lib = dog_find_path("lib/", "libpawnc.so", NULL);
	}

	for (i = 0; i < dogconfig.dog_sef_count; i++) {
		if (strstr(
			dogconfig.dog_sef_found_list[i],
			"libpawnc.so"))
		{
			(void)strncpy(libpawnc_src,
				dogconfig.dog_sef_found_list[i],
				DOG_PATH_MAX);
			break;
		}
	}

	/* Find destination library path */
	for (i = 0; i < s_free_usr_path / s_free_usr_path_zero; i++) {
		if (path_exists(free_usr_path[i])) {
			libpawnc_path = free_usr_path[i];
			break;
		}
	}

	if (!libpawnc_path) {
		return (-1);
	}

	(void)snprintf(dest_path, sizeof(dest_path),
		"%s/libpawnc.so", libpawnc_path);

	if (path_exists(libpawnc_src))
	{
		int na_hexdump = 404;
		na_hexdump = system("sh -c 'hexdump -n 1 watchdogs.toml > /dev/null 2>&1'");
		if (!na_hexdump) {
			print(DOG_COL_DEFAULT);
			pr_info(stdout,
				"Fetching " DOG_COL_YELLOW "%s " DOG_COL_DEFAULT "binary hex..", libpawnc_src);
			(void)snprintf(_hexdump, sizeof(_hexdump),
				"sh -c 'hexdump -C -n 128 %s'", libpawnc_src);
			int not_fail = -2;
			not_fail = system(_hexdump);
		}
	}

	dog_sef_wmv(libpawnc_src, dest_path);

	return (0);
}

/**
 * Apply Pawn compiler installation - copy tools to proper locations
 */
static
void
dog_apply_pawncc(void)
{
	int found_pawncc_exe, found_pawncc;
	int found_pawndisasm_exe, found_pawndisasm;
	int found_pawnc_dll, found_PAWNC_DLL;
	int found_pawnruns, found_pawnruns_exe;

	const char* dest_dir;

	char pawncc_src[DOG_PATH_MAX] = { 0 },
		pawncc_exe_src[DOG_PATH_MAX] = { 0 },
		pawndisasm_src[DOG_PATH_MAX] = { 0 },
		pawndisasm_exe_src[DOG_PATH_MAX] = { 0 },
		pawnc_dll_src[DOG_PATH_MAX] = { 0 },
		PAWNC_DLL_src[DOG_PATH_MAX] = { 0 },
		pawnruns_src[DOG_PATH_MAX] = { 0 },
		pawnruns_exe_src[DOG_PATH_MAX] = { 0 };

	size_t i;

	_sef_restore();

	find_pc_tools(&found_pawncc_exe, &found_pawncc,
		&found_pawndisasm_exe, &found_pawndisasm,
		&found_pawnc_dll, &found_PAWNC_DLL, &found_pawnruns, &found_pawnruns_exe);

	dest_dir = get_pc_directory();
	if (!dest_dir) {
		pr_error(stdout, "Failed to create compiler directory");
		minimal_debugging();
		if (pawncc_dir_source) {
			free(pawncc_dir_source);
			pawncc_dir_source = NULL;
		}
		free(pawncc_dir_source);
		pawncc_dir_source = NULL;
		goto apply_done;
	}

	/* Extract source paths from search results */
	for (i = 0; i < dogconfig.dog_sef_count; i++) {
		const char* item = dogconfig.dog_sef_found_list[i];
		if (!item)
			continue;
		if (strstr(item, "pawncc.exe")) {
			char* size_last_slash = strrchr(item,
				_PATH_CHR_SEP_POSIX);
			if (!size_last_slash)
				size_last_slash = strrchr(item,
					_PATH_CHR_SEP_WIN32);
			if (size_last_slash &&
				strstr(size_last_slash + 1, "pawncc.exe")) {
				(void)strncpy(pawncc_exe_src, item,
					sizeof(pawncc_exe_src));
			}
		}
		if (strstr(item, "pawncc")) {
			char* size_last_slash = strrchr(item,
				_PATH_CHR_SEP_POSIX);
			if (!size_last_slash)
				size_last_slash = strrchr(item,
					_PATH_CHR_SEP_WIN32);
			if (size_last_slash &&
				strstr(size_last_slash + 1, "pawncc")) {
				(void)strncpy(pawncc_src, item, sizeof(pawncc_src));
			}
		}
		if (strstr(item, "pawndisasm.exe")) {
			char* size_last_slash = strrchr(item,
				_PATH_CHR_SEP_POSIX);
			if (!size_last_slash)
				size_last_slash = strrchr(item,
					_PATH_CHR_SEP_WIN32);
			if (size_last_slash &&
				strstr(size_last_slash + 1, "pawndisasm.exe")) {
				(void)strncpy(pawndisasm_exe_src, item,
					sizeof(pawndisasm_exe_src));
			}
		}
		if (strstr(item, "pawndisasm")) {
			char* size_last_slash = strrchr(item,
				_PATH_CHR_SEP_POSIX);
			if (!size_last_slash)
				size_last_slash = strrchr(item,
					_PATH_CHR_SEP_WIN32);
			if (size_last_slash &&
				strstr(size_last_slash + 1, "pawndisasm")) {
				(void)strncpy(pawndisasm_src, item,
					sizeof(pawndisasm_src));
			}
		}
		if (strstr(item, "pawnc.dll")) {
			char* size_last_slash = strrchr(item,
				_PATH_CHR_SEP_POSIX);
			if (!size_last_slash)
				size_last_slash = strrchr(item,
					_PATH_CHR_SEP_WIN32);
			if (size_last_slash &&
				strstr(size_last_slash + 1, "pawnc.dll")) {
				(void)strncpy(pawnc_dll_src, item,
					sizeof(pawnc_dll_src));
			}
		}
		if (strstr(item, "PAWNC.dll")) {
			char* size_last_slash = strrchr(item,
				_PATH_CHR_SEP_POSIX);
			if (!size_last_slash)
				size_last_slash = strrchr(item,
					_PATH_CHR_SEP_WIN32);
			if (size_last_slash &&
				strstr(size_last_slash + 1, "PAWNC.dll")) {
				(void)strncpy(PAWNC_DLL_src, item,
					sizeof(PAWNC_DLL_src));
			}
		}
		if (strstr(item, "pawnruns")) {
			char* size_last_slash = strrchr(item,
				_PATH_CHR_SEP_POSIX);
			if (!size_last_slash)
				size_last_slash = strrchr(item,
					_PATH_CHR_SEP_WIN32);
			if (size_last_slash &&
				strstr(size_last_slash + 1, "pawnruns")) {
				(void)strncpy(pawnruns_src, item,
					sizeof(pawnruns_src));
			}
		}
		if (strstr(item, "pawnruns.exe")) {
			char* size_last_slash = strrchr(item,
				_PATH_CHR_SEP_POSIX);
			if (!size_last_slash)
				size_last_slash = strrchr(item,
					_PATH_CHR_SEP_WIN32);
			if (size_last_slash &&
				strstr(size_last_slash + 1, "pawnruns.exe")) {
				(void)strncpy(pawnruns_exe_src, item,
					sizeof(pawnruns_exe_src));
			}
		}
	}

	/* Copy tools to destination */
	if (found_pawncc_exe && pawncc_exe_src[0])
		copy_pc_tool(pawncc_exe_src, "pawncc.exe", dest_dir);

	if (found_pawncc && pawncc_src[0])
		copy_pc_tool(pawncc_src, "pawncc", dest_dir);

	if (found_pawndisasm_exe && pawndisasm_exe_src[0])
		copy_pc_tool(pawndisasm_exe_src, "pawndisasm.exe",
			dest_dir);

	if (found_pawndisasm && pawndisasm_src[0])
		copy_pc_tool(pawndisasm_src, "pawndisasm", dest_dir);

	if (found_PAWNC_DLL && PAWNC_DLL_src[0])
		copy_pc_tool(PAWNC_DLL_src, "PAWNC.dll", dest_dir);

	if (found_pawnc_dll && pawnc_dll_src[0])
		copy_pc_tool(pawnc_dll_src, "pawnc.dll", dest_dir);

	if (found_pawnruns && pawnruns_src[0])
		copy_pc_tool(pawnruns_src, "pawnruns", dest_dir);

	if (found_pawnruns_exe && pawnruns_exe_src[0])
		copy_pc_tool(pawnruns_exe_src, "pawnruns.exe", dest_dir);

	/* Setup Linux library if needed */
	if (installing_pawncc_linux)
		setup_linux_library();
	installing_pawncc_linux = false;

	/* Clean up temporary source directory */
#ifdef DOG_WINDOWS
	DWORD attr = GetFileAttributesA(pawncc_dir_source);
	if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
		SHFILEOPSTRUCTA op;
		char path[DOG_PATH_MAX];

		ZeroMemory(&op, sizeof(op));
		(void)snprintf(path, sizeof(path), "%s%c%c", pawncc_dir_source, '\0', '\0');

		op.wFunc = FO_DELETE;
		op.pFrom = path;
		op.fFlags = FOF_NO_UI | FOF_SILENT | FOF_NOCONFIRMATION;
		SHFileOperationA(&op);
	}
#else
	struct stat st;
	if (lstat(pawncc_dir_source, &st) == 0 && S_ISDIR(st.st_mode)) {
		pid_t pid = fork();
		if (pid == 0) {
			execlp("rm", "rm", "-rf", pawncc_dir_source, NULL);
			_exit(127);
		}
		waitpid(pid, NULL, 0);
	}
#endif

	/* Normalize DLL names */
	if (path_exists("pawno/pawnc.dll") == 1)
		rename("pawno/pawnc.dll", "pawno/PAWNC.dll");

	if (path_exists("qawno/pawnc.dll") == 1)
		rename("qawno/pawnc.dll", "qawno/PAWNC.dll");

	pr_info(stdout, "Congratulations! - Done.");

	if (pawncc_dir_source) {
		if (dir_exists(pawncc_dir_source))
			destroy_arch_dir(pawncc_dir_source);
		free(pawncc_dir_source);
		pawncc_dir_source = NULL;
	}

	compiling_gamemode = true;

apply_done:
	unit_ret_main(NULL);
}

/**
 * Debug callback for CURL verbose output
 */
static int
debug_callback(CURL* handle __UNUSED__, curl_infotype type,
	char* data, size_t size, void* userptr __UNUSED__)
{
	switch (type) {
	case CURLINFO_TEXT:
	case CURLINFO_HEADER_OUT:
	case CURLINFO_DATA_OUT:
	case CURLINFO_SSL_DATA_OUT:
		break;
	case CURLINFO_HEADER_IN:
		if (!data || (int)size < 1)
			break;
		if (strfind(data, "content-security-policy: ", true))
			break;
		printf("<= Recv header: %.*s", (int)size, data);
		fflush(stdout);
		break;
	case CURLINFO_DATA_IN:
	case CURLINFO_SSL_DATA_IN:
	default:
		break;
	}
	return (0);
}

/**
 * Sanitize filename by replacing invalid characters
 */
static void
parsing_filename(char* filename)
{
	if (filename[0] == '\0')
		return;

	/* Replace invalid characters with underscore */
	for (char* p = filename; *p; ++p) {
		if (*p == '?' || *p == '*' ||
			*p == '<' || *p == '>' ||
			*p == '|' || *p == ':' ||
			*p == '"' || *p == _PATH_CHR_SEP_WIN32 ||
			*p == _PATH_CHR_SEP_POSIX) {
			*p = '_';
		}
	}

	/* Trim trailing whitespace */
	char* end = filename + strlen(filename) - 1;
	while (end > filename && isspace((unsigned char)*end)) {
		*end-- = '\0';
	}

	if (strlen(filename) == 0) {
		(void)strcpy(filename, "downloaded_file");
	}
}

/**
 * Download file from URL with retry logic
 */
int
dog_download_file(const char* url, const char* output_filename)
{
	minimal_debugging();

	if (!url || !output_filename) {
		pr_color(stdout, DOG_COL_RED,
			"Error: Invalid URL or filename\n");
		return (-1);
	}
	CURLcode	res;
	CURL* curl = NULL;
	long		response_code = 0;
	int		retry_count = 0;
	struct stat	file_stat;

	char	filename_noquery[DOG_PATH_MAX];
	char	curl_url_finalname[DOG_PATH_MAX];
	char* q, * p;

	/* Remove query string from filename */
	if ((q = strchr(output_filename, '?')) != NULL) {
		size_t l = q - output_filename;
		if (l >= sizeof(filename_noquery))
			l = sizeof(filename_noquery) - 1;
		(void)memcpy(filename_noquery,
			output_filename,
			l);
		filename_noquery[l] = '\0';
	}
	else {
		(void)strlcpy(filename_noquery,
			output_filename,
			sizeof(filename_noquery));
	}

	/* Extract filename from URL if needed */
	if (strstr(filename_noquery, "://") != NULL) {
		if ((p = strrchr(url, _PATH_CHR_SEP_POSIX)) == NULL) {
			(void)strlcpy(curl_url_finalname, "downloaded_file",
				sizeof(curl_url_finalname));
		}
		else {
			p++;

			if ((q = strchr(p, '?')) != NULL)
				*q = '\0';

			(void)strlcpy(curl_url_finalname, p,
				sizeof(curl_url_finalname));
		}
	}
	else {
		(void)strlcpy(curl_url_finalname, filename_noquery,
			sizeof(curl_url_finalname));
	}

	parsing_filename(curl_url_finalname);

	pr_color(stdout, DOG_COL_GREEN, "* Try Downloading %s", curl_url_finalname);

	/* Retry loop */
	while (retry_count < 5) {
		curl = curl_easy_init();
		if (!curl) {
			pr_color(stdout, DOG_COL_RED,
				"Failed to initialize CURL\n");
			return (-1);
		}

		struct curl_slist* headers = NULL;

		/* Add GitHub token for authenticated requests */
		if (installing_package) {
			if (!dogconfig.dog_toml_github_tokens ||
				strfind(dogconfig.dog_toml_github_tokens,
					"DO_HERE", true) ||
				strlen(dogconfig.dog_toml_github_tokens) < 1) {
				pr_color(stdout, DOG_COL_YELLOW,
					" ~ GitHub token not available\n");
			}
			else {
				char auth_header[512];
				(void)snprintf(auth_header, sizeof(auth_header),
					"Authorization: token %s",
					dogconfig.dog_toml_github_tokens);
				headers = curl_slist_append(headers,
					auth_header);
				char* tokens = dog_masked_text(8,
					dogconfig.dog_toml_github_tokens);
				pr_color(stdout, DOG_COL_GREEN,
					" ~ Using GitHub token: %s\n",
					tokens);
				free(tokens);
			}
		}

		headers = curl_slist_append(headers,
			"User-Agent: watchdogs/1.0");
		headers = curl_slist_append(headers,
			"Accept: application/vnd.github.v3.raw");

		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
			write_memory_callback);

		struct buf download_buffer;
		buf_init(&download_buffer);

		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &download_buffer);

		curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip");
		curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
		curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);

		curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, NULL);
		curl_easy_setopt(curl, CURLOPT_XFERINFODATA, NULL);

		static bool rate_create_debugging = false;

		/* Enable verbose debugging if requested */
		if (rate_create_debugging) {
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
			curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION,
				debug_callback);
			curl_easy_setopt(curl, CURLOPT_DEBUGDATA, NULL);
		}

		curl_verify_cacert_pem(curl);

		fflush(stdout);

		res = curl_easy_perform(curl);
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

		curl_easy_cleanup(curl);
		curl_slist_free_all(headers);

		/* Check if download was successful */
		if (res == CURLE_OK &&
			response_code == 200 &&
			download_buffer.len > 0) {
			FILE* fp = fopen(curl_url_finalname, "wb");
			if (!fp) {
				pr_color(stdout, DOG_COL_RED,
					"* Failed to open file for writing: %s "
					"(errno: %d - %s)\n",
					curl_url_finalname, errno, strerror(errno));
				dog_free(download_buffer.data);
				++retry_count;
				continue;
			}

			size_t written = fwrite(download_buffer.data, 1,
				download_buffer.len, fp);
			fclose(fp);

			if (written != download_buffer.len) {
				pr_color(stdout, DOG_COL_RED,
					"* Failed to write all data to file: %s "
					"(written: %zu, expected: %zu)\n",
					curl_url_finalname, written,
					download_buffer.len);
				dog_free(download_buffer.data);
				unlink(curl_url_finalname);
				++retry_count;
				continue;
			}

			buf_free(&download_buffer);

			/* Verify file was written successfully */
			if (stat(curl_url_finalname, &file_stat) == 0 &&
				file_stat.st_size > 0)
			{
				char size_filename[DOG_PATH_MAX];
				(void)snprintf(size_filename, sizeof(size_filename),
					"%s", curl_url_finalname);

				/* Remove extension for extraction directory */
				char* ext = NULL;
				if ((ext = strstr(size_filename,
					".tar.gz")) != NULL) {
					*ext = '\0';
				} else if ((ext = strstr(size_filename,
					".tar")) != NULL) {
					*ext = '\0';
				} else if ((ext = strstr(size_filename,
					".zip")) != NULL) {
					*ext = '\0';
				}

				/* Extract archive if needed */
				dog_extract_archive(curl_url_finalname,
					size_filename);

				/* Cleanup based on installation type */
				if (installing_package) {
					if (path_exists(
						curl_url_finalname) == 1) {
						destroy_arch_dir(curl_url_finalname);
					}
				}
				else {
					if (installing_pawncc) {
						if (path_exists(
							curl_url_finalname) == 1) {
							destroy_arch_dir(
								curl_url_finalname);
						}
						pawncc_dir_source = strdup(
							size_filename);
						dog_apply_pawncc();
						installing_pawncc = false;
					}
				}

				return (0);
			}
		}
		else {
			buf_free(&download_buffer);
		}

		pr_color(stdout, DOG_COL_YELLOW,
			" Attempt %d/5 failed (HTTP: %ld). Retrying in 3s...\n",
			retry_count + 1, response_code);
		++retry_count;
	}

	pr_color(stdout, DOG_COL_RED,
		" Failed to download %s from %s after %d retries\n",
		curl_url_finalname, url, retry_count);

	return (1);
}