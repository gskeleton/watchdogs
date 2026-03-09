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
	
	/* Validate input parameter */
	if (curl == NULL) {
		pr_error(stdout, "curl_verify_cacert_pem: curl handle is NULL");
		return;
	} /* if */
	
	/* Determine platform */
#ifdef DOG_ANDROID
	platform_specific = 1;
#elif defined(DOG_LINUX)
	platform_specific = 2;
#elif defined(DOG_WINDOWS)
	platform_specific = 3;
#else
	platform_specific = 0;
#endif

	/* Handle based on platform */
	if (platform_specific == 3) {
		/* Windows: check local and system paths */
		if (path_access("cacert.pem") != 0) {
			curl_easy_setopt(curl, CURLOPT_CAINFO, "cacert.pem");
		} else if (access("C:/libdog/cacert.pem", F_OK) == 0) {
			curl_easy_setopt(curl, CURLOPT_CAINFO,
				"C:/libdog/cacert.pem");
		} else {
			if (cacert_notice != true) {
				pr_color(stdout, DOG_COL_GREEN,
					" * cURL: can't locate cacert.pem - "
					"SSL verification may fail.\n");
				cacert_notice = true;
			} /* if */
		} /* if */
	}
	else if (platform_specific == 1) {
		/* Android/Termux: check common paths */
		const char* prefix = getenv("PREFIX");
		char ca1[DOG_PATH_MAX] = {0};
		char ca2[DOG_PATH_MAX] = {0};
		
		if (!prefix || prefix[0] == '\0') {
			prefix = "/data/data/com.termux/files/usr";
		} /* if */

		(void)snprintf(ca1, sizeof(ca1),
			"%s/etc/tls/cert.pem", prefix);
		(void)snprintf(ca2, sizeof(ca2),
			"%s/etc/ssl/certs/ca-certificates.crt", prefix);

		if (access(ca1, F_OK) == 0) {
			curl_easy_setopt(curl, CURLOPT_CAINFO, ca1);
		} else if (access(ca2, F_OK) == 0) {
			curl_easy_setopt(curl, CURLOPT_CAINFO, ca2);
		} else {
			pr_color(stdout, DOG_COL_GREEN,
				" * cURL: can't locate cacert.pem - "
				"SSL verification may fail.\n");
		} /* if */
	}
	else if (platform_specific == 2) {
		/* Linux: check common system certificate locations */
		if (access("cacert.pem", F_OK) == 0) {
			curl_easy_setopt(curl, CURLOPT_CAINFO, "cacert.pem");
		} else if (access("/etc/ssl/certs/cacert.pem", F_OK) == 0) {
			curl_easy_setopt(curl, CURLOPT_CAINFO,
				"/etc/ssl/certs/cacert.pem");
		} else {
			if (cacert_notice != true) {
				pr_color(stdout, DOG_COL_GREEN,
					" * cURL: can't locate cacert.pem - "
					"SSL verification may fail.\n");
				cacert_notice = true;
			} /* if */
		} /* if */
	} else {
		pr_warning(stdout, "curl_verify_cacert_pem: unknown platform %d", platform_specific);
	} /* if */
} /* curl_verify_cacert_pem */

void
buf_init(struct buf* b)
{
	/* Validate input parameter */
	if (b == NULL) {
		pr_error(stdout, "buf_init: buffer structure is NULL");
		unit_ret_main(NULL);
		return;
	} /* if */
	
	b->data = dog_malloc(DOG_MAX_PATH);
	if (!b->data) {
		pr_error(stdout, "buf_init: memory allocation failed for %d bytes", DOG_MAX_PATH);
		unit_ret_main(NULL);
		b->allocated = 0;
		return;
	} /* if */
	
	b->len = 0;
	b->allocated = DOG_MAX_PATH;
} /* buf_init */

void
buf_free(struct buf* b)
{
	/* Validate input parameter */
	if (b == NULL) {
		pr_error(stdout, "buf_free: buffer structure is NULL");
		return;
	} /* if */
	
	if (b->data) {
		dog_free(b->data);
		b->data = NULL;
	} /* if */
	
	b->len = 0;
	b->allocated = 0;
} /* buf_free */

size_t
write_callbacks(void* ptr, size_t size, size_t nmemb, void* userdata)
{
	struct buf* b = (struct buf*)userdata;
	size_t total = size * nmemb;
	size_t required;
	size_t new_alloc;
	char* p;
	
	/* Validate input parameters */
	if (ptr == NULL) {
		pr_error(stdout, "write_callbacks: data pointer is NULL");
		return (0);
	} /* if */
	
	if (userdata == NULL) {
		pr_error(stdout, "write_callbacks: userdata is NULL");
		return (0);
	} /* if */
	
	if (size == 0 || nmemb == 0) {
		pr_info(stdout, "write_callbacks: zero size or nmemb");
		return (0);
	} /* if */

	/* Check alignment */
	if (b->data && ((uintptr_t)b->data & 0x7)) {
		pr_error(stdout, "write_callbacks: misaligned buffer (%p)", b->data);
		return (0);
	} /* if */

	total = size * nmemb;

	/* Prevent excessive allocation */
	if (total > 0xFFFFFFF) {
		pr_error(stdout, "write_callbacks: total size %zu too large", total);
		return (0);
	} /* if */

	required = b->len + total + 1;

	/* Reallocate if needed */
	if (required > b->allocated) {
		new_alloc = (b->allocated * 3) >> 1;
		new_alloc = (required > new_alloc) ? required : new_alloc;
		new_alloc = (new_alloc < 0x4000000) ? new_alloc : 0x4000000;

		p = realloc(b->data, new_alloc);
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
			} /* if */
			return (0);
		} /* if */

		b->data = p;
		b->allocated = new_alloc;
	} /* if */

	memcpy(b->data + b->len, ptr, total);
	b->len += total;
	b->data[b->len] = 0;

	return (total);
} /* write_callbacks */

void
memory_struct_init(struct memory_struct* mem)
{
	/* Validate input parameter */
	if (mem == NULL) {
		pr_error(stdout, "memory_struct_init: memory structure is NULL");
		unit_ret_main(NULL);
		return;
	} /* if */
	
	mem->memory = dog_malloc(DOG_MAX_PATH);
	if (!mem->memory) {
		pr_error(stdout, "memory_struct_init: memory allocation failed for %d bytes", DOG_MAX_PATH);
		unit_ret_main(NULL);
		mem->allocated = 0;
		return;
	} /* if */
	
	mem->size = 0;
	mem->allocated = DOG_MAX_PATH;
} /* memory_struct_init */

void
memory_struct_free(struct memory_struct* mem)
{
	/* Validate input parameter */
	if (mem == NULL) {
		pr_error(stdout, "memory_struct_free: memory structure is NULL");
		return;
	} /* if */
	
	if (mem->memory) {
		free(mem->memory);
		mem->memory = NULL;
	} /* if */
	
	mem->size = 0;
	mem->allocated = 0;
} /* memory_struct_free */

size_t
write_memory_callback(void* contents, size_t size, size_t nmemb, void* userp)
{
	struct memory_struct* mem = (struct memory_struct*)userp;
	size_t realsize = size * nmemb;
	size_t required;
	size_t new_alloc;
	char* ptr;
	
	/* Validate input parameters */
	if (contents == NULL) {
		pr_error(stdout, "write_memory_callback: contents is NULL");
		return (0);
	} /* if */
	
	if (userp == NULL) {
		pr_error(stdout, "write_memory_callback: userp is NULL");
		return (0);
	} /* if */
	
	if (size == 0 || nmemb == 0) {
		pr_info(stdout, "write_memory_callback: zero size or nmemb");
		return (0);
	} /* if */

	realsize = size * nmemb;

	/* Prevent excessive allocation */
	if (!contents || !mem || realsize > 0x10000000) {
		pr_error(stdout, "write_memory_callback: invalid parameters or size %zu too large", realsize);
		return (0);
	} /* if */

	required = mem->size + realsize + 1;

	if (required > mem->allocated) {
		new_alloc = mem->allocated ? (mem->allocated * 2) : 0x1000;
		if (new_alloc < required)
			new_alloc = required;
		if (new_alloc > 0x8000000)
			new_alloc = 0x8000000;

		ptr = realloc(mem->memory, new_alloc);
		if (!ptr) {
#if defined(_DBG_PRINT)
			fprintf(stdout,
				" Memory exhausted at %zu bytes\n", new_alloc);
#endif
			return (0);
		} /* if */
		
		mem->memory = ptr;
		mem->allocated = new_alloc;
	} /* if */

	memcpy(mem->memory + mem->size, contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = '\0';

	return (realsize);
} /* write_memory_callback */

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
	char temp[MAX_USERNAME_LEN] = {0};

	/* Validate input parameters */
	if (!base) {
		pr_error(stdout, "tracker_discrepancy: base username is NULL");
		return;
	} /* if */
	
	if (!discrepancy) {
		pr_error(stdout, "tracker_discrepancy: discrepancy array is NULL");
		return;
	} /* if */
	
	if (!cnt) {
		pr_error(stdout, "tracker_discrepancy: count pointer is NULL");
		return;
	} /* if */
	
	if (*cnt >= MAX_VARIATIONS) {
		pr_warning(stdout, "tracker_discrepancy: count %d already at maximum", *cnt);
		return;
	} /* if */

	base_len = strlen(base);
	if (base_len == 0) {
		pr_warning(stdout, "tracker_discrepancy: base username is empty");
		return;
	} /* if */
	
	if (base_len >= MAX_USERNAME_LEN) {
		pr_warning(stdout, "tracker_discrepancy: base username too long (%zu)", base_len);
		return;
	} /* if */

	pr_info(stdout, "tracker_discrepancy: generating variations for '%s'", base);

	/* Add original username */
	(void)strlcpy(discrepancy[(*cnt)++], base, MAX_USERNAME_LEN);
	pr_info(stdout, "tracker_discrepancy: added original: %s", base);

	/* Duplicate characters at each position */
	for (i = 0;
		i < (int)base_len &&
		*cnt < MAX_VARIATIONS &&
		base_len + 1 < MAX_USERNAME_LEN;
		i++)
	{
		/* Reset temp buffer */
		memset(temp, 0, sizeof(temp));
		
		/* Copy up to current position */
		(void)memcpy(temp, base, (size_t)i);

		/* Duplicate character at position i */
		temp[i] = base[i];
		temp[i + 1] = base[i];

		/* Copy remaining characters */
		(void)strlcpy(temp + i + 2,
			base + i + 1,
			sizeof(temp) - (size_t)(i + 2));

		/* Add to discrepancy list */
		(void)strlcpy(discrepancy[(*cnt)++], temp, MAX_USERNAME_LEN);
		pr_info(stdout, "tracker_discrepancy: added duplicate at %d: %s", i, temp);
	} /* for */

	/* Repeat last character 2-5 times */
	for (i = 2;
		i <= 5 &&
		*cnt < MAX_VARIATIONS;
		i++)
	{
		size_t len = base_len;

		if (len + (size_t)i >= MAX_USERNAME_LEN) {
			pr_info(stdout, "tracker_discrepancy: would exceed buffer, stopping repeats");
			break;
		} /* if */

		/* Reset temp buffer */
		memset(temp, 0, sizeof(temp));
		
		/* Copy base */
		(void)memcpy(temp, base, len);

		/* Repeat last character i times */
		for (j = 0; j < i; j++) {
			temp[len + (size_t)j] = base[base_len - 1];
		} /* for */

		temp[len + (size_t)i] = '\0';

		/* Add to discrepancy list */
		(void)strlcpy(discrepancy[(*cnt)++], temp, MAX_USERNAME_LEN);
		pr_info(stdout, "tracker_discrepancy: added repeat %d times: %s", i, temp);
	} /* for */

	/* Add common suffixes */
	for (i = 0;
		__track_suffixes[i] &&
		*cnt < MAX_VARIATIONS;
		i++)
	{
		/* Reset temp buffer */
		memset(temp, 0, sizeof(temp));
		
		(void)snprintf(temp,
			sizeof(temp),
			"%s%s",
			base,
			__track_suffixes[i]);

		(void)strlcpy(discrepancy[(*cnt)++], temp, MAX_USERNAME_LEN);
		pr_info(stdout, "tracker_discrepancy: added suffix %s: %s", __track_suffixes[i], temp);
	} /* for */
	
	pr_info(stdout, "tracker_discrepancy: generated %d variations", *cnt);
} /* tracker_discrepancy */

/**
 * Track username across social media platforms
 */
void
tracking_username(CURL* curl, const char* username)
{
	CURLcode res = CURLE_REMOTE_ACCESS_DENIED;
	struct memory_struct response;
	struct curl_slist* headers = NULL;
	int success_count = 0;
	int fail_count = 0;
	
	/* Validate input parameters */
	if (curl == NULL) {
		pr_error(stdout, "tracking_username: curl handle is NULL");
		return;
	} /* if */
	
	if (username == NULL) {
		pr_error(stdout, "tracking_username: username is NULL");
		return;
	} /* if */
	
	if (strlen(username) == 0) {
		pr_error(stdout, "tracking_username: username is empty");
		return;
	} /* if */

	pr_info(stdout, "tracking_username: tracking username '%s' across platforms", username);

	headers = curl_slist_append(headers, "User-Agent: Mozilla/5.0");

	/* Iterate through social media sites */
	for (int i = 0; social_site_list[i].site_name != NULL; i++) {
		char url[512] = {0};

		(void)snprintf(url, sizeof(url),
			social_site_list[i].url_template,
			username);

		pr_info(stdout, "tracking_username: checking %s at %s", 
		         social_site_list[i].site_name, url);

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
			fail_count++;
		} else {
			long status = 0;
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE,
				&status);

			if (status == 200 || (status >= 300 && status < 400)) {
				println(stdout, "* [%s] %s -> FOUND (%ld)",
					social_site_list[i].site_name, url,
					status);
				success_count++;
			} else {
				println(stdout, "* [%s] %s -> NOT FOUND (%ld)",
					social_site_list[i].site_name, url,
					status);
				fail_count++;
			} /* if */
		} /* if */

		memory_struct_free(&response);
	} /* for */

	curl_slist_free_all(headers);
	
	pr_info(stdout, "tracking_username: completed - %d found, %d not found", 
	         success_count, fail_count);
} /* tracking_username */

/**
 * Check if URL is accessible (for package verification)
 */
int package_url_checking(const char* url, const char* github_token)
{
	CURL* pkg_curl = NULL;
	CURLcode res;
	long response_code = 0;
	struct curl_slist* headers = NULL;
	char dog_error_buffer[CURL_ERROR_SIZE] = { 0 };
	int ret = 0;
	
	/* Validate input parameters */
	if (url == NULL) {
		pr_error(stdout, "package_url_checking: url is NULL");
		return (0);
	} /* if */
	
	pr_info(stdout, "package_url_checking: checking URL: %s", url);

	pkg_curl = curl_easy_init();
	if (!pkg_curl) {
		pr_error(stdout, "package_url_checking: failed to initialize CURL");
		return (0);
	} /* if */

	fprintf(stdout,
		"\tCreate & Checking URL: %s...\t\t[V]\n", url);

	/* Add GitHub token if available */
	if (strfind(dogconfig.dog_toml_github_tokens, "DO_HERE", true) ||
		dogconfig.dog_toml_github_tokens == NULL ||
		strlen(dogconfig.dog_toml_github_tokens) < 1)
	{
		pr_color(stdout, DOG_COL_GREEN,
			"Can't read Github token.. skipping\n");
	} else {
		char auth_header[DOG_PATH_MAX] = {0};
		(void)snprintf(auth_header, sizeof(auth_header),
			"Authorization: token %s", github_token);
		headers = curl_slist_append(headers, auth_header);
		pr_info(stdout, "package_url_checking: added GitHub token");
	} /* if */

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

	ret = (response_code >= 200 && response_code < 300) ? 1 : 0;
	
	pr_info(stdout, "package_url_checking: response code %ld, ret=%d", response_code, ret);
	return (ret);
} /* package_url_checking */

/**
 * Download content from URL to memory buffer
 */
int
package_http_get_content(const char* url, const char* github_token, char** out_html)
{
	CURL* pkg_curl = NULL;
	CURLcode res;
	struct curl_slist* headers = NULL;
	struct memory_struct buffer = { 0 };
	int ret = 0;
	
	/* Validate input parameters */
	if (url == NULL) {
		pr_error(stdout, "package_http_get_content: url is NULL");
		return (0);
	} /* if */
	
	if (out_html == NULL) {
		pr_error(stdout, "package_http_get_content: out_html is NULL");
		return (0);
	} /* if */
	
	pr_info(stdout, "package_http_get_content: fetching URL: %s", url);

	pkg_curl = curl_easy_init();
	if (!pkg_curl) {
		pr_error(stdout, "package_http_get_content: failed to initialize CURL");
		return (0);
	} /* if */

	/* Add authentication if token provided */
	if (github_token && strlen(github_token) > 0 &&
		!strfind(github_token, "DO_HERE", true)) {
		char auth_header[512] = {0};
		(void)snprintf(auth_header, sizeof(auth_header),
			"Authorization: token %s", github_token);
		headers = curl_slist_append(headers, auth_header);
		pr_info(stdout, "package_http_get_content: added GitHub token");
	} /* if */

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
	
	if (res != CURLE_OK) {
		pr_error(stdout, "package_http_get_content: CURL error: %s", 
		         curl_easy_strerror(res));
	} /* if */
	
	curl_easy_cleanup(pkg_curl);
	curl_slist_free_all(headers);

	if (res != CURLE_OK || buffer.size == 0) {
		pr_warning(stdout, "package_http_get_content: failed to get content (size=%zu)", buffer.size);
		memory_struct_free(&buffer);
		return (0);
	} /* if */

	*out_html = buffer.memory;
	ret = 1;
	
	pr_info(stdout, "package_http_get_content: successfully fetched %zu bytes", buffer.size);
	return (ret);
} /* package_http_get_content */

/**
 * Find Pawn compiler tools in various locations
 */
static void
find_pc_tools(int* found_pawncc_exe, int* found_pawncc,
	int* found_pawndisasm_exe, int* found_pawndisasm,
	int* found_pawnc_dll, int* found_PAWNC_DLL, int* found_pawnruns, int* found_pawnruns_exe)
{
	const char* ignore_dir = NULL;
	int search_count = 0;
	
	/* Validate output pointers */
	if (!found_pawncc_exe || !found_pawncc || !found_pawndisasm_exe || !found_pawndisasm ||
	    !found_pawnc_dll || !found_PAWNC_DLL || !found_pawnruns || !found_pawnruns_exe) {
		pr_error(stdout, "find_pc_tools: one or more output pointers are NULL");
		return;
	} /* if */
	
	pr_info(stdout, "find_pc_tools: searching for Pawn compiler tools in %s", 
	         pawncc_dir_source ? pawncc_dir_source : "(null)");

	/* Search in source directory */
	*found_pawncc_exe = dog_find_path(pawncc_dir_source, "pawncc.exe", ignore_dir);
	*found_pawncc = dog_find_path(pawncc_dir_source, "pawncc", ignore_dir);
	*found_pawndisasm_exe = dog_find_path(pawncc_dir_source, "pawndisasm.exe", ignore_dir);
	*found_pawndisasm = dog_find_path(pawncc_dir_source, "pawndisasm", ignore_dir);
	*found_PAWNC_DLL = dog_find_path(pawncc_dir_source, "PAWNC.dll", ignore_dir);
	*found_pawnc_dll = dog_find_path(pawncc_dir_source, "pawnc.dll", ignore_dir);
	*found_pawnruns = dog_find_path(pawncc_dir_source, "pawnruns", ignore_dir);
	*found_pawnruns_exe = dog_find_path(pawncc_dir_source, "pawnruns.exe", ignore_dir);
	
	search_count++;

	/* Fallback to current directory if not found */
	if (*found_pawncc_exe < 1 && *found_pawncc < 1) {
		pr_info(stdout, "find_pc_tools: trying current directory");
		
		*found_pawncc_exe = dog_find_path(".", "pawncc.exe", ignore_dir);
		*found_pawncc = dog_find_path(".", "pawncc", ignore_dir);
		*found_PAWNC_DLL = dog_find_path(".", "PAWNC.dll", ignore_dir);
		*found_pawnc_dll = dog_find_path(".", "pawnc.dll", ignore_dir);
		*found_pawndisasm_exe = dog_find_path(".", "pawndisasm.exe", ignore_dir);
		*found_pawndisasm = dog_find_path(".", "pawndisasm", ignore_dir);
		
		search_count++;
	} /* if */
	
	/* Fallback to bin directory if not found */
	if (*found_pawncc_exe < 1 && *found_pawncc < 1) {
		pr_info(stdout, "find_pc_tools: trying bin directory");
		
		*found_pawncc_exe = dog_find_path("bin/", "pawncc.exe", ignore_dir);
		*found_pawncc = dog_find_path("bin/", "pawncc", ignore_dir);
		*found_PAWNC_DLL = dog_find_path("bin/", "PAWNC.dll", ignore_dir);
		*found_pawnc_dll = dog_find_path("bin/", "pawnc.dll", ignore_dir);
		*found_pawndisasm_exe = dog_find_path("bin/", "pawndisasm.exe", ignore_dir);
		*found_pawndisasm = dog_find_path("bin/", "pawndisasm", ignore_dir);
		
		search_count++;
	} /* if */

	pr_info(stdout, "find_pc_tools: search complete (%d locations searched)", search_count);
	pr_info(stdout, "find_pc_tools: found - pawncc:%d, pawncc.exe:%d, pawndisasm:%d, pawndisasm.exe:%d", 
	         *found_pawncc, *found_pawncc_exe, *found_pawndisasm, *found_pawndisasm_exe);
} /* find_pc_tools */

/**
 * Get Pawn compiler installation directory
 */
static const char*
get_pc_directory(void)
{
	const char* dir_path = NULL;

	pr_info(stdout, "get_pc_directory: looking for compiler directory");

	if (path_exists("pawno")) {
		dir_path = "pawno";
		pr_info(stdout, "get_pc_directory: found pawno directory");
	}
	else if (path_exists("qawno")) {
		dir_path = "qawno";
		pr_info(stdout, "get_pc_directory: found qawno directory");
	}
	else {
		pr_info(stdout, "get_pc_directory: no existing directory, creating pawno/include");
		if (dog_mkdir_recursive("pawno/include") == 0) {
			dir_path = "pawno";
			pr_info(stdout, "get_pc_directory: created pawno directory");
		} else {
			pr_error(stdout, "get_pc_directory: failed to create pawno/include");
		} /* if */
	} /* if */

	return (dir_path);
} /* get_pc_directory */

/**
 * Copy compiler tool to destination
 */
static void
copy_pc_tool(const char* src_path, const char* tool_name,
	const char* dest_dir)
{
	char dest_path[DOG_PATH_MAX] = {0};
	
	/* Validate input parameters */
	if (src_path == NULL) {
		pr_error(stdout, "copy_pc_tool: src_path is NULL");
		return;
	} /* if */
	
	if (tool_name == NULL) {
		pr_error(stdout, "copy_pc_tool: tool_name is NULL");
		return;
	} /* if */
	
	if (dest_dir == NULL) {
		pr_error(stdout, "copy_pc_tool: dest_dir is NULL");
		return;
	} /* if */
	
	if (strlen(src_path) == 0) {
		pr_warning(stdout, "copy_pc_tool: src_path is empty");
		return;
	} /* if */
	
	pr_info(stdout, "copy_pc_tool: copying %s to %s directory", tool_name, dest_dir);

	(void)snprintf(dest_path, sizeof(dest_path),
		"%s" "%s" "%s", dest_dir, _PATH_STR_SEP_POSIX, tool_name);

	dog_sef_wmv(src_path, dest_path);
	
	pr_info(stdout, "copy_pc_tool: copied %s -> %s", src_path, dest_path);
} /* copy_pc_tool */

/**
 * Setup Linux shared library for Pawn compiler
 */
static int setup_linux_library(void)
{
#ifdef DOG_WINDOWS
	pr_info(stdout, "setup_linux_library: skipping on Windows");
	return (0);
#endif

	const char* libpawnc_path = NULL;
	char        dest_path[DOG_PATH_MAX] = {0};
	char        libpawnc_src[DOG_PATH_MAX] = {0};
	char        _hexdump[DOG_PATH_MAX + 28] = {0};
	size_t      i;
	int         found_lib = 0;
	int         na_hexdump = 404;

	/* Common library paths */
	const char* free_usr_path[] = {
	LINUX_LIB_PATH, LINUX_LIB32_PATH, TMUX_LIB_PATH,
	TMUX_LIB_LOC_PATH, TMUX_LIB_ARM64_PATH, TMUX_LIB_ARM32_PATH,
	TMUX_LIB_AMD64_PATH, TMUX_LIB_AMD32_PATH
	};
	size_t s_free_usr_path = sizeof(free_usr_path);
	size_t s_free_usr_path_zero = sizeof(free_usr_path[0]);

	/* Find libpawnc.so */
	found_lib = dog_find_path(pawncc_dir_source, "libpawnc.so", NULL);

	if (found_lib < 1) {
		found_lib = dog_find_path(".", "libpawnc.so", NULL);
		if (found_lib < 1) {
			found_lib = dog_find_path("lib/", "libpawnc.so", NULL);
		} /* if */
	} /* if */

	/* Search through SEF list for libpawnc.so */
	for (i = 0; i < dogconfig.dog_sef_count; i++) {
		if (dogconfig.dog_sef_found_list[i] != NULL &&
		    strstr(dogconfig.dog_sef_found_list[i], "libpawnc.so"))
		{
			(void)strncpy(libpawnc_src,
				dogconfig.dog_sef_found_list[i],
				DOG_PATH_MAX - 1);
			libpawnc_src[DOG_PATH_MAX - 1] = '\0';
			break;
		} /* if */
	} /* for */

	/* Find destination library path */
	for (i = 0; i < s_free_usr_path / s_free_usr_path_zero; i++) {
		if (path_exists(free_usr_path[i])) {
			libpawnc_path = free_usr_path[i];
			pr_info(stdout, "setup_linux_library: using library path: %s", libpawnc_path);
			break;
		} /* if */
	} /* for */

	if (!libpawnc_path) {
		pr_error(stdout, "setup_linux_library: no suitable library path found");
		return (-1);
	} /* if */

	(void)snprintf(dest_path, sizeof(dest_path),
		"%s/libpawnc.so", libpawnc_path);

	/* Check if source exists */
	if (path_exists(libpawnc_src) == 1)
	{
		na_hexdump = system("sh -c 'hexdump -n 1 watchdogs.toml > /dev/null 2>&1'");
		if (!na_hexdump) {
			print(DOG_COL_DEFAULT);
			pr_info(stdout,
				"Fetching " DOG_COL_YELLOW "%s " DOG_COL_DEFAULT "binary hex..", libpawnc_src);
			(void)snprintf(_hexdump, sizeof(_hexdump),
				"sh -c 'hexdump -C -n 128 %s'", libpawnc_src);
			if (system(_hexdump) == -1) {
				perror("system");
			}
		} /* if */
		
		dog_sef_wmv(libpawnc_src, dest_path);
		pr_info(stdout, "setup_linux_library: copied %s -> %s", libpawnc_src, dest_path);
	} else {
		pr_warning(stdout, "setup_linux_library: source library %s not found", libpawnc_src);
	} /* if */

	return (0);
} /* setup_linux_library */

/**
 * Apply Pawn compiler installation - copy tools to proper locations
 */
static
void
dog_apply_pawncc(void)
{
	int found_pawncc_exe = 0, found_pawncc = 0;
	int found_pawndisasm_exe = 0, found_pawndisasm = 0;
	int found_pawnc_dll = 0, found_PAWNC_DLL = 0;
	int found_pawnruns = 0, found_pawnruns_exe = 0;

	const char* dest_dir = NULL;

	char pawncc_src[DOG_PATH_MAX] = { 0 },
		pawncc_exe_src[DOG_PATH_MAX] = { 0 },
		pawndisasm_src[DOG_PATH_MAX] = { 0 },
		pawndisasm_exe_src[DOG_PATH_MAX] = { 0 },
		pawnc_dll_src[DOG_PATH_MAX] = { 0 },
		PAWNC_DLL_src[DOG_PATH_MAX] = { 0 },
		pawnruns_src[DOG_PATH_MAX] = { 0 },
		pawnruns_exe_src[DOG_PATH_MAX] = { 0 };

	size_t i;
	int copy_count = 0;

	pr_info(stdout, "dog_apply_pawncc: starting Pawn compiler installation");

	_sef_restore();

	/* Find all compiler tools */
	find_pc_tools(&found_pawncc_exe, &found_pawncc,
		&found_pawndisasm_exe, &found_pawndisasm,
		&found_pawnc_dll, &found_PAWNC_DLL, &found_pawnruns, &found_pawnruns_exe);

	/* Get destination directory */
	dest_dir = get_pc_directory();
	if (!dest_dir) {
		pr_error(stdout, "Failed to create compiler directory");
		minimal_debugging();
		if (pawncc_dir_source) {
			free(pawncc_dir_source);
			pawncc_dir_source = NULL;
		} /* if */
		free(pawncc_dir_source);
		pawncc_dir_source = NULL;
		goto apply_done;
	} /* if */
	
	pr_info(stdout, "dog_apply_pawncc: destination directory: %s", dest_dir);

	/* Extract source paths from search results */
	for (i = 0; i < dogconfig.dog_sef_count; i++) {
		const char* item = dogconfig.dog_sef_found_list[i];
		char* size_last_slash = NULL;
		
		if (!item) {
			continue;
		} /* if */
		
		/* Check for pawncc.exe */
		if (strstr(item, "pawncc.exe")) {
			size_last_slash = strrchr(item, _PATH_CHR_SEP_POSIX);
			if (!size_last_slash)
				size_last_slash = strrchr(item, _PATH_CHR_SEP_WIN32);
			if (size_last_slash &&
				strstr(size_last_slash + 1, "pawncc.exe")) {
				(void)strncpy(pawncc_exe_src, item,
					sizeof(pawncc_exe_src) - 1);
				pawncc_exe_src[sizeof(pawncc_exe_src) - 1] = '\0';
				pr_info(stdout, "dog_apply_pawncc: found pawncc.exe at %s", item);
			} /* if */
		} /* if */
		
		/* Check for pawncc */
		if (strstr(item, "pawncc") && !strstr(item, "pawncc.exe")) {
			size_last_slash = strrchr(item, _PATH_CHR_SEP_POSIX);
			if (!size_last_slash)
				size_last_slash = strrchr(item, _PATH_CHR_SEP_WIN32);
			if (size_last_slash &&
				strstr(size_last_slash + 1, "pawncc")) {
				(void)strncpy(pawncc_src, item, sizeof(pawncc_src) - 1);
				pawncc_src[sizeof(pawncc_src) - 1] = '\0';
				pr_info(stdout, "dog_apply_pawncc: found pawncc at %s", item);
			} /* if */
		} /* if */
		
		/* Check for pawndisasm.exe */
		if (strstr(item, "pawndisasm.exe")) {
			size_last_slash = strrchr(item, _PATH_CHR_SEP_POSIX);
			if (!size_last_slash)
				size_last_slash = strrchr(item, _PATH_CHR_SEP_WIN32);
			if (size_last_slash &&
				strstr(size_last_slash + 1, "pawndisasm.exe")) {
				(void)strncpy(pawndisasm_exe_src, item,
					sizeof(pawndisasm_exe_src) - 1);
				pawndisasm_exe_src[sizeof(pawndisasm_exe_src) - 1] = '\0';
				pr_info(stdout, "dog_apply_pawncc: found pawndisasm.exe at %s", item);
			} /* if */
		} /* if */
		
		/* Check for pawndisasm */
		if (strstr(item, "pawndisasm") && !strstr(item, "pawndisasm.exe")) {
			size_last_slash = strrchr(item, _PATH_CHR_SEP_POSIX);
			if (!size_last_slash)
				size_last_slash = strrchr(item, _PATH_CHR_SEP_WIN32);
			if (size_last_slash &&
				strstr(size_last_slash + 1, "pawndisasm")) {
				(void)strncpy(pawndisasm_src, item,
					sizeof(pawndisasm_src) - 1);
				pawndisasm_src[sizeof(pawndisasm_src) - 1] = '\0';
				pr_info(stdout, "dog_apply_pawncc: found pawndisasm at %s", item);
			} /* if */
		} /* if */
		
		/* Check for pawnc.dll */
		if (strstr(item, "pawnc.dll")) {
			size_last_slash = strrchr(item, _PATH_CHR_SEP_POSIX);
			if (!size_last_slash)
				size_last_slash = strrchr(item, _PATH_CHR_SEP_WIN32);
			if (size_last_slash &&
				strstr(size_last_slash + 1, "pawnc.dll")) {
				(void)strncpy(pawnc_dll_src, item,
					sizeof(pawnc_dll_src) - 1);
				pawnc_dll_src[sizeof(pawnc_dll_src) - 1] = '\0';
				pr_info(stdout, "dog_apply_pawncc: found pawnc.dll at %s", item);
			} /* if */
		} /* if */
		
		/* Check for PAWNC.dll */
		if (strstr(item, "PAWNC.dll")) {
			size_last_slash = strrchr(item, _PATH_CHR_SEP_POSIX);
			if (!size_last_slash)
				size_last_slash = strrchr(item, _PATH_CHR_SEP_WIN32);
			if (size_last_slash &&
				strstr(size_last_slash + 1, "PAWNC.dll")) {
				(void)strncpy(PAWNC_DLL_src, item,
					sizeof(PAWNC_DLL_src) - 1);
				PAWNC_DLL_src[sizeof(PAWNC_DLL_src) - 1] = '\0';
				pr_info(stdout, "dog_apply_pawncc: found PAWNC.dll at %s", item);
			} /* if */
		} /* if */
		
		/* Check for pawnruns */
		if (strstr(item, "pawnruns") && !strstr(item, "pawnruns.exe")) {
			size_last_slash = strrchr(item, _PATH_CHR_SEP_POSIX);
			if (!size_last_slash)
				size_last_slash = strrchr(item, _PATH_CHR_SEP_WIN32);
			if (size_last_slash &&
				strstr(size_last_slash + 1, "pawnruns")) {
				(void)strncpy(pawnruns_src, item,
					sizeof(pawnruns_src) - 1);
				pawnruns_src[sizeof(pawnruns_src) - 1] = '\0';
				pr_info(stdout, "dog_apply_pawncc: found pawnruns at %s", item);
			} /* if */
		} /* if */
		
		/* Check for pawnruns.exe */
		if (strstr(item, "pawnruns.exe")) {
			size_last_slash = strrchr(item, _PATH_CHR_SEP_POSIX);
			if (!size_last_slash)
				size_last_slash = strrchr(item, _PATH_CHR_SEP_WIN32);
			if (size_last_slash &&
				strstr(size_last_slash + 1, "pawnruns.exe")) {
				(void)strncpy(pawnruns_exe_src, item,
					sizeof(pawnruns_exe_src) - 1);
				pawnruns_exe_src[sizeof(pawnruns_exe_src) - 1] = '\0';
				pr_info(stdout, "dog_apply_pawncc: found pawnruns.exe at %s", item);
			} /* if */
		} /* if */
	} /* for */

	/* Copy tools to destination */
	if (found_pawncc_exe && pawncc_exe_src[0]) {
		copy_pc_tool(pawncc_exe_src, "pawncc.exe", dest_dir);
		copy_count++;
	} /* if */

	if (found_pawncc && pawncc_src[0]) {
		copy_pc_tool(pawncc_src, "pawncc", dest_dir);
		copy_count++;
	} /* if */

	if (found_pawndisasm_exe && pawndisasm_exe_src[0]) {
		copy_pc_tool(pawndisasm_exe_src, "pawndisasm.exe", dest_dir);
		copy_count++;
	} /* if */

	if (found_pawndisasm && pawndisasm_src[0]) {
		copy_pc_tool(pawndisasm_src, "pawndisasm", dest_dir);
		copy_count++;
	} /* if */

	if (found_PAWNC_DLL && PAWNC_DLL_src[0]) {
		copy_pc_tool(PAWNC_DLL_src, "PAWNC.dll", dest_dir);
		copy_count++;
	} /* if */

	if (found_pawnc_dll && pawnc_dll_src[0]) {
		copy_pc_tool(pawnc_dll_src, "pawnc.dll", dest_dir);
		copy_count++;
	} /* if */

	if (found_pawnruns && pawnruns_src[0]) {
		copy_pc_tool(pawnruns_src, "pawnruns", dest_dir);
		copy_count++;
	} /* if */

	if (found_pawnruns_exe && pawnruns_exe_src[0]) {
		copy_pc_tool(pawnruns_exe_src, "pawnruns.exe", dest_dir);
		copy_count++;
	} /* if */

	pr_info(stdout, "dog_apply_pawncc: copied %d tools", copy_count);

	/* Setup Linux library if needed */
	if (installing_pawncc_linux) {
		setup_linux_library();
	} /* if */
	installing_pawncc_linux = false;

	/* Clean up temporary source directory */
#ifdef DOG_WINDOWS
	DWORD attr = GetFileAttributesA(pawncc_dir_source);
	if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
		SHFILEOPSTRUCTA op;
		char path[DOG_PATH_MAX] = {0};

		ZeroMemory(&op, sizeof(op));
		(void)snprintf(path, sizeof(path), "%s%c%c", pawncc_dir_source, '\0', '\0');

		op.wFunc = FO_DELETE;
		op.pFrom = path;
		op.fFlags = FOF_NO_UI | FOF_SILENT | FOF_NOCONFIRMATION;
		SHFileOperationA(&op);
		pr_info(stdout, "dog_apply_pawncc: cleaned up Windows directory");
	} /* if */
#else
	struct stat st;
	if (lstat(pawncc_dir_source, &st) == 0 && S_ISDIR(st.st_mode)) {
		pid_t pid = fork();
		if (pid == 0) {
			execlp("rm", "rm", "-rf", pawncc_dir_source, NULL);
			_exit(127);
		} else if (pid > 0) {
			waitpid(pid, NULL, 0);
			pr_info(stdout, "dog_apply_pawncc: cleaned up Unix directory");
		} else {
			pr_warning(stdout, "dog_apply_pawncc: fork failed: %s", strerror(errno));
		} /* if */
	} /* if */
#endif

	/* Normalize DLL names */
	if (path_exists("pawno/pawnc.dll") == 1) {
		rename("pawno/pawnc.dll", "pawno/PAWNC.dll");
		pr_info(stdout, "dog_apply_pawncc: renamed pawno/pawnc.dll to PAWNC.dll");
	} /* if */

	if (path_exists("qawno/pawnc.dll") == 1) {
		rename("qawno/pawnc.dll", "qawno/PAWNC.dll");
		pr_info(stdout, "dog_apply_pawncc: renamed qawno/pawnc.dll to PAWNC.dll");
	} /* if */

	pr_info(stdout, "Congratulations! - Done.");

	if (pawncc_dir_source) {
		if (dir_exists(pawncc_dir_source)) {
			destroy_arch_dir(pawncc_dir_source);
		} /* if */
		free(pawncc_dir_source);
		pawncc_dir_source = NULL;
	} /* if */

	compiling_gamemode = true;

apply_done:
	unit_ret_main(NULL);
} /* dog_apply_pawncc */

/**
 * Debug callback for CURL verbose output
 */
static int
debug_callback(CURL* handle __UNUSED__, curl_infotype type,
	char* data, size_t size, void* userptr __UNUSED__)
{
	/* Validate input parameters */
	if (data == NULL && size > 0) {
		pr_error(stdout, "debug_callback: data is NULL with size %zu", size);
		return (0);
	} /* if */
	
	/* Handle different info types */
	switch (type) {
	case CURLINFO_TEXT:
	case CURLINFO_HEADER_OUT:
	case CURLINFO_DATA_OUT:
	case CURLINFO_SSL_DATA_OUT:
		/* Ignore these types */
		break;
		
	case CURLINFO_HEADER_IN:
		if (!data || (int)size < 1) {
			break;
		} /* if */
		
		/* Skip security policy headers */
		if (strfind(data, "content-security-policy: ", true)) {
			break;
		} /* if */
		
		printf("<= Recv header: %.*s", (int)size, data);
		fflush(stdout);
		break;
		
	case CURLINFO_DATA_IN:
	case CURLINFO_SSL_DATA_IN:
		/* Ignore data content */
		break;
		
	default:
		pr_info(stdout, "debug_callback: unknown type %d", type);
		break;
	} /* switch */
	
	return (0);
} /* debug_callback */

/**
 * Sanitize filename by replacing invalid characters
 */
static void
parsing_filename(char* filename)
{
	char* end;
	
	/* Validate input */
	if (filename == NULL) {
		pr_error(stdout, "parsing_filename: filename is NULL");
		return;
	} /* if */
	
	if (filename[0] == '\0') {
		pr_info(stdout, "parsing_filename: empty filename");
		return;
	} /* if */

	pr_info(stdout, "parsing_filename: sanitizing '%s'", filename);

	/* Replace invalid characters with underscore */
	for (char* p = filename; *p; ++p) {
		if (*p == '?' || *p == '*' ||
			*p == '<' || *p == '>' ||
			*p == '|' || *p == ':' ||
			*p == '"' || *p == _PATH_CHR_SEP_WIN32 ||
			*p == _PATH_CHR_SEP_POSIX) {
			*p = '_';
		} /* if */
	} /* for */

	/* Trim trailing whitespace */
	end = filename + strlen(filename) - 1;
	while (end > filename && isspace((unsigned char)*end)) {
		*end-- = '\0';
	} /* while */

	/* Ensure filename is not empty */
	if (strlen(filename) == 0) {
		(void)strcpy(filename, "downloaded_file");
		pr_info(stdout, "parsing_filename: filename was empty, using default");
	} /* if */
	
	pr_info(stdout, "parsing_filename: result '%s'", filename);
} /* parsing_filename */

/**
 * Download file from URL with retry logic
 */
int
dog_download_file(const char* url, const char* output_filename)
{
	CURLcode	res;
	CURL* curl = NULL;
	long		response_code = 0;
	int		retry_count = 0;
	int		max_retries = 5;
	struct stat	file_stat;

	char	filename_noquery[DOG_PATH_MAX] = {0};
	char	curl_url_finalname[DOG_PATH_MAX] = {0};
	char* q = NULL;
	char* p = NULL;
	
	/* Validate input parameters */
	if (!url) {
		pr_error(stdout, "dog_download_file: URL is NULL");
		return (-1);
	} /* if */
	
	if (!output_filename) {
		pr_error(stdout, "dog_download_file: output_filename is NULL");
		return (-1);
	} /* if */
	
	if (strlen(url) == 0) {
		pr_error(stdout, "dog_download_file: URL is empty");
		return (-1);
	} /* if */
	
	pr_info(stdout, "dog_download_file: downloading %s to %s", url, output_filename);

	minimal_debugging();

	/* Remove query string from filename */
	if ((q = strchr(output_filename, '?')) != NULL) {
		size_t l = q - output_filename;
		if (l >= sizeof(filename_noquery)) {
			l = sizeof(filename_noquery) - 1;
		} /* if */
		(void)memcpy(filename_noquery, output_filename, l);
		filename_noquery[l] = '\0';
		pr_info(stdout, "dog_download_file: removed query string, base: %s", filename_noquery);
	} else {
		(void)strlcpy(filename_noquery,
			output_filename,
			sizeof(filename_noquery));
	} /* if */

	/* Extract filename from URL if needed */
	if (strstr(filename_noquery, "://") != NULL) {
		if ((p = strrchr(url, _PATH_CHR_SEP_POSIX)) == NULL) {
			(void)strlcpy(curl_url_finalname, "downloaded_file",
				sizeof(curl_url_finalname));
			pr_info(stdout, "dog_download_file: using default filename");
		} else {
			p++;

			if ((q = strchr(p, '?')) != NULL) {
				*q = '\0';
			} /* if */

			(void)strlcpy(curl_url_finalname, p,
				sizeof(curl_url_finalname));
			pr_info(stdout, "dog_download_file: extracted filename: %s", curl_url_finalname);
		} /* if */
	} else {
		(void)strlcpy(curl_url_finalname, filename_noquery,
			sizeof(curl_url_finalname));
	} /* if */

	parsing_filename(curl_url_finalname);

	pr_color(stdout, DOG_COL_GREEN, "* Try Downloading %s", curl_url_finalname);

	/* Retry loop */
	while (retry_count < max_retries) {
		struct curl_slist* headers = NULL;
		struct buf download_buffer;
		
		pr_info(stdout, "dog_download_file: attempt %d/%d", retry_count + 1, max_retries);
		
		curl = curl_easy_init();
		if (!curl) {
			pr_color(stdout, DOG_COL_RED,
				"Failed to initialize CURL\n");
			return (-1);
		} /* if */

		/* Add GitHub token for authenticated requests */
		if (installing_package) {
			if (!dogconfig.dog_toml_github_tokens ||
				strfind(dogconfig.dog_toml_github_tokens,
					"DO_HERE", true) ||
				strlen(dogconfig.dog_toml_github_tokens) < 1) {
				pr_color(stdout, DOG_COL_YELLOW,
					" ~ GitHub token not available\n");
			} else {
				char auth_header[512] = {0};
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
			} /* if */
		} /* if */

		headers = curl_slist_append(headers,
			"User-Agent: watchdogs/1.0");
		headers = curl_slist_append(headers,
			"Accept: application/vnd.github.v3.raw");

		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
			write_memory_callback);

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
		} /* if */

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
			} /* if */

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
			} /* if */

			buf_free(&download_buffer);

			/* Verify file was written successfully */
			if (stat(curl_url_finalname, &file_stat) == 0 &&
				file_stat.st_size > 0)
			{
				char size_filename[DOG_PATH_MAX] = {0};
				(void)snprintf(size_filename, sizeof(size_filename),
					"%s", curl_url_finalname);

				/* Remove extension for extraction directory */
				char* ext = NULL;
				if ((ext = strstr(size_filename, ".tar.gz")) != NULL) {
					*ext = '\0';
					pr_info(stdout, "dog_download_file: removed .tar.gz extension");
				} else if ((ext = strstr(size_filename, ".tar")) != NULL) {
					*ext = '\0';
					pr_info(stdout, "dog_download_file: removed .tar extension");
				} else if ((ext = strstr(size_filename, ".zip")) != NULL) {
					*ext = '\0';
					pr_info(stdout, "dog_download_file: removed .zip extension");
				} /* if */

				/* Extract archive if needed */
				dog_extract_archive(curl_url_finalname,
					size_filename);

				/* Cleanup based on installation type */
				if (installing_package) {
					if (path_exists(curl_url_finalname) == 1) {
						destroy_arch_dir(curl_url_finalname);
						pr_info(stdout, "dog_download_file: cleaned up package archive");
					} /* if */
				} else {
					if (installing_pawncc) {
						if (path_exists(curl_url_finalname) == 1) {
							destroy_arch_dir(curl_url_finalname);
							pr_info(stdout, "dog_download_file: cleaned up compiler archive");
						} /* if */
						pawncc_dir_source = strdup(size_filename);
						dog_apply_pawncc();
						installing_pawncc = false;
					} /* if */
				} /* if */

				pr_info(stdout, "dog_download_file: download successful on attempt %d", retry_count + 1);
				return (0);
			} /* if */
		} else {
			buf_free(&download_buffer);
			pr_info(stdout, "dog_download_file: attempt %d failed - res=%d, code=%ld, len=%zu", 
			         retry_count + 1, res, response_code, download_buffer.len);
		} /* if */

		pr_color(stdout, DOG_COL_YELLOW,
			" Attempt %d/%d failed (HTTP: %ld). Retrying in 3s...\n",
			retry_count + 1, max_retries, response_code);
		++retry_count;
		
		/* Wait before retry */
		if (retry_count < max_retries) {
			sleep(3);
		} /* if */
	} /* while */

	pr_color(stdout, DOG_COL_RED,
		" Failed to download %s from %s after %d retries\n",
		curl_url_finalname, url, retry_count);

	return (1);
} /* dog_download_file */