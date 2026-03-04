#include "utils.h"
#include "curl.h"
#include "archive.h"
#include "crypto.h"
#include "units.h"
#include "debug.h"
#include "api.h"
#include "replicate.h"

bool		 installing_package = 0;
static const char* opr = NULL;
static char		 json_item[DOG_PATH_MAX];
static int		 fdir_counts = 0;
static char		 pbuf[DOG_MAX_PATH];
#ifdef DOG_WINDOWS
static const char* separator = _PATH_STR_SEP_WIN32;
#else
static const char* separator = _PATH_STR_SEP_POSIX;
#endif

/* Platform pattern matching for Windows */
const char* match_windows_lookup_pattern[] =
ASSERT_PATTERN("windows", "win", "win32", "win32", "msvc", "mingw");

/* Platform pattern matching for Linux */
const char* match_linux_lookup_pattern[] =
ASSERT_PATTERN("linux", "ubuntu", "debian", "cent", "centos",
    "almalinux", "rockylinux", "cent_os", "fedora", "arch",
    "archlinux", "alphine", "rhel", "redhat", "linuxmint", "mint");

/* Generic pattern matching for common directories */
const char* match_any_lookup_pattern[] =
ASSERT_PATTERN("src", "source", "proj", "project", "server",
    "_server", "gamemode", "gamemodes", "bin", "build", "packages",
    "resources", "modules", "plugins", "addons", "es",
    "scripts", "system", "core", "runtime", "libs", "include",
    "deps", "dependencies");

/**
 * Check if filename matches current OS patterns
 */
static int this_os_archive(const char* filename)
{
    int		 k = 0;
    char		 size_host_os[DOG_PATH_MAX] = {0};
    char		 filename_lwr[DOG_PATH_MAX] = {0};
    const char** lookup_pattern = NULL;
    long int     i = 0;
    int          found = 0;

    if (filename == NULL) {
        pr_error(stdout, "this_os_archive: filename is NULL");
        return (0);
    } /* if */

    if (opr == NULL) {
        pr_info(stdout, "this_os_archive: opr is NULL");
        return (0);
    } /* if */

    strlcpy(size_host_os, opr, sizeof(size_host_os));
    size_host_os[sizeof(size_host_os) - 1] = '\0';

    for (i = 0; size_host_os[i] != '\0'; i++) {
        size_host_os[i] = tolower((unsigned char)size_host_os[i]);
    } /* for */

    if (strfind(size_host_os, "win", true)) {
        lookup_pattern = match_windows_lookup_pattern;
    } else if (strfind(size_host_os, "linux", true)) {
        lookup_pattern = match_linux_lookup_pattern;
    } /* if */

    if (lookup_pattern == NULL) {
        return (0);
    } /* if */

    strlcpy(filename_lwr, filename, sizeof(filename_lwr));
    filename_lwr[sizeof(filename_lwr) - 1] = '\0';

    for (i = 0; filename_lwr[i] != '\0'; i++) {
        filename_lwr[i] = tolower((unsigned char)filename_lwr[i]);
    } /* for */

    for (k = 0; lookup_pattern[k] != NULL; ++k) {
        if (strfind(filename_lwr, lookup_pattern[k], true)) {
            found = 1;
            break;
        } /* if */
    } /* for */

    return found;
} /* this_os_archive */

/**
 * Check if filename matches any generic pattern
 */
static int this_more_archive(const char* filename)
{
    int	 k = 0;
    int	 ret = 0;

    if (filename == NULL) {
        pr_error(stdout, "this_more_archive: filename is NULL");
        return (0);
    } /* if */

    for (k = 0; match_any_lookup_pattern[k] != NULL; ++k) {
        if (strfind(filename, match_any_lookup_pattern[k], true)) {
            ret = 1;
            break;
        } /* if */
    } /* for */

    return ret;
} /* this_more_archive */

/**
 * Try to find OS-specific asset from list
 */
static char* try_build_os_asseets(char** assets, int count, const char* os_pattern)
{
    int			 i = 0;
    int          p = 0;
    const char* const* lookup_pattern = NULL;
    char*        result = NULL;

    if (assets == NULL || count <= 0 || os_pattern == NULL) {
        pr_error(stdout, "try_build_os_asseets: invalid parameters");
        return (NULL);
    } /* if */

    if (strfind(os_pattern, "win", true)) {
        lookup_pattern = match_windows_lookup_pattern;
    } else if (strfind(os_pattern, "linux", true)) {
        lookup_pattern = match_linux_lookup_pattern;
    } else {
        return (NULL);
    } /* if */

    for (i = 0; i < count; i++) {
        const char* asset = assets[i];
        
        if (asset == NULL) {
            continue;
        } /* if */

        for (p = 0; lookup_pattern[p] != NULL; p++) {
            if (!strfind(asset, lookup_pattern[p], true)) {
                continue;
            } /* if */

            result = strdup(asset);
            if (result != NULL) {
                pr_info(stdout, "try_build_os_asseets: found %s", asset);
            } /* if */
            return result;
        } /* for */
    } /* for */

    return (NULL);
} /* try_build_os_asseets */

/**
 * Try to find server-related asset matching OS
 */
static char* try_server_assets(char** assets, int count, const char* os_pattern)
{
    const char* const* os_patterns = NULL;
    int			 i = 0;
    int          p = 0;
    char*        result = NULL;

    if (assets == NULL || count <= 0 || os_pattern == NULL) {
        pr_error(stdout, "try_server_assets: invalid parameters");
        return (NULL);
    } /* if */

    if (strfind(os_pattern, "win", true)) {
        os_patterns = match_windows_lookup_pattern;
    } else if (strfind(os_pattern, "linux", true)) {
        os_patterns = match_linux_lookup_pattern;
    } else {
        return (NULL);
    } /* if */

    for (i = 0; i < count; i++) {
        const char* asset = assets[i];
        
        if (asset == NULL) {
            continue;
        } /* if */

        /* Check generic patterns first */
        for (p = 0; match_any_lookup_pattern[p] != NULL; p++) {
            if (strfind(asset, match_any_lookup_pattern[p], true)) {
                break;
            } /* if */
        } /* for */

        if (match_any_lookup_pattern[p] == NULL) {
            continue;
        } /* if */

        /* Then check OS patterns */
        for (p = 0; os_patterns[p] != NULL; p++) {
            if (strfind(asset, os_patterns[p], true)) {
                result = strdup(asset);
                if (result != NULL) {
                    pr_info(stdout, "try_server_assets: found %s", asset);
                } /* if */
                return result;
            } /* if */
        } /* for */
    } /* for */

    return (NULL);
} /* try_server_assets */

/**
 * Try to find generic asset as fallback
 */
static char* try_generic_assets(char** assets, int count)
{
    int	i = 0;
    int p = 0;
    char* result = NULL;

    if (assets == NULL || count <= 0) {
        pr_error(stdout, "try_generic_assets: invalid parameters");
        return (NULL);
    } /* if */

    /* First pass: look for any pattern match */
    for (i = 0; i < count; i++) {
        const char* asset = assets[i];
        
        if (asset == NULL) {
            continue;
        } /* if */

        for (p = 0; match_any_lookup_pattern[p] != NULL; p++) {
            if (strfind(asset, match_any_lookup_pattern[p], true)) {
                result = strdup(asset);
                if (result != NULL) {
                    pr_info(stdout, "try_generic_assets: found pattern match %s", asset);
                } /* if */
                return result;
            } /* if */
        } /* for */
    } /* for */

    /* Second pass: take first asset without OS-specific patterns */
    for (i = 0; i < count; i++) {
        const char* asset = assets[i];
        
        if (asset == NULL) {
            continue;
        } /* if */

        for (p = 0; match_windows_lookup_pattern[p] != NULL; p++) {
            if (strfind(asset, match_windows_lookup_pattern[p], true)) {
                break;
            } /* if */
        } /* for */

        if (match_windows_lookup_pattern[p] != NULL) {
            continue;
        } /* if */

        for (p = 0; match_linux_lookup_pattern[p] != NULL; p++) {
            if (strfind(asset, match_linux_lookup_pattern[p], true)) {
                break;
            } /* if */
        } /* for */

        if (match_linux_lookup_pattern[p] != NULL) {
            continue;
        } /* if */

        result = strdup(asset);
        if (result != NULL) {
            pr_info(stdout, "try_generic_assets: found OS-free asset %s", asset);
        } /* if */
        return result;
    } /* for */

    /* Last resort: return first asset */
    if (assets[0] != NULL) {
        result = strdup(assets[0]);
        pr_info(stdout, "try_generic_assets: using first asset %s", assets[0]);
    } /* if */
    
    return result;
} /* try_generic_assets */

/**
 * Fetch appropriate asset based on OS platform
 */
static char* package_fetching_assets(char** package_assets,
    int counts, const char* pf_os)
{
    char* result = NULL;
    char		 size_host_os[32] = { 0 };
    int          j = 0;

    if (package_assets == NULL || counts == 0) {
        pr_error(stdout, "package_fetching_assets: no assets");
        return (NULL);
    } /* if */

    if (counts == 1) {
        result = strdup(package_assets[0]);
        pr_info(stdout, "package_fetching_assets: only one asset: %s", package_assets[0]);
        return result;
    } /* if */

    if (pf_os != NULL && pf_os[0] != '\0') {
        opr = pf_os;
    } else {
        opr = "windows";
        pr_info(stdout, "package_fetching_assets: using default OS: windows");
    } /* if */

    if (opr != NULL) {
        strncpy(size_host_os, opr, sizeof(size_host_os) - 1);
        size_host_os[sizeof(size_host_os) - 1] = '\0';
        
        for (j = 0; size_host_os[j] != '\0'; j++) {
            size_host_os[j] = tolower((unsigned char)size_host_os[j]);
        } /* for */
    } /* if */

    if (size_host_os[0] != '\0') {
        result = try_server_assets(package_assets, counts, size_host_os);
        if (result != NULL) {
            return result;
        } /* if */

        result = try_build_os_asseets(package_assets, counts, size_host_os);
        if (result != NULL) {
            return result;
        } /* if */
    } /* if */

    result = try_generic_assets(package_assets, counts);
    return result;
} /* package_fetching_assets */

/**
 * Parse repository information from input string
 */
static int package_parse_repo(const char* input, struct _repositories* ctx)
{
    char* parse_input = NULL;
    char* tag_ptr = NULL;
    char* path = NULL;
    char* slash = NULL;
    char* repo_ptr = NULL;
    char* dot_git = NULL;
    char* choice = NULL;
    int   result = 0;
    static int parse_input_size = 1024;

    if (input == NULL || ctx == NULL) {
        pr_error(stdout, "package_parse_repo: invalid parameters");
        return (0);
    } /* if */

    (void)memset(ctx, 0, sizeof(*ctx));

    parse_input = dog_malloc(parse_input_size);
    if (!parse_input) {
        pr_error(stdout, "package_parse_repo: memory allocation failed");
        return (0);
    } /* if */

    (void)strlcpy(parse_input, input, parse_input_size);
    parse_input[parse_input_size - 1] = '\0';

    /* Extract tag if present */
    tag_ptr = strrchr(parse_input, '?');
    if (tag_ptr != NULL) {
        *tag_ptr = '\0';
        (void)strlcpy(ctx->tag,
                      tag_ptr + 1, sizeof(ctx->tag));
        pr_info(stdout, "package_parse_repo: extracted tag: %s", ctx->tag);
    } /* if */

    /* Remove protocol prefix */
    path = parse_input;
    if (strncmp(path, "https://", 8) == 0) {
        path += 8;
    } else if (strncmp(path, "http://", 7) == 0) {
        path += 7;
    } /* if */

    /* Prompt user to select host */
    print(DOG_COL_BCYAN
        "A) GitHub B) GitLab C) Gitea D) SourceForge\n");

    choice = readline("Please select host (A-D): ");
    if (choice == NULL) {
        pr_info(stdout, "package_parse_repo: no host selected");
        dog_free(parse_input);
        return (0);
    } /* if */

    if (choice[0] == '\0') {
        (void)strlcpy(ctx->host,
                      "github",
                      sizeof(ctx->host));
        (void)strlcpy(ctx->domain,
                      "github.com",
                      sizeof(ctx->domain));
        pr_info(stdout, "package_parse_repo: using default host: github");
        goto done;
    } /* if */

    switch (choice[0]) {
    case 'A':
    case 'a':
        (void)strlcpy(ctx->host,
                "github", sizeof(ctx->host));
        (void)strlcpy(ctx->domain,
                "github.com", sizeof(ctx->domain));
        pr_info(stdout, "package_parse_repo: selected GitHub");
        break;
    case 'B':
    case 'b':
        (void)strlcpy(ctx->host,
                "gitlab", sizeof(ctx->host));
        (void)strlcpy(ctx->domain,
                "gitlab.com", sizeof(ctx->domain));
        pr_info(stdout, "package_parse_repo: selected GitLab");
        break;
    case 'C':
    case 'c':
        (void)strlcpy(ctx->host,
                "gitea", sizeof(ctx->host));
        (void)strlcpy(ctx->domain,
                "gitea.com", sizeof(ctx->domain));
        pr_info(stdout, "package_parse_repo: selected Gitea");
        break;
    case 'D':
    case 'd':
        (void)strlcpy(ctx->host,
                "sourceforge", sizeof(ctx->host));
        (void)strlcpy(ctx->domain,
                "sourceforge.net", sizeof(ctx->domain));
        pr_info(stdout, "package_parse_repo: selected SourceForge");
        break;
    default:
        (void)strlcpy(ctx->host,
                "github", sizeof(ctx->host));
        (void)strlcpy(ctx->domain,
                "github.com", sizeof(ctx->domain));
        pr_warning(stdout, "package_parse_repo: invalid choice '%c', using GitHub", choice[0]);
        break;
    } /* switch */

    dog_free(choice);

done:
    /* Extract user and repository names */
    slash = strchr(path, '/');
    if (!slash) {
        pr_error(stdout, "package_parse_repo: invalid format, no slash in path");
        dog_free(parse_input);
        return (0);
    } /* if */

    *slash = '\0';
    (void)strlcpy(ctx->user,
                  path,
                  sizeof(ctx->user));
    pr_info(stdout, "package_parse_repo: user: %s", ctx->user);

    repo_ptr = slash + 1;
    dot_git = strstr(repo_ptr, ".git");
    if (dot_git != NULL) {
        *dot_git = '\0';
    } /* if */

    (void)strlcpy(ctx->repo,
                  repo_ptr,
                  sizeof(ctx->repo));
    pr_info(stdout, "package_parse_repo: repo: %s", ctx->repo);

    dog_free(parse_input);
    result = 1;
    return result;
} /* package_parse_repo */

/**
 * Get release assets from GitHub API
 */
static int package_gh_release_assets(const char* user,
                                     const char* repo,
                                     char* _tag,
                                     char** out_urls,
                                     int max_urls)
{
    char		 api_url[DOG_PATH_MAX * 2] = {0};
    char* json_data = NULL;
    const char* p = NULL;
    int		 url_count = 0;
    int      ret = 0;

    if (user == NULL || repo == NULL || _tag == NULL || out_urls == NULL || max_urls <= 0) {
        pr_error(stdout, "package_gh_release_assets: invalid parameters");
        return (0);
    } /* if */

    (void)snprintf(api_url, sizeof(api_url),
        URL_GH_RELEASE_TAG, user, repo, _tag);

    pr_info(stdout, "package_gh_release_assets: fetching %s", api_url);

    ret = package_http_get_content(api_url,
        dogconfig.dog_toml_github_tokens,
        &json_data);
    if (!ret) {
        pr_error(stdout, "package_gh_release_assets: HTTP get failed");
        dog_free(json_data);
        return (0);
    } /* if */

    /* Parse JSON for browser_download_url fields */
    p = json_data;
    while (url_count < max_urls &&
        (p = strstr(p, "\"browser_download_url\"")) != NULL)
    {
        const char* url_end = NULL;
        size_t		 url_len = 0;

        p += strlen("\"browser_download_url\"");
        p = strchr(p, '"');
        if (!p) {
            break;
        } /* if */
        ++p;

        url_end = strchr(p, '"');
        if (!url_end) {
            break;
        } /* if */

        url_len = url_end - p;
        out_urls[url_count] = dog_malloc(url_len + 1);
        if (!out_urls[url_count]) {
            pr_error(stdout, "package_gh_release_assets: memory allocation failed for URL %d", url_count);
            for (int i = 0; i < url_count; ++i) {
                dog_free(out_urls[i]);
            } /* for */
            dog_free(json_data);
            return (0);
        } /* if */

        (void)strlcpy(out_urls[url_count],
                      p,
                      url_len + 1);
        out_urls[url_count][url_len] = '\0';

        pr_info(stdout, "package_gh_release_assets: found asset: %s", out_urls[url_count]);

        ++url_count;
        p = url_end + 1;
    } /* while */

    dog_free(json_data);
    pr_info(stdout, "package_gh_release_assets: found %d assets", url_count);
    return (url_count);
} /* package_gh_release_assets */

/**
 * Build repository URL based on context
 */
static void package_build_repo_url(const struct _repositories* ctx,
                                   int rate_tag_page,
                                   char* put_url,
                                   size_t put_size)
{
    char tag_access[128] = { 0 };
    int is_github = 0;
    int has_tag = 0;

    if (ctx == NULL || put_url == NULL || put_size == 0) {
        pr_error(stdout, "package_build_repo_url: invalid parameters");
        return;
    } /* if */

    is_github = strcmp(ctx->host, "github") == 0;
    has_tag = ctx->tag[0] != '\0';

    if (has_tag) {
        strlcpy(tag_access, ctx->tag, sizeof(tag_access));
    } /* if */

    if (has_tag && strcmp(tag_access, "newer") == 0 &&
        is_github && !rate_tag_page) {
        strlcpy(tag_access, "latest", sizeof(tag_access));
        pr_info(stdout, "package_build_repo_url: converted 'newer' to 'latest'");
    } /* if */

    if (!is_github) {
        return;
    } /* if */

    if (rate_tag_page && has_tag) {
        if (strcmp(tag_access, "latest") == 0) {
            (void)snprintf(put_url, put_size,
                "https://%s/%s/%s/releases/latest",
                ctx->domain, ctx->user, ctx->repo);
        } else {
            (void)snprintf(put_url, put_size,
                "https://%s/%s/%s/releases/tag/%s",
                ctx->domain, ctx->user, ctx->repo, tag_access);
        } /* if */

    } else if (has_tag) {
        if (strcmp(tag_access, "latest") == 0) {
            (void)snprintf(put_url, put_size,
                "https://%s/%s/%s/releases/latest",
                ctx->domain, ctx->user, ctx->repo);
        } else {
            (void)snprintf(put_url, put_size,
                URL_GH_ARCHIVE_TAG,
                ctx->user, ctx->repo, tag_access);
        } /* if */

    } else {
        (void)snprintf(put_url, put_size,
            URL_GH_ARCHIVE_BRANCH,
            ctx->user, ctx->repo, "main");
        pr_info(stdout, "package_build_repo_url: using main branch");
    } /* if */
} /* package_build_repo_url */

/**
 * Get latest tag from GitHub repository
 */
static int package_gh_latest_tag(const char* user,
                                 const char* repo,
                                 char* out_tag,
                                 size_t put_size)
{
    char api_url[DOG_PATH_MAX * 2] = {0};
    char* json_data = NULL;
    const char* p = NULL;
    const char* end = NULL;
    size_t tag_len = 0;
    int ret = 0;

    if (!user || !repo || !out_tag || put_size == 0) {
        pr_error(stdout, "package_gh_latest_tag: invalid parameters");
        return (0);
    } /* if */

    (void)snprintf(api_url, sizeof(api_url),
        URL_GH_RELEASE_LATEST, user, repo);

    pr_info(stdout, "package_gh_latest_tag: fetching %s", api_url);

    ret = package_http_get_content(api_url,
        dogconfig.dog_toml_github_tokens,
        &json_data);
    if (!ret) {
        pr_error(stdout, "package_gh_latest_tag: HTTP get failed");
        return (0);
    } /* if */

    /* Parse JSON for tag_name */
    p = strstr(json_data, "\"tag_name\"");
    if (!p) {
        pr_error(stdout, "package_gh_latest_tag: tag_name not found in response");
        dog_free(json_data);
        return (0);
    } /* if */

    p = strchr(p, ':');
    if (!p) {
        pr_error(stdout, "package_gh_latest_tag: colon not found after tag_name");
        dog_free(json_data);
        return (0);
    } /* if */

    while (*p && (*p == ':' || *p == ' ' || *p == '\t' ||
        *p == '\n' || *p == '\r')) {
        ++p;
    } /* while */

    if (*p != '"') {
        pr_error(stdout, "package_gh_latest_tag: expected quote after colon");
        dog_free(json_data);
        return (0);
    } /* if */

    ++p;
    end = strchr(p, '"');
    if (!end) {
        pr_error(stdout, "package_gh_latest_tag: closing quote not found");
        dog_free(json_data);
        return (0);
    } /* if */

    tag_len = end - p;
    if (tag_len >= put_size) {
        tag_len = put_size - 1;
        pr_warning(stdout, "package_gh_latest_tag: tag truncated");
    } /* if */

    strlcpy(out_tag, p, tag_len + 1);
    out_tag[tag_len] = '\0';

    pr_info(stdout, "package_gh_latest_tag: found tag: %s", out_tag);

    dog_free(json_data);
    return (1);
} /* package_gh_latest_tag */

/**
 * Parse generic repository URL (non-GitHub)
 */
static int parsing_generic_repo(const struct _repositories* repo,
                                char* put_url,
                                size_t put_size,
                                const char* branch)
{
    const char* fmt = NULL;
    const char* b = branch ? branch : "main";

    if (repo == NULL || put_url == NULL || put_size == 0) {
        pr_error(stdout, "parsing_generic_repo: invalid parameters");
        return (0);
    } /* if */

    if (strcmp(repo->host, "gitlab") == 0) {
        fmt = URL_GL_ARCHIVE;
        pr_info(stdout, "parsing_generic_repo: using GitLab format");
    } else if (strcmp(repo->host, "gitea") == 0) {
        fmt = URL_GA_ARCHIVE;
        pr_info(stdout, "parsing_generic_repo: using Gitea format");
    } else if (strcmp(repo->host, "sourceforge") == 0) {
        fmt = URL_SF_DOWNLOAD;
        pr_info(stdout, "parsing_generic_repo: using SourceForge format");
    } /* if */

    if (!fmt) {
        pr_error(stdout, "parsing_generic_repo: unknown host %s", repo->host);
        return (0);
    } /* if */

    if (strcmp(repo->host, "sourceforge") == 0) {
        (void)snprintf(put_url, put_size, fmt, repo->repo);
    } else if (strcmp(repo->host, "gitea") == 0) {
        (void)snprintf(put_url, put_size, fmt, repo->user, repo->repo, b);
    } else {
        (void)snprintf(put_url, put_size, fmt,
            repo->user, repo->repo, b,
            repo->repo, b);
    } /* if */

    pr_info(stdout, "parsing_generic_repo: URL: %s", put_url);
    return (1);
} /* parsing_generic_repo */

/**
 * Handle repository URL construction and validation
 */
static int package_handle_repo(const struct _repositories* ctx,
                               char* put_url,
                               size_t put_size,
                               const char* branch)
{
    char		 tag_value[128] = {0};
    char* asset_list[10] = {0};
    char* selected_asset = NULL;
    int		 found = 0;
    int      idx = 0;
    int      asset_count = 0;
    int      use_fallback = 0;
    int      ret = 0;
#define MAX_FALLBACK_BRANCH (3)
    const char* fallback_branches[] = { branch, "main", "master" };

    if (ctx == NULL || put_url == NULL || put_size == 0) {
        pr_error(stdout, "package_handle_repo: invalid parameters");
        return (0);
    } /* if */

    if (strcmp(ctx->host, "github") != 0) {
        ret = parsing_generic_repo(ctx, put_url, put_size, branch);
        return ret;
    } /* if */

    /* Handle "newer" tag specially */
    if (ctx->tag[0] && strcmp(ctx->tag, "newer") == 0) {
        ret = package_gh_latest_tag(ctx->user,
            ctx->repo,
            tag_value,
            sizeof(tag_value));
        if (ret) {
            pr_info(stdout,
                "Creating latest/newer tag: " DOG_COL_CYAN
                "%s " DOG_COL_DEFAULT "~instead of latest "
                DOG_COL_CYAN "(?newer)" DOG_COL_DEFAULT "\t\t"
                DOG_COL_YELLOW "[V]",
                tag_value);
        } else {
            pr_error(stdout,
                "Failed to get latest tag for %s/%s,"
                "Falling back to main branch\t\t[X]",
                ctx->user, ctx->repo);
            minimal_debugging();
            use_fallback = 1;
        } /* if */
    } else {
        strlcpy(tag_value, ctx->tag, sizeof(tag_value));
    } /* if */

    /* Try fallback branches if needed */
    if (use_fallback) {
        for (idx = 0; idx < MAX_FALLBACK_BRANCH && !found; idx++) {
            (void)snprintf(put_url,
                put_size,
                URL_GH_ARCHIVE_BRANCH,
                ctx->user,
                ctx->repo,
                fallback_branches[idx]);

            if (package_url_checking(put_url,
                dogconfig.dog_toml_github_tokens))
            {
                found = 1;
                if (idx == 1) {
                    print("Create master branch "
                        "(main branch not found)"
                        "\t\t" DOG_COL_YELLOW "[V]\n");
                } /* if */
                pr_info(stdout, "package_handle_repo: found fallback branch %s", fallback_branches[idx]);
            } /* if */
        } /* for */
        return found;
    } /* if */

    pr_info(stdout,
        "Fetching any archive from %s..", tag_value);

    if (tag_value[0]) {
        /* Try to get release assets */
        asset_count = package_gh_release_assets(ctx->user,
            ctx->repo, tag_value, asset_list, 10);

        if (asset_count > 0) {
            pr_info(stdout, "package_handle_repo: found %d assets", asset_count);

            if (opr == NULL) {
                pr_info(stdout,
                    "Installing for?\n"
                    "   Windows (A/a/Enter) : GNU/Linux : (B/b)");
                print(DOG_COL_CYAN ">" DOG_COL_DEFAULT);
                char* os_choice = readline(" ");
                
                if (os_choice != NULL) {
                    if (os_choice[0] == '\0' ||
                        os_choice[0] == 'A' || os_choice[0] == 'a')
                    {
                        opr = "windows";
                        pr_info(stdout, "package_handle_repo: selected Windows");
                    } else {
                        opr = "linux";
                        pr_info(stdout, "package_handle_repo: selected Linux");
                    } /* if */
                    dog_free(os_choice);
                } /* if */
            } /* if */

            selected_asset = package_fetching_assets(
                asset_list, asset_count, opr);

            if (selected_asset != NULL) {
                strlcpy(put_url, selected_asset, put_size);
                found = 1;

                pr_info(stdout,
                    "Found:\n   "
                    DOG_COL_YELLOW "\033[1m @ \033[0m"
                    DOG_COL_CYAN "%s\t\t" DOG_COL_YELLOW "[V]\n",
                    selected_asset);

                dog_free(selected_asset);
            } /* if */

            for (idx = 0; idx < asset_count; idx++) {
                if (asset_list[idx] != NULL) {
                    dog_free(asset_list[idx]);
                } /* if */
            } /* for */
        } /* if */

        /* Try archive URLs if no assets found */
        if (!found) {
            const char* archive_formats[] = {
                URL_GH_ARCHIVE_TAG,
                URL_GH_ARCHIVE_TAG_ZIP
            };

            for (idx = 0; idx < 2 && !found; idx++) {
                (void)snprintf(put_url, put_size, archive_formats[idx],
                    ctx->user, ctx->repo, tag_value);

                if (package_url_checking(put_url,
                    dogconfig.dog_toml_github_tokens)) {
                    found = 1;
                    pr_info(stdout, "package_handle_repo: found archive format %d", idx);
                } /* if */
            } /* for */
        } /* if */
    } else {
        /* Try branch archives */
        for (idx = 0; idx < 2 && !found; idx++) {
            (void)snprintf(put_url, put_size, URL_GH_ARCHIVE_BRANCH,
                ctx->user, ctx->repo, fallback_branches[idx]);

            if (package_url_checking(put_url,
                dogconfig.dog_toml_github_tokens)) {
                found = 1;
                if (idx == 1) {
                    print("Create master branch "
                        "(main branch not found)\t\t"
                        DOG_COL_YELLOW "[V]\n");
                } /* if */
                pr_info(stdout, "package_handle_repo: found branch %s", fallback_branches[idx]);
            } /* if */
        } /* for */
    } /* if */

    return found;
} /* package_handle_repo */

/**
 * Try parsing file paths for includes
 */
static int package_try_parsing(const char* raw_file_path, const char* raw_json_path)
{
    char	file_path[DOG_PATH_MAX] = {0};
    char	json_path[DOG_PATH_MAX] = {0};
    int     result = 1;

    if (raw_file_path == NULL || raw_json_path == NULL) {
        pr_error(stdout, "package_try_parsing: invalid parameters");
        return (0);
    } /* if */

    (void)strlcpy(file_path, raw_file_path, sizeof(file_path));
    file_path[sizeof(file_path) - 1] = '\0';
    path_sep_to_posix(file_path);

    (void)strlcpy(json_path, raw_json_path, sizeof(json_path));
    json_path[sizeof(json_path) - 1] = '\0';
    path_sep_to_posix(json_path);

    if (strfind(json_path, "pawno", true) ||
        strfind(json_path, "qawno", true)) {
        /* Do nothing, just goto done */
        pr_info(stdout, "package_try_parsing: found pawno/qawno path");
    } /* if */

done:
    return result;
} /* package_try_parsing */

/**
 * Configure SA-MP server config file (server.cfg)
 */
static void package_configure_samp_conf(const char* config_file,
                                        const char* directive,
                                        const char* plugin_name)
{
    FILE* temp_fp = NULL;
    FILE* orig_fp = NULL;
    char	 temp_path[DOG_PATH_MAX] = {0};
    char	 line_buffer[DOG_PATH_MAX] = {0};
    int	     plugin_exists = 0;
    int      directive_exists = 0;
    int      line_has_plugin = 0;
    int      rm = 0;
    int      rn = 0;

    if (config_file == NULL || directive == NULL || plugin_name == NULL) {
        pr_error(stdout, "package_configure_samp_conf: invalid parameters");
        return;
    } /* if */

    (void)snprintf(temp_path, sizeof(temp_path),
        ".watchdogs/XXXXX_temp");

    if (path_exists(temp_path) == 1) {
        remove(temp_path);
        pr_info(stdout, "package_configure_samp_conf: removed existing temp file");
    } /* if */

    temp_fp = fopen(temp_path, "w");

    if (fet_server_env() != false) {
        pr_info(stdout, "package_configure_samp_conf: not SA-MP environment");
        return;
    } /* if */

    if (dir_exists(".watchdogs") == 0) {
        MKDIR(".watchdogs");
        pr_info(stdout, "package_configure_samp_conf: created .watchdogs directory");
    } /* if */

    pr_color(stdout, DOG_COL_GREEN,
        "Create Dependencies '%s' into '%s'\t\t" DOG_COL_YELLOW "[V]\n",
        plugin_name, config_file);

    orig_fp = fopen(config_file, "r");

    if (!orig_fp) {
        orig_fp = fopen(config_file, "w");
        if (orig_fp != NULL) {
            fprintf(orig_fp, "%s %s\n", directive, plugin_name);
            fclose(orig_fp);
            pr_info(stdout, "package_configure_samp_conf: created new config file");
        } /* if */
        return;
    } /* if */

    plugin_exists = 0;
    directive_exists = 0;
    line_has_plugin = 0;

    while (fgets(line_buffer, sizeof(line_buffer), orig_fp) != NULL) {
        line_buffer[strcspn(line_buffer, "\n")] = 0;
        if (strstr(line_buffer, plugin_name) != NULL) {
            plugin_exists = 1;
        } /* if */
        if (strstr(line_buffer, directive) != NULL) {
            directive_exists = 1;
            if (strstr(line_buffer, plugin_name) != NULL) {
                line_has_plugin = 1;
            } /* if */
        } /* if */
    } /* while */
    fclose(orig_fp);

    if (plugin_exists) {
        pr_info(stdout, "package_configure_samp_conf: plugin already exists");
        return;
    } /* if */

    if (directive_exists && !line_has_plugin) {
        orig_fp = fopen(config_file, "r");
        if (orig_fp == NULL) {
            pr_error(stdout, "package_configure_samp_conf: failed to reopen config file");
            fclose(temp_fp);
            return;
        } /* if */

        while (fgets(line_buffer, sizeof(line_buffer), orig_fp) != NULL) {
            char	clean_line[DOG_PATH_MAX] = {0};
            strcpy(clean_line, line_buffer);
            clean_line[strcspn(clean_line, "\n")] = 0;

            if (strstr(clean_line, directive) != NULL
                && strstr(clean_line, plugin_name) == NULL) {
                fprintf(temp_fp, "%s %s\n", clean_line, plugin_name);
                pr_info(stdout, "package_configure_samp_conf: added plugin to line");
            } else {
                fputs(line_buffer, temp_fp);
            } /* if */
        } /* while */

        fclose(orig_fp);
        fclose(temp_fp);

        rm = remove(config_file);
        if (rm != 0) {
            fprintf(stdout,
                "failed to remove: %s..", config_file);
            minimal_debugging();
        } /* if */
        
        if (path_access(temp_path) == 1 && path_access(config_file) == 0) {
            rn = rename(temp_path, config_file);
            if (rn != 0) {
                fprintf(stdout,
                    "failed to rename: %s to %s..", temp_path, config_file);
                minimal_debugging();
            } /* if */
        } /* if */
    } else if (!directive_exists) {
        orig_fp = fopen(config_file, "a");
        if (orig_fp != NULL) {
            fprintf(orig_fp, "%s %s\n", directive, plugin_name);
            fclose(orig_fp);
            pr_info(stdout, "package_configure_samp_conf: appended plugin to config");
        } /* if */
    } /* if */

    return;
} /* package_configure_samp_conf */

#define S_ADD_PLUGIN(config_file, fw_line, plugin_name) \
	package_configure_samp_conf(config_file, fw_line, plugin_name)

/**
 * Configure open.mp server config file (config.json)
 */
static void package_configure_omp_conf(const char* config_name, const char* package_name)
{
    FILE* fp = NULL;
    cJSON* json_root = NULL;
    cJSON* cJSON_pawn = NULL;
    cJSON* cJSON_legplug = NULL;
    cJSON* array_item = NULL;
    cJSON* new_item = NULL;
    char* buffer = NULL;
    char* json_output = NULL;
    long	 file_size = 0;
    size_t	 bytes_read = 0;
    int	 found = 0;

    if (config_name == NULL || package_name == NULL) {
        pr_error(stdout, "package_configure_omp_conf: invalid parameters");
        return;
    } /* if */

    if (fet_server_env() != true) {
        pr_info(stdout, "package_configure_omp_conf: not open.mp environment");
        return;
    } /* if */

    pr_color(stdout, DOG_COL_GREEN,
        "Create Dependencies '%s' into '%s'\t\t" DOG_COL_YELLOW "[V]\n",
        package_name, config_name);

    fp = fopen(config_name, "r");

    if (!fp) {
        json_root = cJSON_CreateObject();
        pr_info(stdout, "package_configure_omp_conf: created new JSON object");
    } else {
        fseek(fp, 0, SEEK_END);
        file_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        buffer = (char*)dog_malloc(file_size + 1);
        if (!buffer) {
            pr_error(stdout,
                "Memory allocation failed!");
            minimal_debugging();
            fclose(fp);
            return;
        } /* if */

        bytes_read = fread(buffer, 1, file_size, fp);
        if (bytes_read != file_size) {
            pr_error(stdout,
                "Failed to read the entire file!");
            minimal_debugging();
            dog_free(buffer);
            fclose(fp);
            return;
        } /* if */

        buffer[file_size] = '\0';
        fclose(fp);

        json_root = cJSON_Parse(buffer);
        dog_free(buffer);

        if (!json_root) {
            json_root = cJSON_CreateObject();
            pr_info(stdout, "package_configure_omp_conf: created new JSON object (parse failed)");
        } /* if */
    } /* if */

    /* Ensure pawn object exists */
    cJSON_pawn = cJSON_GetObjectItem(json_root, "pawn");
    if (!cJSON_pawn) {
        cJSON_pawn = cJSON_CreateObject();
        cJSON_AddItemToObject(json_root, "pawn", cJSON_pawn);
        pr_info(stdout, "package_configure_omp_conf: created pawn object");
    } /* if */

    /* Ensure legacy_plugins array exists */
    cJSON_legplug = cJSON_GetObjectItem(cJSON_pawn, "legacy_plugins");
    if (!cJSON_legplug) {
        cJSON_legplug = cJSON_CreateArray();
        cJSON_AddItemToObject(cJSON_pawn, "legacy_plugins", cJSON_legplug);
        pr_info(stdout, "package_configure_omp_conf: created legacy_plugins array");
    } /* if */

    if (!cJSON_IsArray(cJSON_legplug)) {
        cJSON_DeleteItemFromObject(cJSON_pawn, "legacy_plugins");
        cJSON_legplug = cJSON_CreateArray();
        cJSON_AddItemToObject(cJSON_pawn, "legacy_plugins", cJSON_legplug);
        pr_info(stdout, "package_configure_omp_conf: replaced legacy_plugins with array");
    } /* if */

    /* Check if plugin already exists */
    found = 0;
    cJSON_ArrayForEach(array_item, cJSON_legplug) {
        if (cJSON_IsString(array_item) &&
            strcmp(array_item->valuestring, package_name) == 0) {
            found = 1;
            pr_info(stdout, "package_configure_omp_conf: plugin already exists: %s", package_name);
            break;
        } /* if */
    } /* cJSON_ArrayForEach */

    /* Add if not found */
    if (!found) {
        new_item = cJSON_CreateString(package_name);
        cJSON_AddItemToArray(cJSON_legplug, new_item);
        pr_info(stdout, "package_configure_omp_conf: added plugin: %s", package_name);
    } /* if */

    json_output = cJSON_Print(json_root);
    fp = fopen(config_name, "w");
    if (fp != NULL) {
        fputs(json_output, fp);
        fclose(fp);
        pr_info(stdout, "package_configure_omp_conf: wrote config file");
    } else {
        pr_error(stdout, "package_configure_omp_conf: failed to open config for writing");
    } /* if */

    cJSON_Delete(json_root);
    dog_free(json_output);

    return;
} /* package_configure_omp_conf */

#define M_ADD_PLUGIN(x, y) package_configure_omp_conf(x, y)

/**
 * Move include files from source directory to destination
 */
static void
package_move_includes_from_dir(const char* src_dir, const char* include_dest)
{
    DIR* dir = NULL;
    struct dirent* entry = NULL;
    char		 src_path[DOG_PATH_MAX * 2] = {0};
    char		 dst_path[DOG_PATH_MAX * 2] = {0};
    char* e = NULL;

    if (src_dir == NULL || include_dest == NULL) {
        pr_error(stdout, "package_move_includes_from_dir: invalid parameters");
        return;
    } /* if */

    dir = opendir(src_dir);
    if (dir == NULL) {
        pr_info(stdout, "package_move_includes_from_dir: cannot open directory %s", src_dir);
        return;
    } /* if */

    while ((entry = readdir(dir)) != NULL) {
        if (dog_dot_or_dotdot(entry->d_name)) {
            continue;
        } /* if */

        e = strrchr(entry->d_name, '.');
        if (e == NULL || strcmp(e, ".inc") != 0) {
            continue;
        } /* if */

        (void)snprintf(src_path, sizeof(src_path),
            "%s%s%s", src_dir, separator, entry->d_name);

        (void)snprintf(dst_path, sizeof(dst_path),
            "%s%s%s", include_dest, separator, entry->d_name);

        if (path_access(src_path) != 1) {
            continue;
        } /* if */

        if (rename(src_path, dst_path) != 0) {
#ifdef DOG_WINDOWS
            DWORD err = GetLastError();
            if (!MoveFileExA(src_path,
                dst_path,
                MOVEFILE_REPLACE_EXISTING |
                MOVEFILE_COPY_ALLOWED))
            {
                fprintf(stderr,
                    "Move failed: %lu\n",
                    GetLastError());
            } /* if */
#else
            if (errno == EXDEV) {
                FILE* src = fopen(src_path, "rb");
                FILE* dst = fopen(dst_path, "wb");

                if (src != NULL && dst != NULL) {
                    char buf[8192] = {0};
                    size_t n;

                    while ((n = fread(buf, 1,
                        sizeof(buf), src)) > 0) {
                        fwrite(buf, 1, n, dst);
                    } /* while */
                    
                    pr_info(stdout, "package_move_includes_from_dir: copied across devices");
                } /* if */

                if (src != NULL) fclose(src);
                if (dst != NULL) fclose(dst);

                unlink(src_path);
            } else {
                perror("rename");
            } /* if */
#endif
        } /* if */
        
        package_try_parsing(dst_path, dst_path);

        pr_color(stdout, DOG_COL_YELLOW,
            " [M] Include %s -> %s\n",
            entry->d_name, dst_path);
    } /* while */

    closedir(dir);
} /* package_move_includes_from_dir */

/**
 * Dump and organize files by type
 */
static void package_dump_file_type(const char* dump_path,
                                   char* dump_pattern,
                                   char* dump_exclude,
                                   char* dump_loc,
                                   char* dump_place,
                                   int dump_root)
{
    const char* package_names = NULL;
    const char* basename = NULL;
    const char* match_root_keywords = NULL;
    char		 dest_path[DOG_PATH_MAX * 2] = {0};
    char		 dir_part[DOG_PATH_MAX] = {0};
    char		 plugin_dir[DOG_PATH_MAX * 2] = {0};
    char* basename_lwr = NULL;
    size_t		 i = 0;
    size_t		 j = 0;
    int		 found = 0;
    int		 has_prefix = 0;
    int		 move_success = 0;

    if (dump_path == NULL || dump_pattern == NULL || dump_loc == NULL) {
        pr_error(stdout, "package_dump_file_type: invalid parameters");
        return;
    } /* if */

    _sef_restore();

    found = dog_find_path(dump_path,
        dump_pattern, dump_exclude);
    ++fdir_counts;

    if (found == 0) {
        pr_info(stdout, "package_dump_file_type: no files found matching pattern %s", dump_pattern);
        return;
    } /* if */

    for (i = 0; i < dogconfig.dog_sef_count; i++) {
        if (dogconfig.dog_sef_found_list[i] == NULL) {
            continue;
        } /* if */

        package_names = fet_filename(dogconfig.dog_sef_found_list[i]);

        basename = fet_basename(dogconfig.dog_sef_found_list[i]);

        if (basename == NULL) {
            continue;
        } /* if */

        basename_lwr = strdup(basename);
        if (basename_lwr == NULL) {
            continue;
        } /* if */

        for (j = 0; basename_lwr[j] != '\0'; j++) {
            basename_lwr[j] = tolower((unsigned char)basename_lwr[j]);
        } /* for */

        has_prefix = 0;
        match_root_keywords = dogconfig.dog_toml_root_patterns;

        if (match_root_keywords != NULL) {
            while (*match_root_keywords != '\0') {

                while (*match_root_keywords == ' ') {
                    match_root_keywords++;
                } /* while */

                if (*match_root_keywords == '\0') {
                    break;
                } /* if */

                const char* keyword_end = match_root_keywords;

                while (*keyword_end != '\0' &&
                    *keyword_end != ' ') {
                    keyword_end++;
                } /* while */

                if (keyword_end > match_root_keywords) {
                    size_t keyword_len = keyword_end - match_root_keywords;

                    if (strncmp(basename_lwr,
                        match_root_keywords,
                        keyword_len) == 0) {
                        has_prefix = 1;
                        break;
                    } /* if */
                } /* if */

                match_root_keywords = (*keyword_end != '\0') ? keyword_end + 1 : keyword_end;
            } /* while */
        } /* if */

        dog_free(basename_lwr);

        dest_path[0] = '\0';

        if (dump_place[0] != '\0') {
            (void)snprintf(dest_path,
                sizeof(dest_path),
                "%s%s%s%s%s",
                dump_loc, separator,
                dump_place, separator,
                package_names);

            (void)snprintf(dir_part,
                sizeof(dir_part),
                "%s%s%s",
                dump_loc, separator,
                dump_place);

            if (dir_exists(dir_part) == 0) {
                dog_mkdir_recursive(dir_part);
            } /* if */

        } else if (has_prefix) {
            (void)snprintf(dest_path,
                sizeof(dest_path),
                "%s%s%s",
                dump_loc, separator,
                package_names);
        } else {
            (void)snprintf(dest_path,
                sizeof(dest_path),
                "%s%s%s%s",
                dump_loc, separator,
                separator,
                package_names);

            (void)snprintf(plugin_dir,
                sizeof(plugin_dir),
                "%s%s",
                dump_loc, separator);

            if (dir_exists(plugin_dir) == 0) {
                dog_mkdir_recursive(plugin_dir);
            } /* if */
        } /* if */

        move_success = 0;

#ifdef DOG_WINDOWS
        if (MoveFileExA(
            dogconfig.dog_sef_found_list[i],
            dest_path,
            MOVEFILE_REPLACE_EXISTING |
            MOVEFILE_COPY_ALLOWED)) {

            move_success = 1;

        } else {
            BOOL ok = FALSE;
            ok = CopyFileA(
                dogconfig.dog_sef_found_list[i],
                dest_path,
                FALSE
            );

            if (ok) {
                ok = DeleteFileA(
                    dogconfig.dog_sef_found_list[i]);
            } /* if */

            move_success = (ok == TRUE);

            if (!move_success) {
                fprintf(stderr,
                    "Copy/Delete failed: %lu\n",
                    GetLastError());
            } /* if */
        } /* if */
#else
        if (rename(dogconfig.dog_sef_found_list[i], dest_path) == 0) {
            move_success = 1;
        } else {
            move_success = 0;
            perror("rename");
        } /* if */
#endif

        if (move_success == 0) {
            pr_error(stdout,
                "Failed to move: %s",
                basename ? basename : "unknown");
            continue;
        } /* if */

        pr_color(stdout, DOG_COL_CYAN,
            " [M] Plugins %s -> %s\n",
            basename ? basename : "unknown", dump_loc);

        (void)snprintf(json_item,
            sizeof(json_item),
            "%s", package_names ? package_names : "");

        package_try_parsing(
            json_item, json_item);

        if (dump_root == 1) {
            return;
        } /* if */

        if (fet_server_env() == false &&
            strfind(
                dogconfig.dog_toml_server_config,
                ".cfg", true)) {

            S_ADD_PLUGIN(
                dogconfig.dog_toml_server_config,
                "plugins", basename);

        } else if (fet_server_env() == true &&
            strfind(
                dogconfig.dog_toml_server_config,
                ".json", true)) {

            M_ADD_PLUGIN(
                dogconfig.dog_toml_server_config,
                basename);
        } /* if */
    } /* for */
} /* package_dump_file_type */

/**
 * Check if directory contains include files
 */
static int package_has_inc_files(const char* dir_path)
{
    DIR* dir = NULL;
    struct dirent* entry = NULL;
    struct stat	 st = {0};
    char		 full_path[DOG_PATH_MAX * 3] = {0};
    int		 found = 0;

    if (dir_path == NULL) {
        pr_error(stdout, "package_has_inc_files: dir_path is NULL");
        return (0);
    } /* if */

    dir = opendir(dir_path);
    if (dir == NULL) {
        pr_info(stdout, "package_has_inc_files: cannot open %s", dir_path);
        return (0);
    } /* if */

    found = 0;

    while ((entry = readdir(dir)) != NULL && found == 0) {
        if (dog_dot_or_dotdot(entry->d_name)) {
            continue;
        } /* if */

        (void)snprintf(full_path, sizeof(full_path),
            "%s%s%s", dir_path, separator, entry->d_name);

        if (stat(full_path, &st) != 0) {
            continue;
        } /* if */

        if (S_ISDIR(st.st_mode)) {
            found = package_has_inc_files(full_path);
        } else {
            char* ext = strrchr(entry->d_name, '.');
            if (ext != NULL && strcmp(ext, ".inc") == 0) {
                found = 1;
            } /* if */
        } /* if */
    } /* while */

    closedir(dir);

    return found;
} /* package_has_inc_files */

/**
 * Check if directory or subdirectory contains .dogkeepnormal marker
 */
static int package_dogkeeproot(const char* dir_path)
{
    DIR* dir = NULL;
    struct dirent* entry = NULL;
    struct stat	 st = {0};
    char		 full_path[DOG_PATH_MAX * 3] = {0};
    int		 found = 0;

    if (dir_path == NULL) {
        pr_error(stdout, "package_dogkeeproot: dir_path is NULL");
        return (0);
    } /* if */

    dir = opendir(dir_path);
    if (dir == NULL) {
        return (0);
    } /* if */

    found = 0;

    while ((entry = readdir(dir)) != NULL && found == 0) {
        if (dog_dot_or_dotdot(entry->d_name)) {
            continue;
        } /* if */

        if (strcmp(entry->d_name, ".dogkeepnormal") == 0) {
            (void)snprintf(full_path, sizeof(full_path),
                "%s%s%s", dir_path, separator,
                entry->d_name);

            if (stat(full_path, &st) == 0 &&
                S_ISREG(st.st_mode)) {
                found = 1;
            } /* if */

            continue;
        } /* if */

        (void)snprintf(full_path, sizeof(full_path),
            "%s%s%s", dir_path, separator, entry->d_name);

        if (stat(full_path, &st) != 0) {
            continue;
        } /* if */

        if (S_ISDIR(st.st_mode)) {
            found = package_dogkeeproot(full_path);
        } /* if */
    } /* while */

    closedir(dir);

    return found;
} /* package_dogkeeproot */

/**
 * Walk include tree and parse include files
 */
static void package_walk_include_tree(const char* folder_path)
{
    DIR* dir = NULL;
    struct dirent* entry = NULL;
    struct stat	 st = {0};
    char		 full_path[DOG_PATH_MAX * 3] = {0};
    char* ext = NULL;

    if (folder_path == NULL) {
        pr_error(stdout, "package_walk_include_tree: folder_path is NULL");
        return;
    } /* if */

    dir = opendir(folder_path);
    if (dir == NULL) {
        pr_info(stdout, "package_walk_include_tree: cannot open %s", folder_path);
        return;
    } /* if */

    while ((entry = readdir(dir)) != NULL) {
        if (dog_dot_or_dotdot(entry->d_name)) {
            continue;
        } /* if */

        (void)snprintf(full_path,
            sizeof(full_path),
            "%s%s%s",
            folder_path,
            separator,
            entry->d_name);

        if (stat(full_path, &st) != 0) {
            continue;
        } /* if */

        if (S_ISDIR(st.st_mode)) {
            package_walk_include_tree(full_path);
            continue;
        } /* if */

        ext = strrchr(entry->d_name, '.');
        if (ext == NULL) {
            continue;
        } /* if */

        if (strcmp(ext, ".inc") != 0) {
            continue;
        } /* if */

        package_try_parsing(full_path, full_path);
    } /* while */

    closedir(dir);
} /* package_walk_include_tree */

/**
 * Move include files from subdirectories and parse them
 */
static void package_move_and_parse_includes(const char* folder_path, const char* include_dest)
{
    DIR* dir = NULL;
    struct dirent* entry = NULL;
    struct stat	 st = {0};
    char		 full_path[DOG_PATH_MAX * 3] = {0};
    char		 dest_file[DOG_PATH_MAX * 3] = {0};
    char* ext = NULL;

    if (folder_path == NULL || include_dest == NULL) {
        pr_error(stdout, "package_move_and_parse_includes: invalid parameters");
        return;
    } /* if */

    dir = opendir(folder_path);
    if (dir == NULL) {
        pr_info(stdout, "package_move_and_parse_includes: cannot open %s", folder_path);
        return;
    } /* if */

    while ((entry = readdir(dir)) != NULL) {
        if (dog_dot_or_dotdot(entry->d_name)) {
            continue;
        } /* if */

        (void)snprintf(full_path,
            sizeof(full_path),
            "%s%s%s",
            folder_path,
            separator,
            entry->d_name);

        if (stat(full_path, &st) != 0) {
            continue;
        } /* if */

        if (S_ISDIR(st.st_mode)) {
            package_move_and_parse_includes(
                full_path, include_dest);
            continue;
        } /* if */

        ext = strrchr(entry->d_name, '.');
        if (ext == NULL) {
            continue;
        } /* if */

        if (strcmp(ext, ".inc") != 0) {
            continue;
        } /* if */

        (void)snprintf(dest_file,
            sizeof(dest_file),
            "%s%s%s",
            include_dest,
            separator,
            entry->d_name);

        if (path_access(full_path) != 1) {
            continue;
        } /* if */

        if (rename(full_path, dest_file) != 0) {
            pbuf[0] = '\0';

#ifdef DOG_WINDOWS
            if (!MoveFileExA(full_path, dest_file,
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED)) {
                pr_error(stdout, "package_move_and_parse_includes: MoveFileEx failed");
                return;
            } /* if */
#else
            if (rename(full_path, dest_file) != 0) {
                pr_error(stdout, "package_move_and_parse_includes: rename failed");
                return;
            } /* if */
#endif
        } /* if */

        package_try_parsing(dest_file, dest_file);

        pr_color(stdout,
            DOG_COL_YELLOW,
            " [M] Include %s -> %s "
            "(from subfolder)\n",
            entry->d_name,
            dest_file);
    } /* while */

    closedir(dir);
} /* package_move_and_parse_includes */

/**
 * Recursive directory removal helper
 */
static int rm_rf(const char* path);

static int rm_rf_dir(const char* dirpath)
{
    DIR* dir = NULL;
    struct dirent* dp = NULL;
    char full[PATH_MAX] = {0};
    int ret = -1;

    if (dirpath == NULL) {
        pr_error(stdout, "rm_rf_dir: dirpath is NULL");
        return -1;
    } /* if */

    dir = opendir(dirpath);
    if (dir == NULL) {
        pr_error(stdout, "rm_rf_dir: cannot open %s: %s", dirpath, strerror(errno));
        return -1;
    } /* if */

    while ((dp = readdir(dir)) != NULL) {
        if (dog_dot_or_dotdot(dp->d_name)) {
            continue;
        } /* if */

        snprintf(full, sizeof(full),
            "%s/%s", dirpath, dp->d_name);

        if (rm_rf(full) == -1) {
            fprintf(stderr,
                "rm_rf failed for: %s..: %s",
                full, strerror(errno));
        } /* if */
    } /* while */

    closedir(dir);
    ret = rmdir(dirpath);
    return ret;
} /* rm_rf_dir */

/**
 * Recursive file/directory removal (rm -rf equivalent)
 */
static int rm_rf(const char* path)
{
    int ret = -1;

    if (path == NULL) {
        pr_error(stdout, "rm_rf: path is NULL");
        return -1;
    } /* if */

#ifdef DOG_WINDOWS
    WIN32_FIND_DATAA ffd = {0};
    HANDLE h = INVALID_HANDLE_VALUE;

    pbuf[0] = '\0';
    snprintf(pbuf, sizeof(pbuf),
        "%s%s*", path, _PATH_STR_SEP_WIN32);

    h = FindFirstFileA(pbuf, &ffd);
    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    } /* if */
    
    do {
        if (dog_dot_or_dotdot(ffd.cFileName)) {
            continue;
        } /* if */

        pbuf[0] = '\0';
        snprintf(pbuf, sizeof(pbuf),
            "%s%s%s",
            path,
            _PATH_STR_SEP_WIN32,
            ffd.cFileName);

        if (ffd.dwFileAttributes &
            FILE_ATTRIBUTE_DIRECTORY) {
            SHFILEOPSTRUCTA sh = { 0 };
            sh.wFunc = FO_DELETE;
            sh.pFrom = pbuf;
            sh.fFlags = FOF_NO_UI;
            SHFileOperationA(&sh);

        } else {
            DeleteFileA(pbuf);
        } /* if */

    } while (FindNextFileA(h, &ffd));

    FindClose(h);

    ret = RemoveDirectoryA(path);
#else
    struct stat st = {0};

    if (lstat(path, &st) == -1) {
        return -1;
    } /* if */

    if (S_ISDIR(st.st_mode)) {
        ret = rm_rf_dir(path);
    } else {
        ret = unlink(path);
    } /* if */
#endif

    return ret;
} /* rm_rf */

/**
 * Move files from package directory to appropriate locations
 */
static void package_move_files(const char* package_dir,
    const char* package_loc)
{
    char		 the_path[DOG_PATH_MAX * 2] = {0};
    char		 includes[DOG_PATH_MAX] = {0};
    char		 plugins[DOG_PATH_MAX * 2] = {0};
    char		 components[DOG_PATH_MAX * 2] = {0};
    char		 subdir_path[DOG_PATH_MAX * 2] = {0};
    char		 include_dest[DOG_PATH_MAX * 2] = {0};
    char		 dest_file[DOG_PATH_MAX * 3] = {0};
    char		 dest_dir[DOG_PATH_MAX * 3] = {0};
    char		 keeproot_path[DOG_PATH_MAX * 2] = {0};
    char		 pawno_include[DOG_PATH_MAX * 2] = {0};
    char		 qawno_include[DOG_PATH_MAX * 2] = {0};
    char		 new_folder_path[DOG_PATH_MAX * 4] = {0};
    char* folder_name = NULL;
    struct stat	 dir_st = {0};
    struct dirent* entry = NULL;
    DIR* package_dir_handle = NULL;
    char		 folders_to_move[100][DOG_PATH_MAX];
    int		 folder_count = 0;
    int		 has_special_include = 0;
    int		 has_dogkeeproot = 0;
    int		 i = 0;
    int		 server_type = 0;

    if (package_dir == NULL || package_loc == NULL) {
        pr_error(stdout, "package_move_files: invalid parameters");
        return;
    } /* if */

    memset(folders_to_move, 0, sizeof(folders_to_move));
    folder_count = 0;
    has_special_include = 0;
    has_dogkeeproot = 0;

    /* Check for .dogkeepnormal marker */
    (void)snprintf(keeproot_path,
        sizeof(keeproot_path),
        "%s%s.dogkeepnormal",
        package_dir, separator);

    if (path_access(keeproot_path) == 1) {
        has_dogkeeproot = 1;
        pr_color(stdout, DOG_COL_GREEN,
            " [K] Found .dogkeepnormal in root\n");
    } /* if */

    /* Set platform-specific paths */
#ifdef DOG_WINDOWS
    (void)snprintf(plugins, sizeof(plugins),
        "%s\\plugins", package_dir);
    (void)snprintf(components, sizeof(components),
        "%s\\components", package_dir);
#else
    (void)snprintf(plugins, sizeof(plugins),
        "%s/plugins", package_dir);
    (void)snprintf(components, sizeof(components),
        "%s/components", package_dir);
#endif

    server_type = fet_server_env();

    if (server_type == false) {
        (void)strlcpy(includes,
            "pawno/include", sizeof(includes));
    } else {
        (void)strlcpy(includes,
            "qawno/include", sizeof(includes));
    } /* if */

    (void)snprintf(include_dest,
        sizeof(include_dest),
        "%s%s%s",
        package_loc, separator, includes);

    if (dir_exists(include_dest) == 0) {
        dog_mkdir_recursive(include_dest);
    } /* if */

    /* Handle pawno and qawno include directories */
    (void)snprintf(pawno_include,
        sizeof(pawno_include),
        "%s%spawno%sinclude",
        package_dir, separator, separator);

    (void)snprintf(qawno_include,
        sizeof(qawno_include),
        "%s%sqawno%sinclude",
        package_dir, separator, separator);

    if (dir_exists(pawno_include)) {
        has_special_include = 1;
        package_move_includes_from_dir(
            pawno_include, include_dest);
        pr_info(stdout, "package_move_files: moved includes from pawno");
    } /* if */

    if (dir_exists(qawno_include)) {
        has_special_include = 1;
        package_move_includes_from_dir(
            qawno_include, include_dest);
        pr_info(stdout, "package_move_files: moved includes from qawno");
    } /* if */

    /* Scan package directory for subfolders */
    package_dir_handle = opendir(package_dir);
    if (package_dir_handle == NULL) {
        pr_error(stdout,
            "Failed to open directory: %s",
            package_dir);
        return;
    } /* if */

    while ((entry = readdir(package_dir_handle)) != NULL) {
        if (dog_dot_or_dotdot(entry->d_name)) {
            continue;
        } /* if */

        (void)snprintf(the_path,
            sizeof(the_path),
            "%s%s%s",
            package_dir,
            separator,
            entry->d_name);

        if (stat(the_path, &dir_st) != 0) {
            continue;
        } /* if */

        if (!S_ISDIR(dir_st.st_mode)) {
            continue;
        } /* if */

        if (strcmp(entry->d_name,
            "components") == 0 ||
            strcmp(entry->d_name,
                "plugins") == 0 ||
            strcmp(entry->d_name,
                "pawno") == 0 ||
            strcmp(entry->d_name,
                "qawno") == 0) {
            continue;
        } /* if */

        (void)snprintf(subdir_path,
            sizeof(subdir_path),
            "%s%s%s",
            package_dir,
            separator,
            entry->d_name);

        if (package_dogkeeproot(subdir_path)) {
            pr_color(stdout,
                DOG_COL_GREEN,
                " [K] Found .dogkeepnormal "
                "in %s\n",
                entry->d_name);

            package_move_and_parse_includes(
                subdir_path,
                include_dest);
            continue;
        } /* if */

        if (!has_dogkeeproot &&
            package_has_inc_files(subdir_path) &&
            folder_count < 100)
        {
            (void)strlcpy(
                folders_to_move[folder_count],
                subdir_path,
                sizeof(folders_to_move[folder_count]));

            folder_count++;

            pr_color(stdout,
                DOG_COL_GREEN,
                " [D] Include folder: %s\n",
                entry->d_name);
        } /* if */
    } /* while */

    closedir(package_dir_handle);

    /* Move include folders if no special handling */
    if (!has_special_include && !has_dogkeeproot) {
        for (i = 0; i < folder_count; i++) {
            folder_name = strrchr(folders_to_move[i], separator[0]);

            if (folder_name != NULL) {
                folder_name++;
            } else {
                folder_name = folders_to_move[i];
            } /* if */

            (void)snprintf(dest_dir,
                sizeof(dest_dir),
                "%s%s%s",
                include_dest,
                separator,
                folder_name);

            if (dir_exists(dest_dir)) {
                rm_rf(dest_dir);
            } /* if */

#ifdef DOG_WINDOWS
            if (!MoveFileExA(folders_to_move[i],
                include_dest,
                MOVEFILE_REPLACE_EXISTING |
                MOVEFILE_COPY_ALLOWED)) {

                fprintf(stderr,
                    "MoveFileEx failed: %lu\n",
                    GetLastError());
            } else {
                pr_color(stdout,
                    DOG_COL_YELLOW,
                    " [M] Folder %s\n",
                    folder_name);

                (void)snprintf(
                    new_folder_path,
                    sizeof(new_folder_path),
                    "%s%s%s",
                    include_dest,
                    separator,
                    folder_name);

                package_walk_include_tree(
                    new_folder_path);
            } /* if */
#else
            if (rename(folders_to_move[i],
                include_dest) != 0) {
                perror("rename");
            } else {
                pr_color(stdout,
                    DOG_COL_YELLOW,
                    " [M] Folder %s\n",
                    folder_name);

                (void)snprintf(
                    new_folder_path,
                    sizeof(new_folder_path),
                    "%s%s%s",
                    include_dest,
                    separator,
                    folder_name);

                package_walk_include_tree(
                    new_folder_path);
            } /* if */
#endif
        } /* for */
    } /* if */

    /* Handle plugins directory */
    if (dir_exists(plugins)) {
        char plugin_dest[DOG_PATH_MAX] = {0};

        (void)snprintf(plugin_dest,
            sizeof(plugin_dest),
            "%s%splugins",
            package_loc,
            separator);

        if (dir_exists(plugin_dest) == 0) {
            dog_mkdir_recursive(plugin_dest);
        } /* if */

        if (opr != NULL) {
            if (strcmp(opr, "windows") == 0) {
                package_dump_file_type(
                    plugins,
                    "*.dll",
                    NULL,
                    plugin_dest,
                    "",
                    0);
            } else if (strcmp(opr, "linux") == 0) {
                package_dump_file_type(
                    plugins,
                    "*.so",
                    NULL,
                    plugin_dest,
                    "",
                    0);
            } /* if */
        } /* if */
    } /* if */

    (void)putchar('\n');
    destroy_arch_dir(package_dir);
} /* package_move_files */

/**
 * Apply dependencies after download
 */
static void dog_apply_depends(const char* depends_name,
    const char* depends_location)
{
    char	 dep_name[DOG_PATH_MAX] = {0};
    char	 package_dir[DOG_PATH_MAX] = {0};
    char	 full_dest_path[DOG_PATH_MAX * 2] = {0};
    char* ext = NULL;

    if (depends_name == NULL || depends_location == NULL) {
        pr_error(stdout, "dog_apply_depends: invalid parameters");
        return;
    } /* if */

    (void)snprintf(dep_name, sizeof(dep_name),
        "%s", depends_name);

#if defined(_DBG_PRINT)
    println(stdout, "dep_name: %s", dep_name);
#endif

    /* Remove archive ext */
    ext = strstr(dep_name, ".tar.gz");
    if (ext != NULL) {
        *ext = '\0';
    } else {
        ext = strstr(dep_name, ".tar");
        if (ext != NULL) {
            *ext = '\0';
        } else {
            ext = strstr(dep_name, ".zip");
            if (ext != NULL) {
                *ext = '\0';
            } /* if */
        } /* if */
    } /* if */

    (void)snprintf(package_dir, sizeof(package_dir),
        "%s", dep_name);

#if defined(_DBG_PRINT)
    println(stdout, "package dir: %s", package_dir);
#endif

    /* Create necessary directories based on server type */
    if (fet_server_env() == false) {
        (void)snprintf(full_dest_path,
            sizeof(full_dest_path),
            "%s/pawno/include",
            depends_location);
        if (dir_exists(full_dest_path) == 0) {
            dog_mkdir_recursive(full_dest_path);
        } /* if */

        (void)snprintf(full_dest_path,
            sizeof(full_dest_path),
            "%s/plugins",
            depends_location);
        if (dir_exists(full_dest_path) == 0) {
            dog_mkdir_recursive(full_dest_path);
        } /* if */

    } else {
        (void)snprintf(full_dest_path,
            sizeof(full_dest_path),
            "%s/qawno/include",
            depends_location);
        if (dir_exists(full_dest_path) == 0) {
            dog_mkdir_recursive(full_dest_path);
        } /* if */

        (void)snprintf(full_dest_path,
            sizeof(full_dest_path),
            "%s/plugins",
            depends_location);
        if (dir_exists(full_dest_path) == 0) {
            dog_mkdir_recursive(full_dest_path);
        } /* if */

        (void)snprintf(full_dest_path,
            sizeof(full_dest_path),
            "%s/components",
            depends_location);
        if (dir_exists(full_dest_path) == 0) {
            dog_mkdir_recursive(full_dest_path);
        } /* if */
    } /* if */

    package_move_files(package_dir, depends_location);
} /* dog_apply_depends */

/**
 * Main function to install dependencies
 */
void
dog_install_depends(const char* packages, const char* branch, const char* where)
{
    char			 buffer[1024] = { 0 };
    char			 package_url[1024] = { 0 };
    char			 package_name[DOG_PATH_MAX] = { 0 };
    char* token = NULL;
    char* current_dir = NULL;
    char* target_dir = NULL;
    static char* initial_location = NULL;
    const char* dependencies[MAX_DEPENDS] = { 0 };
    struct _repositories	 repo;
    int			 dep_count = 0, i = 0;
    static int   location_ready = false;
#ifdef DOG_WINDOWS
    WIN32_FIND_DATAA ffd = {0};
    HANDLE           hFind = INVALID_HANDLE_VALUE;
    char             search[] = "*";
#endif

    memset(dependencies, 0, sizeof(dependencies));

    installing_package = true;

    if (!packages || !*packages) {
        pr_color(stdout, DOG_COL_RED, "");
        print("no valid dependencies to install!\t\t[X]\n");
        goto done;
    } /* if */

    if (strlen(packages) >= sizeof(buffer)) {
        pr_color(stdout, DOG_COL_RED, "");
        print("packages too long!\t\t[X]\n");
        goto done;
    } /* if */

    (void)snprintf(buffer, sizeof(buffer), "%s", packages);

    /* Parse package list */
    token = strtok(buffer, " ");
    while (token != NULL && dep_count < MAX_DEPENDS) {
        dependencies[dep_count++] = token;
        token = strtok(NULL, " ");
    } /* while */

    if (!dep_count) {
        pr_color(stdout, DOG_COL_RED, "");
        print("no valid dependencies to install!\t\t[X]\n");
        goto done;
    } /* if */

    pr_info(stdout, "dog_install_depends: installing %d dependencies", dep_count);

    /* Install each dependency */
    for (i = 0; i < dep_count; i++) {
        if (dependencies[i] == NULL) {
            continue;
        } /* if */

        pr_info(stdout, "dog_install_depends: processing %s", dependencies[i]);

        if (!package_parse_repo(dependencies[i], &repo)) {
            pr_color(stdout, DOG_COL_RED, "");
            printf("invalid repo format: %s\t\t[X]\n",
                dependencies[i]);
            continue;
        } /* if */

        /* Handle GitHub repos */
        if (!strcmp(repo.host, "github")) {
            if (!package_handle_repo(&repo, package_url,
                sizeof(package_url), branch)) {
                pr_color(stdout, DOG_COL_RED, "");
                printf("repo not found: %s\t\t[X]\n",
                    dependencies[i]);
                continue;
            } /* if */
        } else {
            /* Handle other platforms */
            package_build_repo_url(&repo, 0,
                package_url, sizeof(package_url));
            if (!package_url_checking(package_url,
                dogconfig.dog_toml_github_tokens)) {
                pr_color(stdout, DOG_COL_RED, "");
                printf("repo not found: %s\t\t[X]\n",
                    dependencies[i]);
                continue;
            } /* if */
        } /* if */

        /* Generate package name from URL */
        if (strrchr(package_url, _PATH_CHR_SEP_POSIX) != NULL
            && *(strrchr(package_url, _PATH_CHR_SEP_POSIX) + 1) != '\0') {

            (void)snprintf(package_name, sizeof(package_name), "%s",
                strrchr(package_url, _PATH_CHR_SEP_POSIX) + 1);

            if (!strend(package_name, ".tar.gz", true) &&
                !strend(package_name, ".tar", true) &&
                !strend(package_name, ".zip", true))
            {
                (void)snprintf(package_name + strlen(package_name),
                    sizeof(package_name) - strlen(package_name),
                    ".zip");
            } /* if */
        } else {
            (void)snprintf(package_name, sizeof(package_name),
                "%s.tar.gz", repo.repo);
        } /* if */

        if (!*package_name) {
            pr_color(stdout, DOG_COL_RED, "");
            printf("invalid repo name: %s\t\t[X]\n",
                package_url);
            continue;
        } /* if */

        installing_package = true;

        /* Download the package */
        dog_download_file(package_url, package_name);

        /* Determine installation location */
        if (where == NULL || where[0] == '\0') {
            if (!location_ready) {
                printf("\n"
                    ".."
                    "LIST OF DIRECTORY: "
                    "%s", dog_procure_pwd());
                (void)putchar('\n');

#ifdef DOG_LINUX
                /* Show directory listing on Linux */
                int tree_ret = -1;
                tree_ret = system("tree > /dev/null 2>&1");
                if (!tree_ret) {
                    (void)system("tree .");
                } else {
                    DIR* d = opendir(".");
                    if (d != NULL) {
                        struct dirent* de = NULL;
                        struct stat st = {0};
                        char path[DOG_PATH_MAX] = {0};

                        while ((de = readdir(d)) != NULL) {
                            if (de->d_name[0] == '.') {
                                continue;
                            } /* if */

                            (void)snprintf(path, sizeof(path), "%s", de->d_name);
                            if (lstat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
                                printf("%s\n", de->d_name);
                            } /* if */
                        } /* while */
                        closedir(d);
                    } /* if */
                } /* if */
#else
                /* Show directory listing on Windows */
                hFind = FindFirstFileA(search, &ffd);
                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                            strcmp(ffd.cFileName, ".") != 0 &&
                            strcmp(ffd.cFileName, "..") != 0) {
                            printf("%s\n", ffd.cFileName);
                        } /* if */
                    } while (FindNextFileA(hFind, &ffd));
                    FindClose(hFind);
                } /* if */
#endif

                (void)putchar('\n');

                /* Prompt for installation directory */
                printf(DOG_COL_BCYAN
                    "Where do you want to install %s? "
                    "(enter for: %s)" DOG_COL_DEFAULT,
                    package_name, dog_procure_pwd());

                target_dir = readline(" ");
                if (target_dir == NULL) {
                    pr_info(stdout, "dog_install_depends: readline returned NULL");
                    continue;
                } /* if */

                if (target_dir[0] == '\0' || target_dir[0] == '.') {
                    current_dir = dog_procure_pwd();
                    initial_location = strdup(current_dir);
                    if (current_dir != NULL) {
                        dog_apply_depends(package_name,
                            current_dir);
                    } /* if */
                    dog_free(target_dir);
                } else {
                    if (dir_exists(target_dir) == 0) {
                        dog_mkdir_recursive(target_dir);
                    } /* if */
                    initial_location = strdup(target_dir);
                    dog_apply_depends(package_name,
                        target_dir);
                    dog_free(target_dir);
                } /* if */

                location_ready = true;
            } else {
                dog_apply_depends(package_name, initial_location);
            } /* if */
        } else {
            if (dir_exists(where) == 0) {
                dog_mkdir_recursive(where);
            } /* if */
            dog_apply_depends(package_name, where);
        } /* if */
    } /* for */

done:
    return;
} /* dog_install_depends */