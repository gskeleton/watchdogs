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
    int		 k;
    char		 size_host_os[DOG_PATH_MAX];
    char		 filename_lwr[DOG_PATH_MAX];
    const char** lookup_pattern = NULL;

    strlcpy(size_host_os, opr, sizeof(size_host_os));
    size_host_os[sizeof(size_host_os) - 1] = '\0';

    for (long int i = 0; size_host_os[i]; i++)
        size_host_os[i] = tolower(size_host_os[i]);

    if (strfind(size_host_os, "win", true))
        lookup_pattern = match_windows_lookup_pattern;
    else if (strfind(size_host_os, "linux", true))
        lookup_pattern = match_linux_lookup_pattern;

    if (!lookup_pattern)
        return (0);

    strlcpy(filename_lwr, filename, sizeof(filename_lwr));
    filename_lwr[sizeof(filename_lwr) - 1] = '\0';

    for (int i = 0; filename_lwr[i]; i++)
        filename_lwr[i] = tolower(filename_lwr[i]);

    for (k = 0; lookup_pattern[k] != NULL; ++k) {
        if (strfind(filename_lwr, lookup_pattern[k], true))
            return (1);
    }

    return (0);
}

/**
 * Check if filename matches any generic pattern
 */
static int this_more_archive(const char* filename)
{
    int	 k;
    int	 ret = 0;

    for (k = 0; match_any_lookup_pattern[k] != NULL; ++k) {
        if (strfind(filename, match_any_lookup_pattern[k], true)) {
            ret = 1;
            break;
        }
    }

    return (ret);
}

/**
 * Try to find OS-specific asset from list
 */
static char* try_build_os_asseets(char** assets, int count, const char* os_pattern)
{
    int			 i;
    const char* const* lookup_pattern = NULL;

    if (strfind(os_pattern, "win", true))
        lookup_pattern = match_windows_lookup_pattern;
    else if (strfind(os_pattern, "linux", true))
        lookup_pattern = match_linux_lookup_pattern;
    else
        return (NULL);

    for (i = 0; i < count; i++) {
        const char* asset = assets[i];
        int		 p;

        for (p = 0; lookup_pattern[p]; p++) {
            if (!strfind(asset, lookup_pattern[p], true))
                continue;

            return (strdup(asset));
        }
    }

    return (NULL);
}

/**
 * Try to find server-related asset matching OS
 */
static char* try_server_assets(char** assets, int count, const char* os_pattern)
{
    const char* const* os_patterns = NULL;
    int			 i;

    if (strfind(os_pattern, "win", true))
        os_patterns = match_windows_lookup_pattern;
    else if (strfind(os_pattern, "linux", true))
        os_patterns = match_linux_lookup_pattern;
    else
        return (NULL);

    for (i = 0; i < count; i++) {
        const char* asset = assets[i];
        int		 p;

        /* Check generic patterns first */
        for (p = 0; match_any_lookup_pattern[p]; p++) {
            if (strfind(asset, match_any_lookup_pattern[p], true))
                break;
        }

        if (!match_any_lookup_pattern[p])
            continue;

        /* Then check OS patterns */
        for (p = 0; os_patterns[p]; p++) {
            if (strfind(asset, os_patterns[p], true))
                return (strdup(asset));
        }
    }

    return (NULL);
}

/**
 * Try to find generic asset as fallback
 */
static char* try_generic_assets(char** assets, int count)
{
    int	i;

    /* First pass: look for any pattern match */
    for (i = 0; i < count; i++) {
        const char* asset = assets[i];
        int		 p;

        for (p = 0; match_any_lookup_pattern[p]; p++) {
            if (strfind(asset, match_any_lookup_pattern[p], true))
                return (strdup(asset));
        }
    }

    /* Second pass: take first asset without OS-specific patterns */
    for (i = 0; i < count; i++) {
        const char* asset = assets[i];
        int		 p;

        for (p = 0; match_windows_lookup_pattern[p]; p++) {
            if (strfind(asset, match_windows_lookup_pattern[p], true))
                break;
        }

        if (match_windows_lookup_pattern[p])
            continue;

        for (p = 0; match_linux_lookup_pattern[p]; p++) {
            if (strfind(asset, match_linux_lookup_pattern[p], true))
                break;
        }

        if (match_linux_lookup_pattern[p])
            continue;

        return (strdup(asset));
    }

    /* Last resort: return first asset */
    return (strdup(assets[0]));
}

/**
 * Fetch appropriate asset based on OS platform
 */
static char* package_fetching_assets(char** package_assets,
    int counts, const char* pf_os)
{
    char* result = NULL;
    char		 size_host_os[32] = { 0 };

    if (counts == 0)
        return (NULL);
    if (counts == 1)
        return (strdup(package_assets[0]));

    if (pf_os && pf_os[0]) {
        opr = pf_os;
    }
    else {
        opr = "windows";
    }

    if (opr) {
        strncpy(size_host_os, opr, sizeof(size_host_os) - 1);
        for (int j = 0; size_host_os[j]; j++)
            size_host_os[j] = tolower(size_host_os[j]);
    }

    if (size_host_os[0]) {
        result = try_server_assets(package_assets, counts, size_host_os);
        if (result)
            return (result);

        result = try_build_os_asseets(package_assets, counts, size_host_os);
        if (result)
            return (result);
    }

    return (try_generic_assets(package_assets, counts));
}

/**
 * Parse repository information from input string
 */
static int package_parse_repo(const char* input, struct _repositories* ctx)
{
    char* parse_input, * tag_ptr, * path, * slash;
    char* repo_ptr, * dot_git;
    char* choice;

    (void)memset(ctx, 0, sizeof(*ctx));

    static int parse_input_size = 1024;
    parse_input = dog_malloc(parse_input_size);
    if (!parse_input)
        return (0);

    (void)strlcpy(parse_input, input, parse_input_size);
    parse_input[parse_input_size - 1] = '\0';

    /* Extract tag if present */
    tag_ptr = strrchr(parse_input, '?');
    if (tag_ptr) {
        *tag_ptr = '\0';
        (void)strlcpy(ctx->tag,
                      tag_ptr + 1, sizeof(ctx->tag));
    }

    /* Remove protocol prefix */
    path = parse_input;
    if (strncmp(path, "https://", 8) == 0) {
        path += 8;
    } else if (strncmp(path, "http://", 7) == 0) {
        path += 7;
    }

    /* Prompt user to select host */
    print(DOG_COL_BCYAN
        "A) GitHub B) GitLab C) Gitea D) SourceForge\n");

    choice = readline("Please select host (A-D): ");
    if (choice[0] == '\0') {
        (void)strlcpy(ctx->host,
                      "github",
                      sizeof(ctx->host));
        (void)strlcpy(ctx->domain,
                      "github.com",
                      sizeof(ctx->domain));
        goto done;
    }

    switch (choice[0]) {
    case 'A':
    case 'a':
        (void)strlcpy(ctx->host,
                "github", sizeof(ctx->host));
        (void)strlcpy(ctx->domain,
                "github.com", sizeof(ctx->domain));
        break;
    case 'B':
    case 'b':
        (void)strlcpy(ctx->host,
                "gitlab", sizeof(ctx->host));
        (void)strlcpy(ctx->domain,
                "gitlab.com", sizeof(ctx->domain));
        break;
    case 'C':
    case 'c':
        (void)strlcpy(ctx->host,
                "gitea", sizeof(ctx->host));
        (void)strlcpy(ctx->domain,
                "gitea.com", sizeof(ctx->domain));
        break;
    case 'D':
    case 'd':
        (void)strlcpy(ctx->host,
                "sourceforge", sizeof(ctx->host));
        (void)strlcpy(ctx->domain,
                "sourceforge.net", sizeof(ctx->domain));
        break;
    default:
        (void)strlcpy(ctx->host,
                "github", sizeof(ctx->host));
        (void)strlcpy(ctx->domain,
                "github.com", sizeof(ctx->domain));
        break;
    }

    dog_free(choice);

done:
    /* Extract user and repository names */
    slash = strchr(path, '/');
    if (!slash) {
        dog_free(parse_input);
        return (0);
    }

    *slash = '\0';
    (void)strlcpy(ctx->user,
                  path,
                  sizeof(ctx->user));

    repo_ptr = slash + 1;
    dot_git = strstr(repo_ptr, ".git");
    if (dot_git)
        *dot_git = '\0';

    (void)strlcpy(ctx->repo,
                  repo_ptr,
                  sizeof(ctx->repo));

    dog_free(parse_input);
    return (1);
}

/**
 * Get release assets from GitHub API
 */
static int package_gh_release_assets(const char* user,
                                     const char* repo,
                                     char* _tag,
                                     char** out_urls,
                                     int max_urls)
{
    char		 api_url[DOG_PATH_MAX * 2];
    char* json_data = NULL;
    const char* p;
    int		 url_count = 0;

    (void)snprintf(api_url, sizeof(api_url),
        URL_GH_RELEASE_TAG, user, repo, _tag);

    int ret = package_http_get_content(api_url,
        dogconfig.dog_toml_github_tokens,
        &json_data);
    if (!ret)
    {
        dog_free(json_data);
        return (0);
    }

    /* Parse JSON for browser_download_url fields */
    p = json_data;
    while (url_count < max_urls &&
        (p = strstr(p, "\"browser_download_url\"")) != NULL)
    {
        const char* url_end;
        size_t		 url_len;

        p += strlen("\"browser_download_url\"");
        p = strchr(p, '"');
        if (!p)
            break;
        ++p;

        url_end = strchr(p, '"');
        if (!url_end)
            break;

        url_len = url_end - p;
        out_urls[url_count] = dog_malloc(url_len + 1);
        if (!out_urls[url_count]) {
            for (int i = 0; i < url_count; ++i) {
                dog_free(out_urls[i]);
            }
            dog_free(json_data);
            return (0);
        }

        (void)strlcpy(out_urls[url_count],
                      p,
                      url_len + 1);
        out_urls[url_count][url_len] = '\0';

        ++url_count;
        p = url_end + 1;
    }

    dog_free(json_data);
    return (url_count);
}

/**
 * Build repository URL based on context
 */
static void package_build_repo_url(const struct _repositories* ctx,
                                   int rate_tag_page,
                                   char* put_url,
                                   size_t put_size)
{
    char tag_access[128] = { 0 };
    int is_github = strcmp(ctx->host, "github") == 0;
    int has_tag = ctx->tag[0] != '\0';

    if (has_tag)
        strlcpy(tag_access, ctx->tag, sizeof(tag_access));

    if (has_tag && strcmp(tag_access, "newer") == 0 &&
        is_github && !rate_tag_page)
        strlcpy(tag_access, "latest", sizeof(tag_access));

    if (!is_github)
        return;

    if (rate_tag_page && has_tag) {
        if (strcmp(tag_access, "latest") == 0) {
            (void)snprintf(put_url, put_size,
                "https://%s/%s/%s/releases/latest",
                ctx->domain, ctx->user, ctx->repo);
        } else {
            (void)snprintf(put_url, put_size,
                "https://%s/%s/%s/releases/tag/%s",
                ctx->domain, ctx->user, ctx->repo, tag_access);
        }

    } else if (has_tag) {
        if (strcmp(tag_access, "latest") == 0) {
            (void)snprintf(put_url, put_size,
                "https://%s/%s/%s/releases/latest",
                ctx->domain, ctx->user, ctx->repo);
        } else {
            (void)snprintf(put_url, put_size,
                URL_GH_ARCHIVE_TAG,
                ctx->user, ctx->repo, tag_access);
        }

    } else {
        (void)snprintf(put_url, put_size,
            URL_GH_ARCHIVE_BRANCH,
            ctx->user, ctx->repo, "main");
    }
}

/**
 * Get latest tag from GitHub repository
 */
static int package_gh_latest_tag(const char* user,
                                 const char* repo,
                                 char* out_tag,
                                 size_t put_size)
{
    char api_url[DOG_PATH_MAX * 2];
    char* json_data = NULL;
    const char* p, * end;
    size_t tag_len;

    if (!user || !repo || !out_tag || put_size == 0)
        return (0);

    (void)snprintf(api_url, sizeof(api_url),
        URL_GH_RELEASE_LATEST, user, repo);

    int ret = package_http_get_content(api_url,
        dogconfig.dog_toml_github_tokens,
        &json_data);
    if (!ret)
    {
        return (0);
    }

    /* Parse JSON for tag_name */
    p = strstr(json_data, "\"tag_name\"");
    if (!p) {
        dog_free(json_data);
        return (0);
    }

    p = strchr(p, ':');
    if (!p) {
        dog_free(json_data);
        return (0);
    }

    while (*p && (*p == ':' || *p == ' ' || *p == '\t' ||
        *p == '\n' || *p == '\r'))
        ++p;

    if (*p != '"') {
        dog_free(json_data);
        return (0);
    }

    ++p;
    end = strchr(p, '"');
    if (!end) {
        dog_free(json_data);
        return (0);
    }

    tag_len = end - p;
    if (tag_len >= put_size)
        tag_len = put_size - 1;

    strlcpy(out_tag, p, tag_len + 1);
    out_tag[tag_len] = '\0';

    dog_free(json_data);
    return (1);
}

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

    if (strcmp(repo->host, "gitlab") == 0) {
        fmt = URL_GL_ARCHIVE;
    } else if (strcmp(repo->host, "gitea") == 0) {
        fmt = URL_GA_ARCHIVE;
    } else if (strcmp(repo->host, "sourceforge") == 0) {
        fmt = URL_SF_DOWNLOAD;
    }

    if (!fmt)
        return (0);

    if (strcmp(repo->host, "sourceforge") == 0) {
        (void)snprintf(put_url, put_size, fmt, repo->repo);
    }
    else if (strcmp(repo->host, "gitea") == 0) {
        (void)snprintf(put_url, put_size, fmt, repo->user, repo->repo, b);
    }
    else {
        (void)snprintf(put_url, put_size, fmt,
            repo->user, repo->repo, b,
            repo->repo, b);
    }

    return (0);
}

/**
 * Handle repository URL construction and validation
 */
static int package_handle_repo(const struct _repositories* ctx,
                               char* put_url,
                               size_t put_size,
                               const char* branch)
{
    char		 tag_value[128];
    char* asset_list[10];
    char* selected_asset;
    int		 found = 0, idx, asset_count, use_fallback = 0;
#define MAX_FALLBACK_BRANCH (3)
    const char* fallback_branches[] = { branch, "main", "master" };

    if (strcmp(ctx->host, "github") != 0)
        return (parsing_generic_repo(ctx, put_url,
            put_size, branch));

    /* Handle "newer" tag specially */
    if (ctx->tag[0] && strcmp(ctx->tag, "newer") == 0) {
        int ret = package_gh_latest_tag(ctx->user,
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
        }
        else {
            pr_error(stdout,
                "Failed to get latest tag for %s/%s,"
                "Falling back to main branch\t\t[X]",
                ctx->user, ctx->repo);
            minimal_debugging();
            use_fallback = 1;
        }
    }
    else {
        strlcpy(tag_value, ctx->tag, sizeof(tag_value));
    }

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
                }
            }
        }
        return (found);
    }

    pr_info(stdout,
        "Fetching any archive from %s..", tag_value);

    if (tag_value[0]) {
        /* Try to get release assets */
        asset_count = package_gh_release_assets(ctx->user,
            ctx->repo, tag_value, asset_list, 10);

        if (asset_count > 0) {

            if (opr == NULL) {
                pr_info(stdout,
                    "Installing for?\n"
                    "   Windows (A/a/Enter) : GNU/Linux : (B/b)");
                print(DOG_COL_CYAN ">" DOG_COL_DEFAULT);
                char* os_choice = readline(" ");
                if (os_choice[0] == '\0' ||
                    os_choice[0] == 'A' || os_choice[0] == 'a')
                {
                    opr = "windows";
                }
                else {
                    opr = "linux";
                }
                dog_free(os_choice);
            }

            selected_asset = package_fetching_assets(
                asset_list, asset_count, opr);

            if (selected_asset) {
                strlcpy(put_url, selected_asset, put_size);
                found = 1;

                pr_info(stdout,
                    "Found:\n   "
                    DOG_COL_YELLOW "\033[1m @ \033[0m"
                    DOG_COL_CYAN "%s\t\t" DOG_COL_YELLOW "[V]\n",
                    selected_asset);

                dog_free(selected_asset);
            }

            for (idx = 0; idx < asset_count; idx++)
                dog_free(asset_list[idx]);
        }

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
                    dogconfig.dog_toml_github_tokens))
                    found = 1;
            }
        }
    }
    else {
        /* Try branch archives */
        for (idx = 0; idx < 2 && !found; idx++) {
            (void)snprintf(put_url, put_size, URL_GH_ARCHIVE_BRANCH,
                ctx->user, ctx->repo, fallback_branches[idx]);

            if (package_url_checking(put_url,
                dogconfig.dog_toml_github_tokens)) {
                found = 1;
                if (idx == 1)
                    print("Create master branch "
                        "(main branch not found)\t\t"
                        DOG_COL_YELLOW "[V]\n");
            }
        }
    }

    return (found);
}

/**
 * Try parsing file paths for includes
 */
static int package_try_parsing(const char* raw_file_path, const char* raw_json_path)
{
    char	res_convert_f_path[DOG_PATH_MAX], res_convert_json_path[DOG_PATH_MAX];

    strlcpy(res_convert_f_path,
        raw_file_path,
        sizeof(res_convert_f_path));
    res_convert_f_path[sizeof(res_convert_f_path) - 1] = '\0';
    path_sep_to_posix(res_convert_f_path);

    strlcpy(res_convert_json_path,
        raw_json_path,
        sizeof(res_convert_json_path));
    res_convert_json_path[sizeof(res_convert_json_path) - 1] = '\0';
    path_sep_to_posix(res_convert_json_path);

    if (strfind(res_convert_json_path, "pawno", true) ||
        strfind(res_convert_json_path, "qawno", true))
        goto done;

done:
    return (1);
}

/**
 * Configure SA-MP server config file (server.cfg)
 */
static void package_configure_samp_conf(const char* config_file,
                                        const char* directive,
                                        const char* plugin_name)
{
    FILE* temp_fp, * orig_fp;
    char	 temp_path[DOG_PATH_MAX];
    char	 line_buffer[DOG_PATH_MAX];
    int	     plugin_exists, directive_exists, line_has_plugin;

    (void)snprintf(temp_path, sizeof(temp_path),
        ".watchdogs/XXXXX_temp");

    if (path_exists(temp_path) == 1)
        remove(temp_path);

    temp_fp = fopen(temp_path, "w");

    if (fet_server_env() != false)
        return;

    if (dir_exists(".watchdogs") == 0)
        MKDIR(".watchdogs");

    pr_color(stdout, DOG_COL_GREEN,
        "Create Dependencies '%s' into '%s'\t\t" DOG_COL_YELLOW "[V]\n",
        plugin_name, config_file);

    orig_fp = fopen(config_file, "r");

    if (!orig_fp) {
        orig_fp = fopen(config_file, "w");
        fprintf(orig_fp, "%s %s\n", directive, plugin_name);
        fclose(orig_fp);
        return;
    }

    plugin_exists = 0;
    directive_exists = 0;
    line_has_plugin = 0;

    while (fgets(line_buffer, sizeof(line_buffer), orig_fp)) {
        line_buffer[strcspn(line_buffer, "\n")] = 0;
        if (strstr(line_buffer, plugin_name) != NULL)
            plugin_exists = 1;
        if (strstr(line_buffer, directive) != NULL) {
            directive_exists = 1;
            if (strstr(line_buffer, plugin_name) != NULL)
                line_has_plugin = 1;
        }
    }
    fclose(orig_fp);

    if (plugin_exists)
        return;

    if (directive_exists && !line_has_plugin) {
        orig_fp = fopen(config_file, "r");

        while (fgets(line_buffer, sizeof(line_buffer), orig_fp)) {
            char	clean_line[DOG_PATH_MAX];
            strcpy(clean_line, line_buffer);
            clean_line[strcspn(clean_line, "\n")] = 0;

            if (strstr(clean_line, directive) != NULL
                && strstr(clean_line, plugin_name) == NULL) {
                fprintf(temp_fp,
                    "%s %s\n", clean_line, plugin_name);
            } else {
                fputs(line_buffer, temp_fp);
            }
        }

        fclose(orig_fp);
        fclose(temp_fp);

        int rm = remove(config_file);
        if (rm) {
            fprintf(stdout,
                "failed to remove: %s..", config_file);
            minimal_debugging();
        }
        if (path_access(temp_path) == 1 && path_access(config_file) == 0) {
            int rn = rename(temp_path, config_file);
            if (rn) {
                fprintf(stdout,
                    "failed to rename: %s to %s..", temp_path, config_file);
                minimal_debugging();
            }
        }
    } else if (!directive_exists) {
        orig_fp = fopen(config_file, "a");
        fprintf(orig_fp, "%s %s\n", directive, plugin_name);
        fclose(orig_fp);
    }

    return;
}

#define S_ADD_PLUGIN(config_file, fw_line, plugin_name) \
	package_configure_samp_conf(config_file, fw_line, plugin_name)

/**
 * Configure open.mp server config file (config.json)
 */
static void package_configure_omp_conf(const char* config_name, const char* package_name)
{
    FILE* fp;
    cJSON* json_root, * cJSON_pawn, * cJSON_legplug, * array_item, * new_item;
    char* buffer, * json_output;
    long	 file_size;
    size_t	 bytes_read;
    int	 found;

    if (fet_server_env() != true)
        return;

    pr_color(stdout, DOG_COL_GREEN,
        "Create Dependencies '%s' into '%s'\t\t" DOG_COL_YELLOW "[V]\n",
        package_name, config_name);

    fp = fopen(config_name, "r");

    if (!fp) {
        json_root = cJSON_CreateObject();
    }
    else {
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
        }

        bytes_read = fread(buffer, 1, file_size, fp);
        if (bytes_read != file_size) {
            pr_error(stdout,
                "Failed to read the entire file!");
            minimal_debugging();
            dog_free(buffer);
            fclose(fp);
            return;
        }

        buffer[file_size] = '\0';
        fclose(fp);

        json_root = cJSON_Parse(buffer);
        dog_free(buffer);

        if (!json_root) json_root = cJSON_CreateObject();
    }

    /* Ensure pawn object exists */
    cJSON_pawn = cJSON_GetObjectItem(json_root, "pawn");
    if (!cJSON_pawn) {
        cJSON_pawn = cJSON_CreateObject();
        cJSON_AddItemToObject(json_root, "pawn", cJSON_pawn);
    }

    /* Ensure legacy_plugins array exists */
    cJSON_legplug = cJSON_GetObjectItem(cJSON_pawn, "legacy_plugins");
    if (!cJSON_legplug) {
        cJSON_legplug = cJSON_CreateArray();
        cJSON_AddItemToObject(cJSON_pawn, "legacy_plugins", cJSON_legplug);
    }

    if (!cJSON_IsArray(cJSON_legplug)) {
        cJSON_DeleteItemFromObject(cJSON_pawn, "legacy_plugins");
        cJSON_legplug = cJSON_CreateArray();
        cJSON_AddItemToObject(cJSON_pawn, "legacy_plugins", cJSON_legplug);
    }

    /* Check if plugin already exists */
    found = 0;
    cJSON_ArrayForEach(array_item, cJSON_legplug) {
        if (cJSON_IsString(array_item) &&
            !strcmp(array_item->valuestring, package_name)) {
            found = 1;
            break;
        }
    }

    /* Add if not found */
    if (!found) {
        new_item = cJSON_CreateString(package_name);
        cJSON_AddItemToArray(cJSON_legplug, new_item);
    }

    json_output = cJSON_Print(json_root);
    fp = fopen(config_name, "w");
    if (fp) {
        fputs(json_output, fp);
        fclose(fp);
    }

    cJSON_Delete(json_root);
    dog_free(json_output);

    return;
}

#define M_ADD_PLUGIN(x, y) package_configure_omp_conf(x, y)

/**
 * Move include files from source directory to destination
 */
static void
package_move_includes_from_dir(const char* src_dir, const char* include_dest)
{
    DIR* dir;
    struct dirent* entry;
    char		 src_path[DOG_PATH_MAX * 2];
    char		 dst_path[DOG_PATH_MAX * 2];
    char* e;

    dir = opendir(src_dir);
    if (dir == NULL)
        return;

    while ((entry = readdir(dir)) != NULL) {
        if (dog_dot_or_dotdot(entry->d_name))
            continue;

        e = strrchr(entry->d_name, '.');
        if (e == NULL || strcmp(e, ".inc") != 0)
            continue;

        (void)snprintf(src_path, sizeof(src_path),
            "%s%s%s", src_dir, separator, entry->d_name);

        (void)snprintf(dst_path, sizeof(dst_path),
            "%s%s%s", include_dest, separator, entry->d_name);

        if (path_access(src_path) != 1)
            continue;

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
            }
#else
            if (errno == EXDEV) {
                FILE* src = fopen(src_path, "rb");
                FILE* dst = fopen(dst_path, "wb");

                if (src && dst) {
                    char buf[8192];
                    size_t n;

                    while ((n = fread(buf, 1,
                        sizeof(buf), src)) > 0)
                        fwrite(buf, 1, n, dst);
                }

                if (src) fclose(src);
                if (dst) fclose(dst);

                unlink(src_path);
            }
            else {
                perror("rename");
            }
#endif
        }
        package_try_parsing(dst_path, dst_path);

        pr_color(stdout, DOG_COL_YELLOW,
            " [M] Include %s -> %s\n",
            entry->d_name, dst_path);
    }

    closedir(dir);
}

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
    const char* package_names;
    const char* basename;
    const char* match_root_keywords;
    char		 dest_path[DOG_PATH_MAX * 2];
    char		 dir_part[DOG_PATH_MAX];
    char		 plugin_dir[DOG_PATH_MAX * 2];
    char* basename_lwr;
    size_t		 i;
    size_t		 j;
    int		 found;
    int		 has_prefix;
    int		 move_success;

    _sef_restore();

    found = dog_find_path(dump_path,
        dump_pattern, dump_exclude);
    ++fdir_counts;

    if (found == 0)
        return;

    for (i = 0; i < dogconfig.dog_sef_count; i++) {

        package_names =
            fet_filename(dogconfig.dog_sef_found_list[i]);

        basename =
            fet_basename(dogconfig.dog_sef_found_list[i]);

        basename_lwr = strdup(basename);
        if (basename_lwr == NULL)
            continue;

        for (j = 0; basename_lwr[j] != '\0'; j++)
            basename_lwr[j] =
            tolower((unsigned char)basename_lwr[j]);

        has_prefix = 0;
        match_root_keywords =
            dogconfig.dog_toml_root_patterns;

        while (*match_root_keywords != '\0') {

            while (*match_root_keywords == ' ')
                match_root_keywords++;

            if (*match_root_keywords == '\0')
                break;

            const char* keyword_end =
                match_root_keywords;

            while (*keyword_end != '\0' &&
                *keyword_end != ' ')
                keyword_end++;

            if (keyword_end > match_root_keywords) {
                size_t keyword_len =
                    keyword_end -
                    match_root_keywords;

                if (strncmp(basename_lwr,
                    match_root_keywords,
                    keyword_len) == 0) {
                    has_prefix = 1;
                    break;
                }
            }

            match_root_keywords =
                (*keyword_end != '\0') ?
                keyword_end + 1 :
                keyword_end;
        }

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

            if (dir_exists(dir_part) == 0)
                dog_mkdir_recursive(dir_part);

        }
        else if (has_prefix) {

            (void)snprintf(dest_path,
                sizeof(dest_path),
                "%s%s%s",
                dump_loc, separator,
                package_names);

        }
        else {

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

            if (dir_exists(plugin_dir) == 0)
                dog_mkdir_recursive(plugin_dir);
        }

        move_success = 0;

#ifdef DOG_WINDOWS
        if (MoveFileExA(
            dogconfig.dog_sef_found_list[i],
            dest_path,
            MOVEFILE_REPLACE_EXISTING |
            MOVEFILE_COPY_ALLOWED)) {

            move_success = 1;

        }
        else {
#ifdef DOG_WINDOWS
            BOOL ok;
            ok = CopyFileA(
                dogconfig.dog_sef_found_list[i],
                dest_path,
                FALSE
            );

            if (ok) {
                ok = DeleteFileA(
                    dogconfig.dog_sef_found_list[i]);
            }

            move_success = (ok == TRUE);

            if (!move_success) {
                fprintf(stderr,
                    "Copy/Delete failed: %lu\n",
                    GetLastError());
            }
#else
            if (rename(dogconfig.dog_sef_found_list[i],
                dest_path) == 0) {
                move_success = 1;
            }
            else {
                move_success = 0;
                perror("rename");
            }
#endif
        }
#else
        if (rename(
            dogconfig.dog_sef_found_list[i],
            dest_path) == 0) {
            move_success = 1;
        }
        else {
            move_success = 0;
        }
#endif

        if (move_success == 0) {
            pr_error(stdout,
                "Failed to move: %s",
                basename);
            continue;
        }

        pr_color(stdout, DOG_COL_CYAN,
            " [M] Plugins %s -> %s\n",
            basename, dump_loc);

        (void)snprintf(json_item,
            sizeof(json_item),
            "%s", package_names);

        package_try_parsing(
            json_item, json_item);

        if (dump_root == 1)
            return;

        if (fet_server_env() == false &&
            strfind(
                dogconfig.dog_toml_server_config,
                ".cfg", true)) {

            S_ADD_PLUGIN(
                dogconfig.dog_toml_server_config,
                "plugins", basename);

        }
        else if (fet_server_env() == true &&
            strfind(
                dogconfig.dog_toml_server_config,
                ".json", true)) {

            M_ADD_PLUGIN(
                dogconfig.dog_toml_server_config,
                basename);
        }
    }
}

/**
 * Check if directory contains include files
 */
static int package_has_inc_files(const char* dir_path)
{
    DIR* dir;
    struct dirent* entry;
    struct stat	 st;
    char		 full_path[DOG_PATH_MAX * 3];
    int		 found;

    dir = opendir(dir_path);
    if (dir == NULL)
        return (0);

    found = 0;

    while ((entry = readdir(dir)) != NULL && found == 0) {
        if (dog_dot_or_dotdot(entry->d_name))
            continue;

        (void)snprintf(full_path, sizeof(full_path),
            "%s%s%s", dir_path, separator, entry->d_name);

        if (stat(full_path, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            found = package_has_inc_files(full_path);
        }
        else {
            char* ext;

            ext = strrchr(entry->d_name, '.');
            if (ext != NULL && strcmp(ext, ".inc") == 0)
                found = 1;
        }
    }

    closedir(dir);

    return (found);
}

/**
 * Check if directory or subdirectory contains .dogkeepnormal marker
 */
static int package_dogkeeproot(const char* dir_path)
{
    DIR* dir;
    struct dirent* entry;
    struct stat	 st;
    char		 full_path[DOG_PATH_MAX * 3];
    int		 found;

    dir = opendir(dir_path);
    if (dir == NULL)
        return (0);

    found = 0;

    while ((entry = readdir(dir)) != NULL && found == 0) {
        if (dog_dot_or_dotdot(entry->d_name))
            continue;

        if (strcmp(entry->d_name, ".dogkeepnormal") == 0) {
            (void)snprintf(full_path, sizeof(full_path),
                "%s%s%s", dir_path, separator,
                entry->d_name);

            if (stat(full_path, &st) == 0 &&
                S_ISREG(st.st_mode))
                found = 1;

            continue;
        }

        (void)snprintf(full_path, sizeof(full_path),
            "%s%s%s", dir_path, separator, entry->d_name);

        if (stat(full_path, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode))
            found = package_dogkeeproot(full_path);
    }

    closedir(dir);

    return (found);
}

/**
 * Walk include tree and parse include files
 */
static void package_walk_include_tree(const char* folder_path)
{
    DIR* dir;
    struct dirent* entry;
    struct stat	 st;
    char		 full_path[DOG_PATH_MAX * 3];
    char* ext;

    dir = opendir(folder_path);
    if (dir == NULL)
        return;

    while ((entry = readdir(dir)) != NULL) {

        if (dog_dot_or_dotdot(entry->d_name))
            continue;

        (void)snprintf(full_path,
            sizeof(full_path),
            "%s%s%s",
            folder_path,
            separator,
            entry->d_name);

        if (stat(full_path, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            package_walk_include_tree(full_path);
            continue;
        }

        ext = strrchr(entry->d_name, '.');
        if (ext == NULL)
            continue;

        if (strcmp(ext, ".inc") != 0)
            continue;

        package_try_parsing(full_path, full_path);
    }

    closedir(dir);
}

/**
 * Move include files from subdirectories and parse them
 */
static void package_move_and_parse_includes(const char* folder_path, const char* include_dest)
{
    DIR* dir;
    struct dirent* entry;
    struct stat	 st;
    char		 full_path[DOG_PATH_MAX * 3];
    char		 dest_file[DOG_PATH_MAX * 3];
    char* ext;

    dir = opendir(folder_path);
    if (dir == NULL)
        return;

    while ((entry = readdir(dir)) != NULL) {

        if (dog_dot_or_dotdot(entry->d_name))
            continue;

        (void)snprintf(full_path,
            sizeof(full_path),
            "%s%s%s",
            folder_path,
            separator,
            entry->d_name);

        if (stat(full_path, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            package_move_and_parse_includes(
                full_path, include_dest);
            continue;
        }

        ext = strrchr(entry->d_name, '.');
        if (ext == NULL)
            continue;

        if (strcmp(ext, ".inc") != 0)
            continue;

        (void)snprintf(dest_file,
            sizeof(dest_file),
            "%s%s%s",
            include_dest,
            separator,
            entry->d_name);

        if (path_access(full_path) != 1)
            continue;

        if (rename(full_path,
            dest_file) != 0) {

            pbuf[0] = '\0';

#ifdef DOG_WINDOWS
            if (!MoveFileExA(full_path, dest_file,
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED))
                return;
#else
            if (rename(full_path, dest_file) != 0)
                return;
#endif
        }

        package_try_parsing(
            dest_file, dest_file);

        pr_color(stdout,
            DOG_COL_YELLOW,
            " [M] Include %s -> %s "
            "(from subfolder)\n",
            entry->d_name,
            dest_file);
    }

    closedir(dir);
}

/**
 * Recursive directory removal helper
 */
static int rm_rf(const char* path);

static int rm_rf_dir(const char* dirpath)
{
    DIR* dir;
    struct dirent* dp;
    char full[PATH_MAX];

    dir = opendir(dirpath);
    if (dir == NULL)
        return -1;

    while ((dp = readdir(dir)) != NULL) {
        if (dog_dot_or_dotdot(dp->d_name))
            continue;

        snprintf(full, sizeof(full),
            "%s/%s", dirpath, dp->d_name);

        if (rm_rf(full) == -1)
            fprintf(stderr,
                "rm_rf failed for: %s..: %s",
                full, strerror(errno));
    }

    closedir(dir);
    return rmdir(dirpath);
}

/**
 * Recursive file/directory removal (rm -rf equivalent)
 */
static int rm_rf(const char* path)
{
#ifdef DOG_WINDOWS
    WIN32_FIND_DATAA ffd;
    HANDLE h;

    pbuf[0] = '\0';
    snprintf(pbuf, sizeof(pbuf),
        "%s%s*", path, _PATH_STR_SEP_WIN32);

    h = FindFirstFileA(pbuf, &ffd);
    if (h == INVALID_HANDLE_VALUE)
        return -1;
    do {
        if (dog_dot_or_dotdot(ffd.cFileName))
            continue;

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

        }
        else {
            DeleteFileA(pbuf);
        }

    } while (FindNextFileA(h, &ffd));

    FindClose(h);

    RemoveDirectoryA(path);
#else
    struct stat st;

    if (lstat(path, &st) == -1)
        return -1;

    if (S_ISDIR(st.st_mode))
        return rm_rf_dir(path);

    return unlink(path);
#endif
}

/**
 * Move files from package directory to appropriate locations
 */
static void package_move_files(const char* package_dir,
    const char* package_loc)
{
    char		 the_path[DOG_PATH_MAX * 2];
    char		 includes[DOG_PATH_MAX];
    char		 plugins[DOG_PATH_MAX * 2];
    char		 components[DOG_PATH_MAX * 2];
    char		 subdir_path[DOG_PATH_MAX * 2];
    char		 include_dest[DOG_PATH_MAX * 2];
    char		 dest_file[DOG_PATH_MAX * 3];
    char		 dest_dir[DOG_PATH_MAX * 3];
    char		 keeproot_path[DOG_PATH_MAX * 2];
    char		 pawno_include[DOG_PATH_MAX * 2];
    char		 qawno_include[DOG_PATH_MAX * 2];
    char		 new_folder_path[DOG_PATH_MAX * 4];
    char* folder_name;
    struct stat	 dir_st;
    struct dirent* entry;
    DIR* package_dir_handle;
    char		 folders_to_move[100][DOG_PATH_MAX];
    int		 folder_count;
    int		 has_special_include;
    int		 has_dogkeeproot;
    int		 i;
    int		 server_type;

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
    }

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

    if (server_type == false)
        (void)strlcpy(includes,
            "pawno/include", sizeof(includes));
    else
        (void)strlcpy(includes,
            "qawno/include", sizeof(includes));

    (void)snprintf(include_dest,
        sizeof(include_dest),
        "%s%s%s",
        package_loc, separator, includes);

    if (dir_exists(include_dest) == 0)
        dog_mkdir_recursive(include_dest);

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
    }

    if (dir_exists(qawno_include)) {
        has_special_include = 1;
        package_move_includes_from_dir(
            qawno_include, include_dest);
    }

    /* Scan package directory for subfolders */
    package_dir_handle = opendir(package_dir);
    if (package_dir_handle == NULL) {
        pr_error(stdout,
            "Failed to open directory: %s",
            package_dir);
        return;
    }

    while ((entry =
        readdir(package_dir_handle)) != NULL) {

        if (dog_dot_or_dotdot(entry->d_name))
            continue;

        (void)snprintf(the_path,
            sizeof(the_path),
            "%s%s%s",
            package_dir,
            separator,
            entry->d_name);

        if (stat(the_path, &dir_st) != 0)
            continue;

        if (!S_ISDIR(dir_st.st_mode))
            continue;

        if (strcmp(entry->d_name,
            "components") == 0 ||
            strcmp(entry->d_name,
                "plugins") == 0 ||
            strcmp(entry->d_name,
                "pawno") == 0 ||
            strcmp(entry->d_name,
                "qawno") == 0)
            continue;

        (void)snprintf(subdir_path,
            sizeof(subdir_path),
            "%s%s%s",
            package_dir,
            separator,
            entry->d_name);

        if (package_dogkeeproot(
            subdir_path)) {

            pr_color(stdout,
                DOG_COL_GREEN,
                " [K] Found .dogkeepnormal "
                "in %s\n",
                entry->d_name);

            package_move_and_parse_includes(
                subdir_path,
                include_dest);
            continue;
        }

        if (!has_dogkeeproot &&
            package_has_inc_files(
                subdir_path) &&
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
        }
    }

    closedir(package_dir_handle);

    /* Move include folders if no special handling */
    if (!has_special_include &&
        !has_dogkeeproot) {

        for (i = 0; i < folder_count; i++) {

            folder_name =
                strrchr(
                    folders_to_move[i],
                    separator[0]);

            if (folder_name != NULL)
                folder_name++;
            else
                folder_name =
                folders_to_move[i];

            (void)snprintf(dest_dir,
                sizeof(dest_dir),
                "%s%s%s",
                include_dest,
                separator,
                folder_name);

            if (dir_exists(dest_dir))
                rm_rf(dest_dir);

#ifdef DOG_WINDOWS
            if (!MoveFileExA(folders_to_move[i],
                include_dest,
                MOVEFILE_REPLACE_EXISTING |
                MOVEFILE_COPY_ALLOWED)) {

                fprintf(stderr,
                    "MoveFileEx failed: %lu\n",
                    GetLastError());
            }
            else {
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
            }
#else
            if (rename(folders_to_move[i],
                include_dest) != 0) {
                perror("rename");
            }
            else {
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
            }
#endif
        }
    }

    /* Handle plugins directory */
    if (dir_exists(plugins)) {

        char plugin_dest[DOG_PATH_MAX];

        (void)snprintf(plugin_dest,
            sizeof(plugin_dest),
            "%s%splugins",
            package_loc,
            separator);

        if (dir_exists(plugin_dest) == 0)
            dog_mkdir_recursive(
                plugin_dest);

        if (strcmp(opr, "windows") == 0)
            package_dump_file_type(
                plugins,
                "*.dll",
                NULL,
                plugin_dest,
                "",
                0);
        else if (strcmp(opr, "linux") == 0)
            package_dump_file_type(
                plugins,
                "*.so",
                NULL,
                plugin_dest,
                "",
                0);
    }

    putchar('\n');
    destroy_arch_dir(package_dir);
}

/**
 * Apply dependencies after download
 */
static void dog_apply_depends(const char* depends_name,
    const char* depends_location)
{
    char	 dep_name[DOG_PATH_MAX];
    char	 package_dir[DOG_PATH_MAX];
    char	 full_dest_path[DOG_PATH_MAX * 2];
    char* ext;

    (void)snprintf(dep_name, sizeof(dep_name),
        "%s", depends_name);

#if defined(_DBG_PRINT)
    println(stdout, "dep_name: %s", dep_name);
#endif

    /* Remove archive ext */
    if ((ext = strstr(dep_name, ".tar.gz")) != NULL)
        *ext = '\0';
    else if ((ext = strstr(dep_name, ".tar")) != NULL)
        *ext = '\0';
    else if ((ext = strstr(dep_name, ".zip")) != NULL)
        *ext = '\0';

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
        if (dir_exists(full_dest_path) == 0)
            dog_mkdir_recursive(full_dest_path);

        (void)snprintf(full_dest_path,
            sizeof(full_dest_path),
            "%s/plugins",
            depends_location);
        if (dir_exists(full_dest_path) == 0)
            dog_mkdir_recursive(full_dest_path);

    }
    else {
        (void)snprintf(full_dest_path,
            sizeof(full_dest_path),
            "%s/qawno/include",
            depends_location);
        if (dir_exists(full_dest_path) == 0)
            dog_mkdir_recursive(full_dest_path);

        (void)snprintf(full_dest_path,
            sizeof(full_dest_path),
            "%s/plugins",
            depends_location);
        if (dir_exists(full_dest_path) == 0)
            dog_mkdir_recursive(full_dest_path);

        (void)snprintf(full_dest_path,
            sizeof(full_dest_path),
            "%s/components",
            depends_location);
        if (dir_exists(full_dest_path) == 0)
            dog_mkdir_recursive(full_dest_path);
    }

    package_move_files(package_dir, depends_location);
}

/**
 * Main function to install dependencies
 */
void
dog_install_depends(const char* packages, const char* branch, const char* where)
{
    char			 buffer[1024] = { 0 }, package_url[1024] = { 0 },
        package_name[DOG_PATH_MAX] = { 0 };
    char* token = NULL, * current_dir = NULL,
        * target_dir = NULL;
    static char* initial_location = NULL;
    const char* dependencies[MAX_DEPENDS] = { 0 };
    struct _repositories	 repo;
    int			 dep_count = 0, i;
    static int   location_ready = false;
#ifdef DOG_WINDOWS
    WIN32_FIND_DATAA ffd;
    HANDLE           hFind;
    char             search[] = "*";
#endif
    memset(dependencies, 0, sizeof(dependencies));

    installing_package = true;

    if (!packages || !*packages) {
        pr_color(stdout, DOG_COL_RED, "");
        print("no valid dependencies to install!\t\t[X]\n");
        goto done;
    }

    if (strlen(packages) >= sizeof(buffer)) {
        pr_color(stdout, DOG_COL_RED, "");
        print("packages too long!\t\t[X]\n");
        goto done;
    }

    (void)snprintf(buffer, sizeof(buffer), "%s", packages);

    /* Parse package list */
    token = strtok(buffer, " ");
    while (token && dep_count < MAX_DEPENDS) {
        dependencies[dep_count++] = token;
        token = strtok(NULL, " ");
    }

    if (!dep_count) {
        pr_color(stdout, DOG_COL_RED, "");
        print("no valid dependencies to install!\t\t[X]\n");
        goto done;
    }

    /* Install each dependency */
    for (i = 0; i < dep_count; i++) {
        if (!package_parse_repo(dependencies[i], &repo)) {
            pr_color(stdout, DOG_COL_RED, "");
            printf("invalid repo format: %s\t\t[X]\n",
                dependencies[i]);
            continue;
        }

        /* Handle GitHub repos */
        if (!strcmp(repo.host, "github")) {
            if (!package_handle_repo(&repo, package_url,
                sizeof(package_url), branch)) {
                pr_color(stdout, DOG_COL_RED, "");
                printf("repo not found: %s\t\t[X]\n",
                    dependencies[i]);
                continue;
            }
        }
        else {
            /* Handle other platforms */
            package_build_repo_url(&repo, 0,
                package_url, sizeof(package_url));
            if (!package_url_checking(package_url,
                dogconfig.dog_toml_github_tokens)) {
                pr_color(stdout, DOG_COL_RED, "");
                printf("repo not found: %s\t\t[X]\n",
                    dependencies[i]);
                continue;
            }
        }

        /* Generate package name from URL */
        if (strrchr(package_url, _PATH_CHR_SEP_POSIX)
            && *(strrchr(package_url, _PATH_CHR_SEP_POSIX) + 1)) {

            (void)snprintf(package_name, sizeof(package_name), "%s",
                strrchr(package_url, _PATH_CHR_SEP_POSIX) + 1);

            if (!strend(package_name, ".tar.gz", true) &&
                !strend(package_name, ".tar", true) &&
                !strend(package_name, ".zip", true))
            {
                (void)snprintf(package_name + strlen(package_name),
                    sizeof(package_name) - strlen(package_name),
                    ".zip");
            }
        }
        else {
            (void)snprintf(package_name, sizeof(package_name),
                "%s.tar.gz", repo.repo);
        }

        if (!*package_name) {
            pr_color(stdout, DOG_COL_RED, "");
            printf("invalid repo name: %s\t\t[X]\n",
                package_url);
            continue;
        }

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
                putchar('\n');

#ifdef DOG_LINUX
                /* Show directory listing on Linux */
                int tree_ret = -1;
                tree_ret = system("tree > /dev/null 2>&1");
                if (!tree_ret) {
                    system("tree .");
                }
                else {
                    DIR* d = opendir(".");
                    if (d) {
                        struct dirent* de;
                        struct stat st;
                        char path[DOG_PATH_MAX];

                        while ((de = readdir(d)) != NULL) {
                            if (de->d_name[0] == '.')
                                continue;

                            (void)snprintf(path, sizeof(path), "%s", de->d_name);
                            if (lstat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
                                printf("%s\n", de->d_name);
                            }
                        }
                        closedir(d);
                    }
                }
#else
                /* Show directory listing on Windows */
                hFind = FindFirstFileA(search, &ffd);
                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                            strcmp(ffd.cFileName, ".") != 0 &&
                            strcmp(ffd.cFileName, "..") != 0) {
                            printf("%s\n", ffd.cFileName);
                        }
                    } while (FindNextFileA(hFind, &ffd));
                    FindClose(hFind);
                }
#endif

                putchar('\n');

                /* Prompt for installation directory */
                printf(DOG_COL_BCYAN
                    "Where do you want to install %s? "
                    "(enter for: %s)" DOG_COL_DEFAULT,
                    package_name, dog_procure_pwd());

                target_dir = readline(" ");
                if (target_dir[0] == '\0' || target_dir[0] == '.') {
                    current_dir = dog_procure_pwd();
                    initial_location = strdup(current_dir);
                    if (current_dir)
                        dog_apply_depends(package_name,
                            current_dir);
                    dog_free(target_dir);
                }
                else {
                    if (dir_exists(target_dir) == 0)
                        dog_mkdir_recursive(target_dir);
                    initial_location = strdup(target_dir);
                    dog_apply_depends(package_name,
                        target_dir);
                    dog_free(target_dir);
                }

                location_ready = true;
            }
            else {
                dog_apply_depends(package_name, initial_location);
            }
        }
        else {
            if (dir_exists(where) == 0)
                dog_mkdir_recursive(where);
            dog_apply_depends(package_name, where);
        }
    }

done:
    return;
}