#pragma once

/* GitHub API endpoint for programmatic access */
#define	URL_GITHUB_API		"https://api.github.com/"

/* GitHub raw content and web interface base URL */
#define	URL_GITHUB_RAW		"https://github.com/"

/* GitLab base URL for raw content and web interface */
#define	URL_GITLAB_RAW		"https://gitlab.com/"

/* Gitea base URL (open-source Git hosting platform) */
#define	URL_GITEA_RAW		"https://gitea.com/"

/* SourceForge base URL for project hosting and downloads */
#define	URL_SF_RAW		    "https://sourceforge.net/"

/* GitHub API URL to fetch specific release by tag name
 *  Parameters: owner, repository, tag_name */
#define	URL_GH_RELEASE_TAG	    URL_GITHUB_API     "repos/%s/%s/releases/tags/%s"

/* GitHub API URL to fetch latest release information
 *  Parameters: owner, repository */
#define	URL_GH_RELEASE_LATEST	URL_GITHUB_API     "repos/%s/%s/releases/latest"

/* GitHub URL to download source archive for specific tag (tar.gz format)
 *  Parameters: owner, repository, tag_name */
#define	URL_GH_ARCHIVE_TAG	    URL_GITHUB_RAW     "%s/%s/archive/refs/tags/%s.tar.gz"

/* GitHub URL to download source archive for specific tag (zip format)
 *  Parameters: owner, repository, tag_name */
#define	URL_GH_ARCHIVE_TAG_ZIP	URL_GITHUB_RAW     "%s/%s/archive/refs/tags/%s.zip"

/* GitHub URL to download source archive for specific branch (zip format)
 *  Parameters: owner, repository, branch_name */
#define	URL_GH_ARCHIVE_BRANCH	URL_GITHUB_RAW     "%s/%s/archive/refs/heads/%s.zip"

/* GitLab URL to download source archive for specific tag/branch
 *  Parameters: owner, repository, tag/branch name, repository, tag/branch name (duplicated due to GitLab URL format) */
#define	URL_GL_ARCHIVE		    URL_GITLAB_RAW     "%s/%s/-/archive/%s/%s-%s.tar.gz"

/* Gitea URL to download source archive for specific tag/branch
 *  Parameters: owner, repository, tag/branch name */
#define	URL_GA_ARCHIVE		    URL_GITEA_RAW      "%s/%s/archive/%s.tar.gz"

/* SourceForge URL to download latest release file (auto-redirects to latest version)
 *  Parameters: project_name */
#define	URL_SF_DOWNLOAD		    URL_SF_RAW         "projects/%s/files/latest/download"