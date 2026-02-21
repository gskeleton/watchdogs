#pragma once

#define	URL_GITHUB_API		"https://api.github.com/"
#define	URL_GITHUB_RAW		"https://github.com/"
#define	URL_GITLAB_RAW		"https://gitlab.com/"
#define	URL_GITEA_RAW		"https://gitea.com/"
#define	URL_SF_RAW		    "https://sourceforge.net/"

#define	URL_GH_RELEASE_TAG	    URL_GITHUB_API     "repos/%s/%s/releases/tags/%s"
#define	URL_GH_RELEASE_LATEST	URL_GITHUB_API     "repos/%s/%s/releases/latest"
#define	URL_GH_ARCHIVE_TAG	    URL_GITHUB_RAW     "%s/%s/archive/refs/tags/%s.tar.gz"
#define	URL_GH_ARCHIVE_TAG_ZIP	URL_GITHUB_RAW     "%s/%s/archive/refs/tags/%s.zip"
#define	URL_GH_ARCHIVE_BRANCH	URL_GITHUB_RAW     "%s/%s/archive/refs/heads/%s.zip"
#define	URL_GL_ARCHIVE		    URL_GITLAB_RAW     "%s/%s/-/archive/%s/%s-%s.tar.gz"
#define	URL_GA_ARCHIVE		    URL_GITEA_RAW      "%s/%s/archive/%s.tar.gz"
#define	URL_SF_DOWNLOAD		    URL_SF_RAW         "projects/%s/files/latest/download"
