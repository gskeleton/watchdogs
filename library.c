#include  "utils.h"
#include  "units.h"
#include  "archive.h"
#include  "curl.h"
#include  "debug.h"
#include  "library.h"

_Bool
installing_pawncc = false;
_Bool
installing_pcc_posix = false;

static char
library_options_list(const char* title, const char** items,
  const char* keys, int counts)
{
  /* Validate input parameters */
  if (!title || !items || !keys || !counts) {
    return (0);
  } /* if */

  /* Display title if provided */
  if (title[0] != '\0') {
    char pbuf[strlen(title) + 45 + 1];
    int len = snprintf(pbuf, sizeof(pbuf),
      "\033[1;33m== %s ==\033[0m\n", title);
    
    if (len > 0 && len < (int)sizeof(pbuf)) {
      fwrite(pbuf, 1, len, stdout);
      fflush(stdout);
    } /* if */
  } /* if */

  /* Display all options */
  int i;
  for (i = 0; i < counts; i++) {
    char pbuf[DOG_PATH_MAX + 1] = {0};
    
    /* Validate item at index */
    if (items[i] == NULL) {
      pr_warning(stdout, "library_options_list: items[%d] is NULL", i);
      continue;
    } /* if */
    
    int len = snprintf(pbuf, sizeof(pbuf),
      "  %c) %s\n", keys[i], items[i]);
      
    if (len > 0 && len < (int)sizeof(pbuf)) {
      fwrite(pbuf, 1, len, stdout);
      fflush(stdout);
    } /* if */
  } /* for */

  /* Interactive selection loop */
  while (true) {
    char* input = NULL;
    char choice = '\0';
    int k;
    
    fputs(LR_CYAN ">" LR_DEFAULT, stdout);
    input = readline(" ");
    
    if (!input) {
      pr_info(stdout, "library_options_list: readline returned NULL");
      continue;
    } /* if */

    /* Process single character input */
    if (strlen(input) == 1) {
      choice = input[0];
      
      /* Search for matching key */
      for (k = 0; k < counts; k++) {
        if (choice == keys[k] || choice == (keys[k] + 32)) {
          dog_free(input);
          pr_info(stdout, "library_options_list: selected option %c", choice);
          return (choice);
        } /* if */
      } /* for */
    } /* if */

    /* Invalid selection */
    puts("Invalid selection. Please try again.\n");
    dog_free(input);
  } /* while */
  
  /* Should never reach here */
  return (0);
} /* library_options_list */

static int
pawncc_handle_termux_installation(void)
{
  const char* items[] = {
    "Pawncc 3.10.7   - experimental"
  };
  const char   keys[] = { 'A' };
  int ret = 0;
  char sel = 0;
  const char* machine = NULL;

  /* Get user selection */
  sel = library_options_list("Select PawnCC Version", items, keys, 1);
  if (!sel) {
    pr_error(stdout, "pawncc_handle_termux_installation: no selection made");
    return (0);
  } /* if */

  pr_info(stdout, "pawncc_handle_termux_installation: selected %c", sel);

  installing_pawncc = true;
  installing_pcc_posix = true;

#ifdef DOG_LINUX
  struct utsname u;
  if (uname(&u) != 0) {
    pr_error(stdout, "pawncc_handle_termux_installation: uname failed: %s", strerror(errno));
    return 1;
  } /* if */
  machine = u.machine;
#else
  machine = "unknown";
  pr_info(stdout, "pawncc_handle_termux_installation: not on Linux, machine set to unknown");
#endif

  pr_info(stdout, "pawncc_handle_termux_installation: machine architecture: %s", machine);

  /* Download appropriate version based on architecture */
  if (sel == 'A' || sel == 'a') {
    /* Clean up existing files */
    if (path_exists("pawncc-termux-37.zip") == 1) {
      remove("pawncc-termux-37.zip");
      pr_info(stdout, "pawncc_handle_termux_installation: removed existing pawncc-termux-37.zip");
    } /* if */
    
    if (path_exists("pawncc-termux-37") == 1) {
      remove("pawncc-termux-37");
      pr_info(stdout, "pawncc_handle_termux_installation: removed existing pawncc-termux-37");
    } /* if */
    
    /* Download based on architecture */
    if (strcmp(machine, "aarch64") == 0) {
      pr_info(stdout, "Downloading PawnCC for aarch64..");
      ret = dog_download_file(
        "https://github.com/gskeleton/pawn/releases/download/v3.10.7/pawn-3.10.7-arm64-v8a.zip",
        "pawncc-termux-37.zip"
      );
    } else if (strcmp(machine, "armv7l") == 0) {
      pr_info(stdout, "Downloading PawnCC for armv7l..");
      ret = dog_download_file(
        "https://github.com/gskeleton/pawn/releases/download/v3.10.7/pawnc-3.10.7-armeabi-v7a.zip",
        "pawncc-termux-37.zip"
      );
    } else {
      pr_info(stdout, "Downloading PawnCC for aarch64 (default)..");
      ret = dog_download_file(
        "https://github.com/gskeleton/pawn/releases/download/v3.10.7/pawn-3.10.7-arm64-v8a.zip",
        "pawncc-termux-37.zip"
      );
    } /* if */
  }
  else {
    pr_warning(stdout, "pawncc_handle_termux_installation: unknown selection %c", sel);
  } /* if */

  /* Check download result */
  if (ret != 0) {
    pr_error(stdout, "pawncc_handle_termux_installation: download failed with code %d", ret);
    return ret;
  } /* if */

  pr_info(stdout, "pawncc_handle_termux_installation: installation initiated successfully");
  return (0);
} /* pawncc_handle_termux_installation */

static int
pawncc_handle_standard_installation(const char* platform)
{
  const char* versions[] = {
    "PawnCC 3.10.11  - new",
    "PawnCC 3.10.10  - new",
    "PawnCC 3.10.7   - stable",
    "PawnCC 3.10.7   - experimental"
  };
  const char   keys[] = { 'A', 'B', 'C', 'D' };
  const char* vernums[] = {
    "3.10.11", "3.10.10", "3.10.7", "3.10.7"
  };
  int idx = -1;
  char sel = 0;
  const char* library_repo_base = NULL;
  const char* archive_ext = NULL;
  char url[512] = {0};
  char filename[128] = {0};
  int ret = 0;

  /* Validate platform parameter */
  if (platform == NULL) {
    pr_error(stdout, "pawncc_handle_standard_installation: platform is NULL");
    return (-1);
  } /* if */

  /* Check if platform is supported */
  if (strcmp(platform, "linux") != 0 &&
    strcmp(platform, "windows") != 0) {
    pr_error(stdout, "Unsupported platform: %s", platform);
    return (-1);
  } /* if */

  pr_info(stdout, "pawncc_handle_standard_installation: platform: %s", platform);

  /* Get user selection */
  sel = library_options_list("Select PawnCC Version", versions, keys, 4);
  if (!sel) {
    pr_error(stdout, "pawncc_handle_standard_installation: no selection made");
    return (0);
  } /* if */

  /* Determine index from selection */
  if (sel >= 'A' && sel <= 'D') {
    idx = sel - 'A';
  } else if (sel >= 'a' && sel <= 'd') {
    idx = sel - 'a';
  } /* if */
  
  if (idx < 0 || idx >= 4) {
    pr_error(stdout, "pawncc_handle_standard_installation: invalid selection index %d", idx);
    return (0);
  } /* if */

  pr_info(stdout, "pawncc_handle_standard_installation: selected index %d (%s)", idx, versions[idx]);

  /* Set repository base based on version type */
  if (idx == 3) {
    library_repo_base = "https://github.com/gskeleton/pawn";
    pr_info(stdout, "pawncc_handle_standard_installation: using experimental repo");
  } else {
    library_repo_base = "https://github.com/gskeleton/gcompiler";
    pr_info(stdout, "pawncc_handle_standard_installation: using stable repo");
  } /* if */
  
  /* Set archive extension based on platform */
  if (strcmp(platform, "linux") == 0) {
    archive_ext = "tar.gz";
  } else {
    archive_ext = "zip";
  } /* if */

  /* Build URL and filename */
  (void)snprintf(url, sizeof(url),
    "%s/releases/download/v%s/pawnc-%s-%s.%s",
    library_repo_base, vernums[idx], vernums[idx], platform,
    archive_ext);

  (void)snprintf(filename, sizeof(filename),
    "pawnc-%s-%s.%s", vernums[idx], platform, archive_ext);

  pr_info(stdout, "pawncc_handle_standard_installation: URL: %s", url);
  pr_info(stdout, "pawncc_handle_standard_installation: filename: %s", filename);

  /* Set installation flags */
  installing_pawncc = true;
  if (strcmp(platform, "linux") == 0) {
    installing_pcc_posix = true;
    pr_info(stdout, "pawncc_handle_standard_installation: Linux installation flagged");
  } /* if */

  /* Download file */
  ret = dog_download_file(url, filename);
  
  if (ret != 0) {
    pr_error(stdout, "pawncc_handle_standard_installation: download failed with code %d", ret);
  } /* if */

  return (ret);
} /* pawncc_handle_standard_installation */

int
dog_install_pawncc(const char* platform)
{
  int ret = 0;
  _Bool stat_false = !unit_selection_state;

  pr_info(stdout, "dog_install_pawncc: starting installation for platform: %s", 
           platform ? platform : "NULL");

  minimal_debugging();

  /* Validate platform parameter */
  if (!platform) {
    pr_error(stdout, "Platform parameter is NULL");
    if (stat_false) {
      return (0);
    } /* if */
    return (-1);
  } /* if */

  /* Handle different platform types */
  if (strcmp(platform, "termux") == 0) {
    pr_info(stdout, "dog_install_pawncc: handling Termux installation");
    ret = pawncc_handle_termux_installation();

  loop_ipcc:
    if (stat_false) {
      pr_info(stdout, "dog_install_pawncc: stat_false true, looping");
      goto loop_ipcc;
    } else if (ret == 0) {
      pr_info(stdout, "dog_install_pawncc: Termux installation successful");
      return (0);
    } /* if */
  } else {
    pr_info(stdout, "dog_install_pawncc: handling standard installation for %s", platform);
    ret = pawncc_handle_standard_installation(platform);

  loop_ipcc2:
    if (stat_false) {
      pr_info(stdout, "dog_install_pawncc: stat_false true, looping");
      goto loop_ipcc2;
    } else if (ret == 0) {
      pr_info(stdout, "dog_install_pawncc: standard installation successful");
      return (0);
    } /* if */
  } /* if */

  pr_info(stdout, "dog_install_pawncc: installation completed with ret=%d", ret);
  return (ret);
} /* dog_install_pawncc */

int
dog_install_server(const char* platform)
{
  int ret = 0;
  char sel = 0;
  int idx = -1;
  struct library_version_info* chosen = NULL;
  const char* url = NULL;
  const char* filename = NULL;

  pr_info(stdout, "dog_install_server: starting server installation for platform: %s", 
           platform ? platform : "NULL");

  minimal_debugging();

  installing_pawncc = false;

  /* Validate platform parameter */
  if (platform == NULL) {
    pr_error(stdout, "dog_install_server: platform is NULL");
    return (-1);
  } /* if */

  /* Check if platform is supported */
  if (strcmp(platform, "linux") != 0 &&
    strcmp(platform, "windows") != 0 &&
    strcmp(platform, "termux") != 0) {
    pr_error(stdout, "Unsupported platform: %s", platform);
    return (-1);
  } /* if */

  pr_info(stdout, "dog_install_server: platform %s is supported", platform);

  /* Server version list for Linux/Windows */
  const char* items[] = {
    "SA-MP 0.3.DL R1",
    "SA-MP 0.3.7 R3",
    "SA-MP 0.3.7 R2-2-1",
    "SA-MP 0.3.7 R2-1-1",
    "OPEN.MP v1.5.8.3079 (Static SSL)",
    "OPEN.MP v1.5.8.3079 (Dynamic SSL)",
    "OPEN.MP v1.4.0.2779 (Static SSL)",
    "OPEN.MP v1.4.0.2779 (Dynamic SSL)",
    "OPEN.MP v1.3.1.2748 (Static SSL)",
    "OPEN.MP v1.3.1.2748 (Dynamic SSL)",
    "OPEN.MP v1.2.0.2670 (Static SSL)",
    "OPEN.MP v1.2.0.2670 (Dynamic SSL)",
    "OPEN.MP v1.1.0.2612 (Static SSL)",
    "OPEN.MP v1.1.0.2612 (Dynamic SSL)"
  };

  const char   keys[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
    'M', 'N'
  };

  pr_info(stdout, "dog_install_server: showing server selection menu for %s", platform);

  /* Get user selection */
  sel = library_options_list("Select SA-MP / open.mp Server", items, keys, 14);
  if (!sel) {
    pr_error(stdout, "dog_install_server: no selection made");
    return (0);
  } /* if */

  /* Determine index from selection */
  if (sel >= 'A' && sel <= 'N') {
    idx = sel - 'A';
  } else if (sel >= 'a' && sel <= 'n') {
    idx = sel - 'a';
  } /* if */
  
  if (idx < 0 || idx >= 14) {
    pr_error(stdout, "dog_install_server: invalid selection index %d", idx);
    return (0);
  } /* if */

  pr_info(stdout, "dog_install_server: selected index %d (%s)", idx, items[idx]);

  /* Server version information */
  struct library_version_info versions[] = {
    {
      'A', "SA-MP 0.3.DL R1",
      "https://github.com/"
      "KrustyKoyle/"
      "files.sa-mp.com-Archive/raw/refs/heads/master/samp03DLsvr_R1.tar.gz",
      "samp03DLsvr_R1.tar.gz",
      "https://github.com/"
      "KrustyKoyle/"
      "files.sa-mp.com-Archive/raw/refs/heads/master/samp03DL_svr_R1_win32.zip",
      "samp03DL_svr_R1_win32.zip"
    },
    {
      'B', "SA-MP 0.3.7 R3",
      "https://github.com/"
      "KrustyKoyle/"
      "files.sa-mp.com-Archive/raw/refs/heads/master/samp037svr_R3.tar.gz",
      "samp037svr_R3.tar.gz",
      "https://github.com/"
      "KrustyKoyle/"
      "files.sa-mp.com-Archive/raw/refs/heads/master/samp037_svr_R3_win32.zip",
      "samp037_svr_R3_win32.zip"
    },
    {
      'C', "SA-MP 0.3.7 R2-2-1",
      "https://github.com/"
      "KrustyKoyle/"
      "files.sa-mp.com-Archive/raw/refs/heads/master/samp037svr_R2-2-1.tar.gz",
      "samp037svr_R2-2-1.tar.gz",
      "https://github.com/"
      "KrustyKoyle/"
      "files.sa-mp.com-Archive/raw/refs/heads/master/samp037_svr_R2-1-1_win32.zip",
      "samp037_svr_R2-2-1_win32.zip"
    },
    {
      'D', "SA-MP 0.3.7 R2-1-1",
      "https://github.com/"
      "KrustyKoyle/"
      "files.sa-mp.com-Archive/raw/refs/heads/master/samp037svr_R2-1.tar.gz",
      "samp037svr_R2-1.tar.gz",
      "https://github.com/"
      "KrustyKoyle/"
      "files.sa-mp.com-Archive/raw/refs/heads/master/samp037_svr_R2-1-1_win32.zip",
      "samp037_svr_R2-1-1_win32.zip"
    },
    {
      'E', "OPEN.MP v1.5.8.3079 (Static SSL)",
      "https://github.com/"
      "openmultiplayer/"
      "open.mp/releases/download/v1.5.8.3079/open.mp-linux-x86.tar.gz",
      "open.mp-linux-x86.tar.gz",
      "https://github.com/"
      "openmultiplayer/"
      "open.mp/releases/download/v1.5.8.3079/open.mp-win-x86.zip",
      "open.mp-win-x86.zip"
    },
    {
      'F', "OPEN.MP v1.5.8.3079 (Dynamic SSL)",
      "https://github.com/"
      "openmultiplayer/"
      "open.mp/releases/download/v1.5.8.3079/open.mp-linux-x86-dynssl.tar.gz",
      "open.mp-linux-x86-dynssl.tar.gz",
      "https://github.com/"
      "openmultiplayer/"
      "open.mp/releases/download/v1.5.8.3079/open.mp-win-x86.zip",
      "open.mp-win-x86.zip"
    },
    {
      'G', "OPEN.MP v1.4.0.2779 (Static SSL)",
      "https://github.com/"
      "openmultiplayer/"
      "open.mp/releases/download/v1.4.0.2779/open.mp-linux-x86.tar.gz",
      "open.mp-linux-x86.tar.gz",
      "https://github.com/"
      "openmultiplayer/"
      "open.mp/releases/download/v1.4.0.2779/open.mp-win-x86.zip",
      "open.mp-win-x86.zip"
    },
    {
      'H', "OPEN.MP v1.4.0.2779 (Dynamic SSL)",
      "https://github.com/"
      "openmultiplayer/"
      "open.mp/releases/download/v1.4.0.2779/open.mp-linux-x86-dynssl.tar.gz",
      "open.mp-linux-x86-dynssl.tar.gz",
      "https://github.com/"
      "openmultiplayer/"
      "open.mp/releases/download/v1.4.0.2779/open.mp-win-x86.zip",
      "open.mp-win-x86.zip"
    },
    {
      'I', "OPEN.MP v1.3.1.2748 (Static SSL)",
      "https://github.com/"
      "openmultiplayer/"
      "open.mp/releases/download/v1.3.1.2748/open.mp-linux-x86.tar.gz",
      "open.mp-linux-x86.tar.gz",
      "https://github.com/"
      "openmultiplayer/"
      "open.mp/releases/download/v1.3.1.2748/open.mp-win-x86.zip",
      "open.mp-win-x86.zip"
    },
    {
      'J', "OPEN.MP v1.3.1.2748 (Dynamic SSL)",
      "https://github.com/"
      "openmultiplayer/"
      "open.mp/releases/download/v1.3.1.2748/open.mp-linux-x86-dynssl.tar.gz",
      "open.mp-linux-x86-dynssl.tar.gz",
      "https://github.com/"
      "openmultiplayer/"
      "open.mp/releases/download/v1.3.1.2748/open.mp-win-x86.zip",
      "open.mp-win-x86.zip"
    },
    {
      'K', "OPEN.MP v1.2.0.2670 (Static SSL)",
      "https://github.com/"
      "openmultiplayer/"
      "open.mp/releases/download/v1.2.0.2670/open.mp-linux-x86.tar.gz",
      "open.mp-linux-x86.tar.gz",
      "https://github.com/"
      "openmultiplayer/"
      "open.mp/releases/download/v1.2.0.2670/open.mp-win-x86.zip",
      "open.mp-win-x86.zip"
    },
    {
      'L', "OPEN.MP v1.2.0.2670 (Dynamic SSL)",
      "https://github.com/"
      "openmultiplayer/"
      "open.mp/releases/download/v1.2.0.2670/open.mp-linux-x86-dynssl.tar.gz",
      "open.mp-linux-x86-dynssl.tar.gz",
      "https://github.com/"
      "openmultiplayer/"
      "open.mp/releases/download/v1.2.0.2670/open.mp-win-x86.zip",
      "open.mp-win-x86.zip"
    },
    {
      'M', "OPEN.MP v1.1.0.2612 (Static SSL)",
      "https://github.com/"
      "openmultiplayer/"
      "open.mp/releases/download/v1.1.0.2612/open.mp-linux-x86.tar.gz",
      "open.mp-linux-x86.tar.gz",
      "https://github.com/"
      "openmultiplayer/"
      "open.mp/releases/download/v1.1.0.2612/open.mp-win-x86.zip",
      "open.mp-win-x86.zip"
    },
    {
      'N', "OPEN.MP v1.1.0.2612 (Dynamic SSL)",
      "https://github.com/"
      "openmultiplayer/"
      "open.mp/releases/download/v1.1.0.2612/open.mp-linux-x86-dynssl.tar.gz",
      "open.mp-linux-x86-dynssl.tar.gz",
      "https://github.com/"
      "openmultiplayer/"
      "open.mp/releases/download/v1.1.0.2612/open.mp-win-x86.zip",
      "open.mp-win-x86.zip"
    }
  };

  /* Get chosen version */
  chosen = &versions[idx];

  /* Select appropriate URL based on platform */
  if (strcmp(platform, "linux") == 0) {
    url = chosen->linux_url;
    filename = chosen->linux_file;
    pr_info(stdout, "dog_install_server: using Linux URL: %s", url);
  } else {
    url = chosen->windows_url;
    filename = chosen->windows_file;
    pr_info(stdout, "dog_install_server: using Windows URL: %s", url);
  } /* if */

  /* Download the file */
  ret = dog_download_file(url, filename);
  
  if (ret != 0) {
    pr_error(stdout, "dog_install_server: download failed with code %d", ret);
  } /* if */

done:
  pr_info(stdout, "dog_install_server: installation completed with ret=%d", ret);
  return (ret);
} /* dog_install_server */