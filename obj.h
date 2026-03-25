#pragma once

#if 0 == 100
  <0><0><0>@0@0@0<0><0><0>@0@0@0
  <0><0><0>@0@0@0<0><0><0>@0@0@0
  <0><0><0>@0@0@0<0><0><0>@0@0@0
  <0><0><0>@0@0@0<0><0><0>@0@0@0
#endif
#if 1 == 200
  <1><1><1>@1@1@1<1><1><1>@1@1@1
  <1><1><1>@1@1@1<1><1><1>@1@1@1
  <1><1><1>@1@1@1<1><1><1>@1@1@1
#endif
#if 2 == 300
  <2><2><2>@2@2@2<2><2><2>@2@2@2
  <2><2><2>@2@2@2<2><2><2>@2@2@2
  <2><2><2>@2@2@2<2><2><2>@2@2@2
#endif

struct __uk__ {
  int ok;
  union {
      int fail;
  } __uk;
};
enum ___u___ {
  __u1
};

#define __UNUSED__      __attribute__((unused))
#define __DEPRECATED__  __attribute__((deprecated))
#define __NORETURN__    __attribute__((noreturn))
#define __PACKED__      __attribute__((packed))
#define __ALIGN(N)__    __attribute__((aligned(N)))
#define __FORMAT(F,V)__ __attribute__((format(F,V,V)))
#define __CONSTRUCTOR__ __attribute__((constructor))
#define __DESTRUCTOR__  __attribute__((destructor))
#define __PURE__        __attribute__((pure))
#define __CONST__       __attribute__((const))
#define _EXTRN                         extern

#if defined (__WINDOWS_NT__)
  #define DOG_WINDOWS /* windows */
  #define IS_WINDOWS
#endif
#if defined (__LINUX__)
  #define DOG_LINUX /* linux */
  #define IS_LINUX
  #define IS_POSIX
#endif
#if defined (__ANDROID__)
  #define DOG_LINUX /* linux */
  #define DOG_ANDROID /* android */
  #define IS_LINUX
  #define IS_POSIX
  #define IS_ANDROID
#endif

#if ! defined (true)
  #define true (1)
#endif
#if ! defined (false)
  #define false (0)
#endif

#ifndef EXIT_FAILURE
  #define EXIT_FAILURE (1)
#endif
#ifndef EXIT_SUCCESS
  #define EXIT_SUCCESS (0)
#endif

#include <fcntl.h>

#if defined (DOG_WINDOWS)
  #define MKDIR(wx) _mkdir(wx)
  #define __set_default_access /* ignoring */
  #define lstat(wx, wy) stat(wx, wy)
  #define S_ISLNK(wx) ((wx & S_IFMT) == S_IFLNK)
  #define O_RDONLY _O_RDONLY
  #define open  _open
  #define read  _read
  #define close _close
#else
  _EXTRN char **environ;
  #define MKDIR(wx) mkdir(wx, 0755)
  #define __set_default_access(wx) \
    chmod(wx, 0777)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>

#include <time.h>
#include <limits.h>

#include <dirent.h>
#include <libgen.h>

#ifdef DOG_WINDOWS
  #include <io.h>
  #include <windows.h>
  #include <process.h>
  #include <direct.h>
  #include <shellapi.h>
#else
  #include <sys/wait.h>
  #include <sys/utsname.h>
#endif

#include <sys/stat.h>
#include <sys/types.h>

#include <curl/curl.h>
#include <archive.h>
#include <archive_entry.h>
#include <readline/history.h>
#include <readline/readline.h>

#if __has_include(<spawn.h>)
  #include <spawn.h>
#endif

#include "tomlc/toml.h"

#if 0 == 100
  <0><0><0>@0@0@0<0><0><0>@0@0@0
  <0><0><0>@0@0@0<0><0><0>@0@0@0
  <0><0><0>@0@0@0<0><0><0>@0@0@0
  <0><0><0>@0@0@0<0><0><0>@0@0@0
#endif
#if 1 == 200
  <1><1><1>@1@1@1<1><1><1>@1@1@1
  <1><1><1>@1@1@1<1><1><1>@1@1@1
  <1><1><1>@1@1@1<1><1><1>@1@1@1
#endif
#if 2 == 300
  <2><2><2>@2@2@2<2><2><2>@2@2@2
  <2><2><2>@2@2@2<2><2><2>@2@2@2
  <2><2><2>@2@2@2<2><2><2>@2@2@2
#endif