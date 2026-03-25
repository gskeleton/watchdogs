VERSION        = DOG-26.01
FULL_VERSION   = DOG-260101
TARGET        ?= watchdogs
OUTPUT        ?= $(TARGET)
TARGET_NAME    = Watchdogs
SHELL 		  := /bin/bash
CC            ?= clang
CFLAGS         = -O2 -pipe
LDFLAGS        = -lm -lcurl -lreadline -lhistory -larchive

SRCS = \
	debug.c \
	curl.c \
	units.c \
	utils.c \
	cause.c \
	process.c \
	compiler.c \
	archive.c \
	library.c \
	server.c \
	crypto.c \
	tomlc/toml.c
	
OBJS = $(SRCS:.c=.o)

.PHONY: init clean linux termux debug termux-debug windows-debug

init:
	@echo "==> Detecting environment..."
	@UNAME_S="$$(uname -s)"; \
	if echo "$$UNAME_S" | grep -qi "MINGW64_NT"; then \
		echo "==> Using pacman (MSYS2)"; \
		pacman -Sy --noconfirm && \
		pacman -S --needed --noconfirm \
			curl base-devel procps-ng \
			mingw-w64-ucrt-x86_64-libc++ \
			mingw-w64-ucrt-x86_64-clang \
			mingw-w64-ucrt-x86_64-gcc \
			mingw-w64-ucrt-x86_64-lld \
			mingw-w64-ucrt-x86_64-curl \
			mingw-w64-ucrt-x86_64-readline \
			mingw-w64-ucrt-x86_64-libarchive; \
		elif echo "$$UNAME_S" | grep -qi "Linux" && [ -d "/data/data/com.termux" ]; then \
			echo "==> Using apt (Termux)"; \
			apt -o Acquire::Queue-Mode=access -o Acquire::Retries=3 update -y && \
			DEBIAN_FRONTEND=noninteractive \
			apt -o Dpkg::Use-Pty=0 install -y --no-install-recommends \
				unstable-repo x11-repo ndk-sysroot coreutils binutils procps clang curl \
				libarchive readline; \
		elif echo "$$UNAME_S" | grep -qi "Linux"; then \
			if command -v apt >/dev/null 2>&1; then \
				echo "==> Using apt (Debian/Ubuntu)"; \
				dpkg --add-architecture i386 2>/dev/null || true; \
				apt -o Acquire::Queue-Mode=access -o Acquire::Retries=3 update -y && \
				DEBIAN_FRONTEND=noninteractive \
				apt -o Dpkg::Use-Pty=0 install -y --no-install-recommends \
					build-essential curl procps clang lld make binutils \
					libcurl4-openssl-dev libatomic1 libreadline-dev libarchive-dev \
					zlib1g-dev libc6:i386 libstdc++6:i386 libcurl4:i386; \
		elif command -v dnf >/dev/null 2>&1 || command -v dnf5 >/dev/null 2>&1; then \
			echo "==> Using dnf/dnf5 (Fedora/RHEL/AlmaLinux/Rocky Linux)"; \
			if [ -f /etc/almalinux-release ] || [ -f /etc/rocky-release ] || [ -f /etc/redhat-release ]; then \
				echo "==> Detected RHEL-based distribution (AlmaLinux/Rocky Linux/RHEL)"; \
				dnf -y install epel-release dnf-plugins-core 2>/dev/null || true; \
				dnf config-manager --set-enabled crb 2>/dev/null || true; \
			fi; \
			if command -v dnf5 >/dev/null 2>&1; then \
				dnf_ver="dnf5"; \
				echo "==> Detected dnf5 (Fedora 39+)"; \
				$$dnf_ver install -y 'dnf5-command(group)' 2>/dev/null || true; \
			else \
				dnf_ver="dnf"; \
				echo "==> Detected dnf (Fedora <= 38 / RHEL-based)"; \
			fi; \
			$$dnf_ver -y update; \
			if [ "$$dnf_ver" = "dnf5" ]; then \
				echo "==> Installing Development Tools with dnf5"; \
				$$dnf_ver -y install '@Development Tools' || \
				$$dnf_ver -y install @development-tools; \
			else \
				echo "==> Installing Development Tools with dnf"; \
				$$dnf_ver -y groupinstall 'Development Tools'; \
			fi; \
			echo "==> Installing additional dependencies"; \
			$$dnf_ver -y install libcxx-devel 2>/dev/null; \
			if $$dnf_ver list 'curl-devel.i686' >/dev/null 2>&1; then \
				$$dnf_ver -y install \
					clang lld libatomic curl-devel \
					readline-devel libarchive-devel \
					zlib-devel binutils procps-ng file \
					glibc-devel.i686 libstdc++-devel.i686; \
				$$dnf_ver -y install curl-devel.i686 2>/dev/null; \
			else \
				$$dnf_ver -y install \
					clang lld libatomic curl-devel \
					readline-devel libarchive-devel \
					zlib-devel binutils procps-ng file \
					glibc.i686 libstdc++.i686; \
			fi; \
			$$dnf_ver -y install llvm-toolset 2>/dev/null; \
		elif command -v zypper >/dev/null 2>&1; then \
			echo "==> Using zypper (openSUSE)"; \
			zypper --non-interactive refresh && \
			zypper --non-interactive install -y -t pattern devel_basis && \
			echo "==> Installing additional dependencies for openSUSE (64-bit only)"; \
			zypper --non-interactive install -y \
				curl clang lld llvm \
				libc++-devel libatomic1 \
				libcurl-devel readline-devel \
				libarchive-devel binutils \
				procps libstdc++6-32bit; \
		elif command -v pacman >/dev/null 2>&1; then \
			echo "==> Using pacman (Arch)"; \
			pacman -Syu --noconfirm && \
			pacman -S --needed --noconfirm \
				base-devel clang lld llvm libc++ \
				libatomic_ops readline \
				curl libarchive \
				zlib binutils \
				procps-ng \
				lib32-gcc-libs; \
		fi; \
	fi

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

linux: OUTPUT = watchdogs
linux:
	echo "==> Compiling.."; $(CC) $(CFLAGS) \
		-D__LINUX__ -D__W_VERSION__=\"$(FULL_VERSION)\" $(SRCS) -o $(OUTPUT) $(LDFLAGS)

termux: OUTPUT = watchdogs.tmux
termux:
	echo "==> Compiling.."; $(CC) $(CFLAGS) \
		-D__ANDROID__ -D__W_VERSION__=\"$(FULL_VERSION)\" -fPIE $(SRCS) -o $(OUTPUT) $(LDFLAGS) -pie

windows: OUTPUT = watchdogs.win
windows:
	echo "==> Compiling.."; $(CC) \
	-lshell32 -D_POSIX_C_SOURCE=200809L $(CFLAGS) $(SRCS) -D__WINDOWS_NT__ -D__W_VERSION__=\"$(FULL_VERSION)\" -o $(OUTPUT) $(LDFLAGS)

debug: DEBUG_MODE=1
debug: OUTPUT = watchdogs.debug
debug:
	echo "==> Compiling.."; $(CC) $(CFLAGS) \
	-ggdb3 -Og \
  -Wall -Wunused -Wunused-variable -Wunused-parameter -Wunused-function -Wextra \
  -Wconversion -Wsign-conversion -Wfloat-conversion \
  -Wshadow -Wundef \
  -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations \
  -Wnull-dereference -Wuninitialized \
  -fno-omit-frame-pointer -fno-inline -fno-optimize-sibling-calls \
  -fwrapv -fno-strict-aliasing \
  -fno-sanitize-recover=all \
  -fdata-sections -ffunction-sections \
  -DDEBUG -g -D_DBG_PRINT -D__LINUX__ -D__W_VERSION__=\"$(FULL_VERSION)\" $(SRCS) -o $(OUTPUT) $(LDFLAGS) -rdynamic

termux-debug: DEBUG_MODE=1
termux-debug: OUTPUT = watchdogs.debug.tmux
termux-debug:
	echo "==> Compiling.."; $(CC) $(CFLAGS) \
	-ggdb3 -Og \
  -Wall -Wunused -Wunused-variable -Wunused-parameter -Wunused-function -Wextra \
  -Wconversion -Wsign-conversion -Wfloat-conversion \
  -Wshadow -Wundef \
  -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations \
  -Wnull-dereference -Wuninitialized \
  -fno-omit-frame-pointer -fno-inline -fno-optimize-sibling-calls \
  -fwrapv -fno-strict-aliasing \
  -fno-sanitize-recover=all \
  -fdata-sections -ffunction-sections \
  -DDEBUG -g -D_DBG_PRINT -D__ANDROID__ -D__W_VERSION__=\"$(FULL_VERSION)\" $(SRCS) -o $(OUTPUT) $(LDFLAGS) -rdynamic

windows-debug: DEBUG_MODE=1
windows-debug: OUTPUT = watchdogs.debug.win
windows-debug:
	echo "==> Compiling.."; $(CC) -lshell32 -D_POSIX_C_SOURCE=200809L $(CFLAGS) \
	-ggdb3 -Og \
  -Wall -Wunused -Wunused-variable -Wunused-parameter -Wunused-function -Wextra \
  -Wconversion -Wsign-conversion -Wfloat-conversion \
  -Wshadow -Wundef \
  -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations \
  -Wnull-dereference -Wuninitialized \
  -fno-omit-frame-pointer -fno-inline -fno-optimize-sibling-calls \
  -fwrapv -fno-strict-aliasing \
  -fno-sanitize-recover=all \
  -fdata-sections -ffunction-sections \
  -DDEBUG -g -D_DBG_PRINT -D__WINDOWS_NT__ -D__W_VERSION__=\"$(FULL_VERSION)\" $(SRCS) -o $(OUTPUT) $(LDFLAGS)

clean:
	rm -rf $(OBJS) $(OUTPUT) watchdogs watchdogs.win watchdogs.tmux \
	       watchdogs.debug watchdogs.debug.tmux watchdogs.debug.win
