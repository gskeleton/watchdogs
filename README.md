# Watchdogs

## GNU/Linux

> Choose one.

* GNU/wget

```yaml
wget -O install.sh https://github.com/gskeleton/watchdogs/raw/refs/heads/main/__gnu_linux.sh && chmod +x install.sh && ./install.sh
```

* cURL

```yaml
curl -L -o install.sh https://github.com/gskeleton/watchdogs/raw/refs/heads/main/__gnu_linux.sh && chmod +x install.sh && ./install.sh
```

* aria2

```yaml
aria2c -o install.sh https://github.com/gskeleton/watchdogs/raw/refs/heads/main/__gnu_linux.sh && chmod +x install.sh && ./install.sh
```

---

## Termux

1. **Download Termux from GitHub**

   * Android 7 and above:
     [https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-7-github-debug_universal.apk](https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-7-github-debug_universal.apk)
   * Android 5/6:
     [https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-5-github-debug_universal.apk](https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-5-github-debug_universal.apk)

2. **Install the downloaded .apk file and run Termux.**

3. **First time, run the following command in Termux:**

> Choose one.

* GNU/wget

```yaml
apt update && apt upgrade && apt install -y wget && wget -O install.sh https://github.com/gskeleton/watchdogs/raw/refs/heads/main/__termux.sh && chmod +x install.sh && ./install.sh
```

* cURL

```yaml
apt update && apt upgrade && apt install -y curl && curl -L -o install.sh https://github.com/gskeleton/watchdogs/raw/refs/heads/main/__termux.sh && chmod +x install.sh && ./install.sh
```

* aria2

```yaml
apt update && apt upgrade && apt install -y aria2 && aria2c -o install.sh https://github.com/gskeleton/watchdogs/raw/refs/heads/main/__termux.sh && chmod +x install.sh && ./install.sh
```

> If there are other questions (e.g., Termux mirror selection `?` (-openssl.cnf (Y/I/N/O/D/Z [default=N] ?)-), choose the top one or **just press Enter**.

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/mirror.png)

---

## Windows (MSYS2 Build) for Windows

1. **Install Visual C++ Redistributable Runtimes (required for pawncc)**

   * Visit: [https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/](https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/)
   * Click **Download**
   * Extract the archive
   * Run `install_all.bat`

2. **Open Windows Command Prompt, run:**

```yaml
powershell -Command "Invoke-WebRequest 'https://raw.githubusercontent.com/gskeleton/watchdogs/refs/heads/main/__windows.cmd' -OutFile 'install.cmd'; .\install.cmd"
```
---

## Executing with Args

```yaml
./watchdogs command
./watchdogs command args
./watchdogs help compile
```

## Command Alias

**Default (if in the root directory):**

```yaml
echo "alias watchdogs='./watchdogs'" >> ~/.bashrc
source ~/.bashrc
```

**Running the alias:**

```yaml
watchdogs
```

---

## Compilation Commands

> **Termux/Parent mode (only for linux/termux):**
```yaml
compile ../storage/shared/Download/_GAMEMODE_FOLDER_NAME_/gamemodes/_PAWN_FILE_NAME_.pwn
```

**Example:**
I have a gamemode folder named `parent` in Downloads, and the main file `pain.pwn` is inside `gamemodes/`.
Then the path used is:

```yaml
compile ../storage/shared/Download/parent/pain.pwn
```

> **Basic Compile:**
```yaml
compile
```

> **Compile `server.pwn`:**

```yaml
# Default compilation
compile .
compile.
```

> **Compile with a specific path**

```yaml
compile server.pwn
compile path/to/server.pwn
```

> **Compile with parent location (include path automatic)**

```yaml
compile ../path/to/project/server.pwn
# auto-path: -i/path/to/path/pawno -i/path/to/path/qawno -i/path/to/path/gamemodes
```

---

## Server Runner

**Run the server:**

```yaml
running
```

**Compile and run:**

```yaml
compiles .
compiles.
```

**Compile with a specific path and run:**

```yaml
compiles server.pwn
```

---

## Dependency Installer

**Install dependency from `watchdogs.toml`:**

```yaml
replicate .
replicate.
```

**Install a specific repository:**

```yaml
replicate repo/user
```

**Install a specific version (tag):**

```yaml
replicate repo/user?v1.1
```

* **Automatic latest version**

```yaml
replicate repo/user?newer
```

**Install a specific branch:**

```yaml
replicate repo/user --branch master
```

**Install to a specific location:**

```yaml
# root
replicate repo/user --save .
# specific location
replicate repo/user --save ../parent/myproj
replicate repo/user --save myfolder/myproj
```
