# Watchdogs

## GNU/Linux Installation

Choose one of the following download methods:

```bash
# wget
wget -O install.sh https://github.com/gskeleton/watchdogs/raw/refs/heads/main/Install/__gnu_linux.sh && chmod +x install.sh && ./install.sh

# cURL
curl -L -o install.sh https://github.com/gskeleton/watchdogs/raw/refs/heads/main/Install/__gnu_linux.sh && chmod +x install.sh && ./install.sh

# aria2
aria2c -o install.sh https://github.com/gskeleton/watchdogs/raw/refs/heads/main/Install/__gnu_linux.sh && chmod +x install.sh && ./install.sh
```

---

## Termux (Android)

### 1. Download Termux
- **Android 7+**:
1. Universal: [click here](https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-7-github-debug_universal.apk) - recommended
2. arm64-v8a: [click here](https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-7-github-debug_arm64-v8a.apk)
3. armeabi-v7a: [click here](https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-7-github-debug_armeabi-v7a.apk)

- **Android 5/6**:
1. Universal: [click here](https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-5-github-debug_universal.apk) - recommended
2. arm64-v8a: [click here](https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-5-github-debug_arm64-v8a.apk)
3. armeabi-v7a: [lclick heres](https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-5-github-debug_armeabi-v7a.apk)

### 2. Install & Run
Install the downloaded `.apk` file and launch Termux.

### 3. Initial Setup
Run one of the following commands:

```bash
# wget
apt update && apt upgrade && apt install -y wget && wget -O install.sh https://github.com/gskeleton/watchdogs/raw/refs/heads/main/Install/__termux.sh && chmod +x install.sh && ./install.sh

# cURL
apt update && apt upgrade && apt install -y curl && curl -L -o install.sh https://github.com/gskeleton/watchdogs/raw/refs/heads/main/Install/__termux.sh && chmod +x install.sh && ./install.sh

# aria2
apt update && apt upgrade && apt install -y aria2 && aria2c -o install.sh https://github.com/gskeleton/watchdogs/raw/refs/heads/main/Install/__termux.sh && chmod +x install.sh && ./install.sh
```

---

## Windows (MSYS2 Build)

### 1. Install Visual C++ Redistributable
- Download from: [techpowerup.com](https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/)
- Click **Download**, extract archive, and run `install_all.bat`

### 2. Run Installation
Open **Command Prompt** and execute:

```powershell
powershell -Command "Invoke-WebRequest 'https://raw.githubusercontent.com/gskeleton/watchdogs/refs/heads/main/Install/__windows.cmd' -OutFile 'install.cmd'; .\install.cmd"
```

---

## Usage

### Basic Commands
```bash
./watchdogs command
./watchdogs command args
./watchdogs help compile
```

### Command Alias
```bash
echo "alias watchdogs='./watchdogs'" >> ~/.bashrc
source ~/.bashrc
watchdogs
```

---

## Compilation

### Termux/Parent Mode (Linux/Termux only)
```bash
compile ../storage/shared/Download/_GAMEMODE_FOLDER_/gamemodes/_FILE_.pwn
```

**Example:**
```bash
compile ../storage/shared/Download/parent/gamemodes/pain.pwn
```

### Basic Compilation
```bash
compile           # Default compilation
compile .         # Compile server.pwn
compile server.pwn
compile path/to/server.pwn
```

### Parent Location Compilation
```bash
compile ../path/to/project/server.pwn
# Auto-includes: -i/path/to/source, -i/pawno, -i/qawno, -i/gamemodes
```

---

## Server Runner

### Run Server
```bash
running
```

### Compile & Run
```bash
compiles .        # Compile and run server.pwn
compiles.         # Same as above
compiles server.pwn
```

---

## Dependency Installer

### Install from `watchdogs.toml`
```bash
replicate .       # Install all dependencies
replicate.
```

### Install Specific Repository
```bash
replicate repo/user                    # Latest version
replicate repo/user?v1.1               # Specific tag
replicate repo/user?newer               # Latest tag
replicate repo/user --branch master     # Specific branch
```

### Install to Custom Location
```bash
replicate repo/user --save .                    # Root directory
replicate repo/user --save ../parent/myproj     # Parent directory
replicate repo/user --save myfolder/myproj       # Subdirectory
```