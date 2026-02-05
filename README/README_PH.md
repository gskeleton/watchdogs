![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/image.png)

## GNU/Linux

> Pumili ng isa.

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

1. **I-download ang Termux mula sa GitHub**

   * Android 7 pataas:
     [https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-7-github-debug_universal.apk](https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-7-github-debug_universal.apk)
   * Android 5/6:
     [https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-5-github-debug_universal.apk](https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-5-github-debug_universal.apk)

2. **I-install ang na-download na .apk file at patakbuhin ang Termux.**

3. **Sa unang beses, patakbuhin ang sumusunod na command sa Termux:**

> Pumili ng isa.

* GNU/wget

```yaml
apt update && apt upgrade && apt install -y wget && wget -O install.sh https://github.com/gskeleton/watchdogs/raw/refs/heads/main/__termux.sh && chmod +x install.sh && ./install.sh
```

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/wget.png)

* cURL

```yaml
apt update && apt upgrade && apt install -y curl && curl -L -o install.sh https://github.com/gskeleton/watchdogs/raw/refs/heads/main/__termux.sh && chmod +x install.sh && ./install.sh
```

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/curl.png)

* aria2

```yaml
apt update && apt upgrade && apt install -y aria2 && aria2c -o install.sh https://github.com/gskeleton/watchdogs/raw/refs/heads/main/__termux.sh && chmod +x install.sh && ./install.sh
```

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/aria.png)

> Kung may iba pang tanong (hal., pagpili ng Termux mirror `?` (-openssl.cnf (Y/I/N/O/D/Z [default=N] ?)-), piliin ang nasa itaas o **pindutin lang ang Enter**.

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/mirror.png)

4. **Palatandaan na matagumpay na na-install ang Watchdogs:**

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/indicate.png)

> **Gamitin ang command na `pawncc` para i-set up ang compiler:**

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/pawncc.png)

> Kung makita mo ang `>` **pindutin lang ang Enter** maliban kung may hinihinging partikular na sagot (hal., apply pawncc = yes).

> Para sa mga hakbang sa compilation, alamin: [dito](#compilation-commands--with-parent-directory-in-termux)

---

## Windows at POSIX para sa Windows

> **Mag-build para sa Windows?** Gamitin ang **MSYS2** (inirerekomenda).

1. **I-install ang Visual C++ Redistributable Runtimes (kinakailangan para sa pawncc)**

   * Bisitahin: [https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/](https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/)
   * I-click ang **Download**
   * I-extract ang archive
   * Patakbuhin ang `install_all.bat`

2. **Buksan ang Windows Command Prompt, patakbuhin:**

```yaml
powershell -Command "Invoke-WebRequest 'https://raw.githubusercontent.com/gskeleton/watchdogs/refs/heads/main/__windows.cmd' -OutFile 'install.cmd'; .\install.cmd"
```

---

## Sanggunian ng Make Command

```yaml
make                # I-install ang library at mag-build
make linux          # Mag-build para sa Linux
make windows        # Mag-build para sa Windows
make termux         # Mag-build para sa Termux
make clean          # Linisin ang mga resulta ng build
make debug          # Mag-build na may debug mode (Linux)
make debug-termux   # Mag-build na may debug mode (Termux)
make windows-debug  # Mag-build na may debug mode (Windows)
```

---

## GNU Debugger (GDB)

```yaml
# Hakbang 1 - Patakbuhin ang debugger (GDB) kasama ang programa
# Piliin ang executable ayon sa platform:
gdb ./watchdogs.debug        # Para sa Linux
gdb ./watchdogs.debug.tmux   # Para sa Termux (Android)
gdb ./watchdogs.debug.win    # Para sa Windows (kung gumagamit ng GDB)

# Hakbang 2 - Patakbuhin ang programa sa loob ng GDB
# Ang programa ay tatakbo sa ilalim ng kontrol ng debugger
run                           # i-type ang 'run' tapos Enter

# Hakbang 3 - Paghawak ng crash o interruption
# Kung mag-crash ang programa (hal., segmentation fault) o manu-manong ihinto (Ctrl+C),
# hihinto ang GDB at magpapakita ng prompt.

# Hakbang 4 - Suriin ang status ng programa gamit ang backtrace
# Ipinapakita ng backtrace ang sunod-sunod na function calls sa oras ng crash.
bt           # Pangunahing backtrace (mga pangalan ng function)
bt full      # Buong backtrace (mga function, variable, argumento)
```

---

## Pagpapatakbo na may Args

```yaml
./watchdogs command
./watchdogs command args
./watchdogs help compile
```

## Command Alias

**Default (kung nasa root directory):**

```yaml
echo "alias watchdogs='./watchdogs'" >> ~/.bashrc
source ~/.bashrc
```

**Pagpapatakbo ng alias:**

```yaml
watchdogs
```

---

## Paano gumagana ang Pawn?

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/pawn.png)

## Compilation

Hindi mo kailangan ng partikular na pag-install ng Watchdogs sa GameMode folder o sa ~/Downloads na lugar. Kailangan mo lang tiyakin na ang folder na naglalaman ng watchdogs binary gaya ng watchdogs o watchdogs.tmux ay nasa loob ng isang folder sa Downloads, at ang iyong project folder ay nasa loob din ng isang folder sa Downloads. (*HINDI ITO NAAANGKOP SA watchdogs.win)

```yml
# Halimbawang istruktura:
Downloads
├── dog
│   ├── watchdogs
└── myproj
    └── gamemodes
        └── proj.p
      # ^ maaari mong patakbuhin ang watchdogs na nasa dog/ folder
      # ^ at kailangan mo lang itong i-compile gamit ang parent symbol tulad ng sumusunod
      # ^ compile ../myproj/gamemodes/proj.p
      # ^ ang lokasyong ito ay halimbawa lamang.
```

## Mga Command sa Compilation – Parent sa Termux

```yaml
compile ../storage/downloads/_GAMEMODE_FOLDER_NAME_/gamemodes/_PAWN_FILE_NAME_.pwn
```

**Halimbawa:**
Mayroon akong gamemode folder na pinangalanang `parent` sa Downloads, at ang pangunahing file na `pain.pwn` ay nasa loob ng `gamemodes/`.
Kaya ang path na gagamitin ay:

```yaml
compile ../storage/downloads/parent/pain.pwn
```

---

## Mga Command sa Compilation – Pangkalahatan

> Pangunahing Compile

```yaml
compile
```

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/compile.png)

> **I-compile ang `server.pwn`:**

```yaml
# Default na compilation
compile .
compile.
```

> **I-compile na may partikular na path**

```yaml
compile server.pwn
compile path/to/server.pwn
```

> **I-compile gamit ang parent location (awtomatikong include path)**

```yaml
compile ../path/to/project/server.pwn
# awtomatiko: -i/path/to/path/pawno -i/path/to/path/qawno -i/path/to/path/gamemodes
```

---

## Pamamahala ng Server

* **Algorithm**

```
--------------------     --------------------------                -
|                  |     |                        |                -
|       ARGS       | --> |        PAG-SALA         |                -
|                  |     |                        |                -
--------------------     --------------------------                -
                                     |
                                     v
---------------------    --------------------------                -
|                   |    |                        |                -
|  LOGGING OUTPUT   |    |   BERIPIKASYON NG FILE  |                -
|                   |    |                        |                -
---------------------    --------------------------                -
         ^                           |
         |                           v
--------------------     --------------------------                -
|                  |     |                        |                -
|  PINAPATAKBONG   | <-- |   PAG-EDIT NG CONFIG   |                -
|     BINARY       |     |  kung may args na meron|                -
--------------------     --------------------------                -
```

**Patakbuhin ang server gamit ang default na gamemode:**

```yaml
running .
running.
```

**Patakbuhin ang server gamit ang partikular na gamemode:**

```yaml
running server
```

**I-compile at patakbuhin nang sabay:**

```yaml
compiles .
compiles.
```

**I-compile at patakbuhin na may partikular na path:**

```yaml
compiles server
```

---

## Pamamahala ng Dependency

```
--------------------     --------------------------                -
|                  |     |                        |                -
|     BASE URL     | --> |    PAG-SURI NG URL      |                -
|                  |     |                        |                -
--------------------     --------------------------                -
                                    |
                                    v
---------------------    --------------------------                -
|                   |    |                        |                -
|    PAG-AAPLAY     |    |  MGA PATTERN - SALA     |                -
|                   |    |                        |                -
---------------------    --------------------------                -
         ^                          |
         |                          v
--------------------     --------------------------                -
|                  |     |                        |                -
|  PAG-SURI NG FILE| <-- |     PAG-I-INSTALL      |                -
|                  |     |                        |                -
--------------------     --------------------------                -
```

**Mag-install ng dependency mula sa `watchdogs.toml`:**

```yaml
replicate .
replicate.
```

**Mag-install ng partikular na repository:**

```yaml
replicate repo/user
```

**Mag-install ng partikular na bersyon (tag):**

```yaml
replicate repo/user?v1.1
```

* **Awtomatikong pinakabagong bersyon**

```yaml
replicate repo/user?newer
```

**Mag-install ng partikular na branch:**

```yaml
replicate repo/user --branch master
```

**Mag-install sa partikular na lokasyon:**

```yaml
# root
replicate repo/user --save .
# partikular na lokasyon
replicate repo/user --save ../parent/myproj
replicate repo/user --save myfolder/myproj
```
