![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/image.png)

## GNU/Linux

> Pilih satu.

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

1. **Muat turun Termux dari GitHub**

   * Android 7 dan ke atas:
     [https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-7-github-debug_universal.apk](https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-7-github-debug_universal.apk)
   * Android 5/6:
     [https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-5-github-debug_universal.apk](https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-5-github-debug_universal.apk)

2. **Pasang fail .apk yang dimuat turun dan jalankan Termux.**

3. **Kali pertama, jalankan arahan berikut dalam Termux:**

> Pilih satu.

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

> Jika terdapat soalan lain (contoh pemilihan mirror Termux `?` (-openssl.cnf (Y/I/N/O/D/Z [default=N] ?)-), pilih yang teratas atau **tekan Enter sahaja**.

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/mirror.png)

4. **Petunjuk bahawa Watchdogs berjaya dipasang:**

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/indicate.png)

> **Gunakan arahan `pawncc` untuk menyediakan compiler:**

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/pawncc.png)

> Jika anda melihat `>` **tekan Enter sahaja** kecuali jika jawapan khusus diminta (contoh apply pawncc = yes).

> Untuk langkah kompilasi, pelajari: [di sini](#compilation-commands--with-parent-directory-in-termux)

---

## Windows dan POSIX untuk Windows

> **Bina untuk Windows?** Gunakan **MSYS2** (disyorkan).

1. **Pasang Visual C++ Redistributable Runtimes (diperlukan untuk pawncc)**

   * Lawati: [https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/](https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/)
   * Klik **Download**
   * Ekstrak arkib
   * Jalankan `install_all.bat`

2. **Buka Windows Command Prompt, jalankan:**

```yaml
powershell -Command "Invoke-WebRequest 'https://raw.githubusercontent.com/gskeleton/watchdogs/refs/heads/main/__windows.cmd' -OutFile 'install.cmd'; .\install.cmd"
```

---

## Rujukan Arahan Make

```yaml
make                # Pasang perpustakaan dan bina
make linux          # Bina untuk Linux
make windows        # Bina untuk Windows
make termux         # Bina untuk Termux
make clean          # Bersihkan hasil binaan
make debug          # Bina dengan mod debug (Linux)
make debug-termux   # Bina dengan mod debug (Termux)
make windows-debug  # Bina dengan mod debug (Windows)
```

---

## GNU Debugger (GDB)

```yaml
# Langkah 1 - Jalankan debugger (GDB) bersama program
# Pilih executable mengikut platform:
gdb ./watchdogs.debug        # Untuk Linux
gdb ./watchdogs.debug.tmux   # Untuk Termux (Android)
gdb ./watchdogs.debug.win    # Untuk Windows (jika menggunakan GDB)

# Langkah 2 - Jalankan program di dalam GDB
# Program dijalankan di bawah kawalan debugger
run                           # taip 'run' kemudian Enter

# Langkah 3 - Mengendalikan crash atau gangguan
# Jika program crash (contoh segmentation fault) atau dihentikan secara manual (Ctrl+C),
# GDB akan menghentikan pelaksanaan dan memaparkan prompt.

# Langkah 4 - Semak status program dengan backtrace
# Backtrace memaparkan urutan panggilan fungsi semasa crash.
bt           # Backtrace asas (nama fungsi)
bt full      # Backtrace penuh (fungsi, pembolehubah, argumen)
```

---

## Menjalankan dengan Args

```yaml
./watchdogs command
./watchdogs command args
./watchdogs help compile
```

## Alias Arahan

**Default (jika dalam direktori root):**

```yaml
echo "alias watchdogs='./watchdogs'" >> ~/.bashrc
source ~/.bashrc
```

**Menjalankan alias:**

```yaml
watchdogs
```

---

## Bagaimana Pawn berfungsi?

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/pawn.png)

## Kompilasi

Anda tidak memerlukan pemasangan khusus Watchdogs dalam folder GameMode atau dalam kawasan ~/Downloads. Anda hanya perlu memastikan folder yang mengandungi binari watchdogs seperti watchdogs atau watchdogs.tmux berada dalam folder di Downloads, dan folder projek anda juga berada dalam folder di Downloads. (*INI TIDAK TERPAKAI UNTUK watchdogs.win)

```yml
# Contoh struktur:
Downloads
├── dog
│   ├── watchdogs
└── myproj
    └── gamemodes
        └── proj.p
      # ^ kemudian anda boleh menjalankan watchdogs yang berada dalam folder dog/
      # ^ dan anda hanya perlu mengkompilasinya dengan simbol parent seperti berikut
      # ^ compile ../myproj/gamemodes/proj.p
      # ^ lokasi ini hanyalah contoh.
```

## Arahan Kompilasi – Parent dalam Termux

```yaml
compile ../storage/downloads/_GAMEMODE_FOLDER_NAME_/gamemodes/_PAWN_FILE_NAME_.pwn
```

**Contoh:**
Saya mempunyai folder gamemode bernama `parent` dalam Downloads, dan fail utama `pain.pwn` berada di dalam `gamemodes/`.
Maka laluan yang digunakan ialah:

```yaml
compile ../storage/downloads/parent/pain.pwn
```

---

## Arahan Kompilasi – Umum

> Kompilasi Asas

```yaml
compile
```

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/compile.png)

> **Kompilasi `server.pwn`:**

```yaml
# Kompilasi lalai
compile .
compile.
```

> **Kompilasi dengan laluan tertentu**

```yaml
compile server.pwn
compile path/to/server.pwn
```

> **Kompilasi dengan lokasi parent (include path automatik)**

```yaml
compile ../path/to/project/server.pwn
# automatik: -i/path/to/path/pawno -i/path/to/path/qawno -i/path/to/path/gamemodes
```

---

## Pengurusan Server

* **Algoritma**

```
--------------------     --------------------------                -
|                  |     |                        |                -
|       ARGS       | --> |       PENAPISAN        |                -
|                  |     |                        |                -
--------------------     --------------------------                -
                                     |
                                     v
---------------------    --------------------------                -
|                   |    |                        |                -
|   LOG OUTPUT      |    |   PENGESAHAN FAIL      |                -
|                   |    |                        |                -
---------------------    --------------------------                -
         ^                           |
         |                           v
--------------------     --------------------------                -
|                  |     |                        |                -
|  BINARI BERJALAN  | <-- |   EDIT KONFIGURASI    |                -
|                  |     | jika args wujud        |                -
--------------------     --------------------------                -
```

**Jalankan server dengan gamemode lalai:**

```yaml
running .
running.
```

**Jalankan server dengan gamemode tertentu:**

```yaml
running server
```

**Kompilasi dan jalankan serentak:**

```yaml
compiles .
compiles.
```

**Kompilasi dan jalankan dengan laluan tertentu:**

```yaml
compiles server
```

---

## Pengurusan Kebergantungan

```
--------------------     --------------------------                -
|                  |     |                        |                -
|     BASE URL     | --> |     SEMAKAN URL         |                -
|                  |     |                        |                -
--------------------     --------------------------                -
                                    |
                                    v
---------------------    --------------------------                -
|                   |    |                        |                -
|    PENERAPAN      |    |  CORAK - PENAPISAN     |                -
|                   |    |                        |                -
---------------------    --------------------------                -
         ^                          |
         |                          v
--------------------     --------------------------                -
|                  |     |                        |                -
|  SEMAKAN FAIL    | <-- |     PEMASANGAN         |                -
|                  |     |                        |                -
--------------------     --------------------------                -
```

**Pasang kebergantungan dari `watchdogs.toml`:**

```yaml
replicate .
replicate.
```

**Pasang repositori tertentu:**

```yaml
replicate repo/user
```

**Pasang versi tertentu (tag):**

```yaml
replicate repo/user?v1.1
```

* **Versi terkini automatik**

```yaml
replicate repo/user?newer
```

**Pasang branch tertentu:**

```yaml
replicate repo/user --branch master
```

**Pasang ke lokasi tertentu:**

```yaml
# root
replicate repo/user --save .
# lokasi tertentu
replicate repo/user --save ../parent/myproj
replicate repo/user --save myfolder/myproj
```
