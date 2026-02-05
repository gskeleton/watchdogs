![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/image.png)

## GNU/Linux

> Pilih salah satu.

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

1. **Unduh Termux dari GitHub**

   * Android 7 ke atas:
     [https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-7-github-debug_universal.apk](https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-7-github-debug_universal.apk)
   * Android 5/6:
     [https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-5-github-debug_universal.apk](https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-5-github-debug_universal.apk)

2. **Instal file .apk yang diunduh lalu jalankan Termux.**

3. **Pada penggunaan pertama, jalankan perintah berikut di Termux:**

> Pilih salah satu.

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

> Jika ada pertanyaan lain (misalnya pemilihan mirror Termux `?` (-openssl.cnf (Y/I/N/O/D/Z [default=N] ?)-), pilih opsi teratas atau **cukup tekan Enter**.

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/mirror.png)

4. **Indikasi bahwa Watchdogs berhasil diinstal:**

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/indicate.png)

> **Gunakan perintah `pawncc` untuk menyiapkan compiler:**

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/pawncc.png)

> Jika Anda melihat tanda `>` **cukup tekan Enter** kecuali jika diminta jawaban tertentu (misalnya apply pawncc = yes).

> Untuk langkah kompilasi, pelajari: [di sini](#compilation-commands--with-parent-directory-in-termux)

---

## Windows dan POSIX untuk Windows

> **Build untuk Windows?** Gunakan **MSYS2** (direkomendasikan).

1. **Instal Visual C++ Redistributable Runtimes (diperlukan untuk pawncc)**

   * Kunjungi: [https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/](https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/)
   * Klik **Download**
   * Ekstrak arsip
   * Jalankan `install_all.bat`

2. **Buka Windows Command Prompt, jalankan:**

```yaml
powershell -Command "Invoke-WebRequest 'https://raw.githubusercontent.com/gskeleton/watchdogs/refs/heads/main/__windows.cmd' -OutFile 'install.cmd'; .\install.cmd"
```

---

## Referensi Perintah Make

```yaml
make                # Instal library dan build
make linux          # Build untuk Linux
make windows        # Build untuk Windows
make termux         # Build untuk Termux
make clean          # Bersihkan hasil build
make debug          # Build dengan mode debug (Linux)
make debug-termux   # Build dengan mode debug (Termux)
make windows-debug  # Build dengan mode debug (Windows)
```

---

## GNU Debugger (GDB)

```yaml
# Langkah 1 - Jalankan debugger (GDB) dengan program
# Pilih executable sesuai platform:
gdb ./watchdogs.debug        # Untuk Linux
gdb ./watchdogs.debug.tmux   # Untuk Termux (Android)
gdb ./watchdogs.debug.win    # Untuk Windows (jika menggunakan GDB)

# Langkah 2 - Jalankan program di dalam GDB
# Program dijalankan di bawah kendali debugger
run                           # ketik 'run' lalu Enter

# Langkah 3 - Menangani crash atau interupsi
# Jika program crash (misalnya segmentation fault)
# atau dihentikan manual (Ctrl+C), GDB akan berhenti dan menampilkan prompt.

# Langkah 4 - Periksa status program dengan backtrace
# Backtrace menampilkan urutan pemanggilan fungsi saat crash.
bt           # Backtrace dasar (nama fungsi)
bt full      # Backtrace lengkap (fungsi, variabel, argumen)
```

---

## Menjalankan dengan Argumen

```yaml
./watchdogs command
./watchdogs command args
./watchdogs help compile
```

## Alias Perintah

**Default (jika berada di direktori root):**

```yaml
echo "alias watchdogs='./watchdogs'" >> ~/.bashrc
source ~/.bashrc
```

**Menjalankan alias:**

```yaml
watchdogs
```

---

## Bagaimana Pawn bekerja?

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/pawn.png)

## Kompilasi

Anda tidak memerlukan instalasi khusus Watchdogs di folder GameMode atau di area ~/Downloads. Anda hanya perlu memastikan folder yang berisi binary watchdogs seperti watchdogs atau watchdogs.tmux berada di dalam folder Downloads, dan folder proyek Anda juga berada di dalam folder Downloads. (*INI TIDAK BERLAKU UNTUK watchdogs.win)

```yml
# Contoh struktur:
Downloads
├── dog
│   ├── watchdogs
└── myproj
    └── gamemodes
        └── proj.p
      # ^ lalu Anda dapat menjalankan watchdogs yang berada di folder dog/
      # ^ dan cukup mengompilasinya dengan simbol parent seperti berikut
      # ^ compile ../myproj/gamemodes/proj.p
      # ^ lokasi ini hanya contoh.
```

## Perintah Kompilasi – Parent di Termux

```yaml
compile ../storage/downloads/_GAMEMODE_FOLDER_NAME_/gamemodes/_PAWN_FILE_NAME_.pwn
```

**Contoh:**
Saya memiliki folder gamemode bernama `parent` di Downloads, dan file utama `pain.pwn` berada di dalam `gamemodes/`.
Maka path yang digunakan adalah:

```yaml
compile ../storage/downloads/parent/pain.pwn
```

---

## Perintah Kompilasi – Umum

> Kompilasi Dasar

```yaml
compile
```

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/compile.png)

> **Kompilasi `server.pwn`:**

```yaml
# Kompilasi default
compile .
compile.
```

> **Kompilasi dengan path tertentu**

```yaml
compile server.pwn
compile path/to/server.pwn
```

> **Kompilasi dengan lokasi parent (include path otomatis)**

```yaml
compile ../path/to/project/server.pwn
# otomatis: -i/path/to/path/pawno -i/path/to/path/qawno -i/path/to/path/gamemodes
```

---

## Manajemen Server

* **Algoritma**

```
--------------------     --------------------------                -
|                  |     |                        |                -
|       ARGS       | --> |       PENYARINGAN       |                -
|                  |     |                        |                -
--------------------     --------------------------                -
                                     |
                                     v
---------------------    --------------------------                -
|                   |    |                        |                -
|   OUTPUT LOG      |    |   VALIDASI FILE        |                -
|                   |    |                        |                -
---------------------    --------------------------                -
         ^                           |
         |                           v
--------------------     --------------------------                -
|                  |     |                        |                -
|  BINARY BERJALAN  | <-- |   EDIT KONFIGURASI    |                -
|                  |     | jika args ada          |                -
--------------------     --------------------------                -
```

**Jalankan server dengan gamemode default:**

```yaml
running .
running.
```

**Jalankan server dengan gamemode tertentu:**

```yaml
running server
```

**Kompilasi dan jalankan bersamaan:**

```yaml
compiles .
compiles.
```

**Kompilasi dan jalankan dengan path tertentu:**

```yaml
compiles server
```

---

## Manajemen Dependensi

```
--------------------     --------------------------                -
|                  |     |                        |                -
|     BASE URL     | --> |     PENGECEKAN URL      |                -
|                  |     |                        |                -
--------------------     --------------------------                -
                                    |
                                    v
---------------------    --------------------------                -
|                   |    |                        |                -
|    PENERAPAN      |    |  POLA - PENYARINGAN    |                -
|                   |    |                        |                -
---------------------    --------------------------                -
         ^                          |
         |                          v
--------------------     --------------------------                -
|                  |     |                        |                -
|  PENGECEKAN FILE | <-- |     INSTALASI          |                -
|                  |     |                        |                -
--------------------     --------------------------                -
```

**Instal dependensi dari `watchdogs.toml`:**

```yaml
replicate .
replicate.
```

**Instal repositori tertentu:**

```yaml
replicate repo/user
```

**Instal versi tertentu (tag):**

```yaml
replicate repo/user?v1.1
```

* **Versi terbaru otomatis**

```yaml
replicate repo/user?newer
```

**Instal branch tertentu:**

```yaml
replicate repo/user --branch master
```

**Instal ke lokasi tertentu:**

```yaml
# root
replicate repo/user --save .
# lokasi tertentu
replicate repo/user --save ../parent/myproj
replicate repo/user --save myfolder/myproj
```
