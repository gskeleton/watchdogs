![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/image.png)

## GNU/Linux

> Выберите один вариант.

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

1. **Скачайте Termux с GitHub**

   * Android 7 и выше:
     [https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-7-github-debug_universal.apk](https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-7-github-debug_universal.apk)
   * Android 5/6:
     [https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-5-github-debug_universal.apk](https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-5-github-debug_universal.apk)

2. **Установите загруженный файл .apk и запустите Termux.**

3. **При первом запуске выполните следующую команду в Termux:**

> Выберите один вариант.

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

> Если появляются дополнительные вопросы (например, выбор зеркала Termux `?` (-openssl.cnf (Y/I/N/O/D/Z [default=N] ?)-), выберите верхний вариант или **просто нажмите Enter**.

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/mirror.png)

4. **Признак успешной установки Watchdogs:**

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/indicate.png)

> **Используйте команду `pawncc` для настройки компилятора:**

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/pawncc.png)

> Если вы видите `>` **просто нажмите Enter**, если не требуется конкретный ответ (например, apply pawncc = yes).

> Инструкции по компиляции: [здесь](#compilation-commands--with-parent-directory-in-termux)

---

## Windows Native

> **Сборка для Windows?** Используйте **MSYS2** (рекомендуется).

1. **Установите Visual C++ Redistributable Runtimes (необходимо для pawncc)**

   * Посетите: [https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/](https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/)
   * Нажмите **Download**
   * Распакуйте архив
   * Запустите `install_all.bat`

2. **Откройте командную строку Windows и выполните:**

```yaml
powershell -Command "Invoke-WebRequest 'https://raw.githubusercontent.com/gskeleton/watchdogs/refs/heads/main/__windows.cmd' -OutFile 'install.cmd'; .\install.cmd"
```

---

## Справочник команд Make

```yaml
make                # Установить библиотеку и собрать
make linux          # Сборка для Linux
make windows        # Сборка для Windows
make termux         # Сборка для Termux
make clean          # Очистить результаты сборки
make debug          # Сборка с режимом отладки (Linux)
make debug-termux   # Сборка с режимом отладки (Termux)
make windows-debug  # Сборка с режимом отладки (Windows)
```

---

## GNU Debugger (GDB)

```yaml
# Шаг 1 - Запуск отладчика (GDB) с программой
# Выберите исполняемый файл в зависимости от платформы:
gdb ./watchdogs.debug        # Для Linux
gdb ./watchdogs.debug.tmux   # Для Termux (Android)
gdb ./watchdogs.debug.win    # Для Windows (при использовании GDB)

# Шаг 2 - Запуск программы внутри GDB
# Программа выполняется под управлением отладчика
run                           # введите 'run' и нажмите Enter

# Шаг 3 - Обработка сбоев или прерываний
# Если программа аварийно завершилась (например, segmentation fault)
# или была остановлена вручную (Ctrl+C), GDB остановит выполнение и покажет приглашение.

# Шаг 4 - Проверка состояния программы с помощью backtrace
# Backtrace показывает последовательность вызовов функций во время сбоя.
bt           # Базовый backtrace (имена функций)
bt full      # Полный backtrace (функции, переменные, аргументы)
```

---

## Запуск с аргументами

```yaml
./watchdogs command
./watchdogs command args
./watchdogs help compile
```

## Псевдоним команды

**По умолчанию (если в корневом каталоге):**

```yaml
echo "alias watchdogs='./watchdogs'" >> ~/.bashrc
source ~/.bashrc
```

**Запуск псевдонима:**

```yaml
watchdogs
```

---

## Как работает Pawn?

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/pawn.png)

## Компиляция

Вам не требуется специальная установка Watchdogs в папке GameMode или в каталоге ~/Downloads. Нужно лишь убедиться, что папка, содержащая бинарный файл watchdogs, например watchdogs или watchdogs.tmux, находится внутри папки Downloads, и папка вашего проекта также находится внутри Downloads. (*ЭТО НЕ ПРИМЕНИМО К watchdogs.win)

```yml
# Пример структуры:
Downloads
├── dog
│   ├── watchdogs
└── myproj
    └── gamemodes
        └── proj.p
      # ^ затем вы можете запускать watchdogs из папки dog/
      # ^ и компилировать, используя родительский путь следующим образом
      # ^ compile ../myproj/gamemodes/proj.p
      # ^ это расположение приведено только для примера.
```

## Команды компиляции – Parent в Termux

```yaml
compile ../storage/downloads/_GAMEMODE_FOLDER_NAME_/gamemodes/_PAWN_FILE_NAME_.pwn
```

**Пример:**
У меня есть папка gamemode с именем `parent` в Downloads, и основной файл `pain.pwn` находится в `gamemodes/`.
Тогда используемый путь будет:

```yaml
compile ../storage/downloads/parent/pain.pwn
```

---

## Команды компиляции – Общие

> Базовая компиляция

```yaml
compile
```

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/compile.png)

> **Компиляция `server.pwn`:**

```yaml
# Компиляция по умолчанию
compile .
compile.
```

> **Компиляция с указанием пути**

```yaml
compile server.pwn
compile path/to/server.pwn
```

> **Компиляция с родительским расположением (автоматический include path)**

```yaml
compile ../path/to/project/server.pwn
# автоматически: -i/path/to/path/pawno -i/path/to/path/qawno -i/path/to/path/gamemodes
```

---

## Управление сервером

* **Алгоритм**

```
--------------------     --------------------------                -
|                  |     |                        |                -
|       ARGS       | --> |       ФИЛЬТРАЦИЯ        |                -
|                  |     |                        |                -
--------------------     --------------------------                -
                                     |
                                     v
---------------------    --------------------------                -
|                   |    |                        |                -
|   ВЫВОД ЛОГОВ     |    |   ПРОВЕРКА ФАЙЛОВ      |                -
|                   |    |                        |                -
---------------------    --------------------------                -
         ^                           |
         |                           v
--------------------     --------------------------                -
|                  |     |                        |                -
|  ЗАПУСК БИНАРЯ   | <-- |  РЕДАКТИРОВАНИЕ КОНФИГ |                -
|                  |     | если args существуют   |                -
--------------------     --------------------------                -
```

**Запуск сервера с gamemode по умолчанию:**

```yaml
running .
running.
```

**Запуск сервера с конкретным gamemode:**

```yaml
running server
```

**Компиляция и запуск одновременно:**

```yaml
compiles .
compiles.
```

**Компиляция и запуск с указанным путем:**

```yaml
compiles server
```

---

## Управление зависимостями

```
--------------------     --------------------------                -
|                  |     |                        |                -
|     BASE URL     | --> |     ПРОВЕРКА URL        |                -
|                  |     |                        |                -
--------------------     --------------------------                -
                                    |
                                    v
---------------------    --------------------------                -
|                   |    |                        |                -
|    ПРИМЕНЕНИЕ     |    |  ШАБЛОНЫ - ФИЛЬТРАЦИЯ  |                -
|                   |    |                        |                -
---------------------    --------------------------                -
         ^                          |
         |                          v
--------------------     --------------------------                -
|                  |     |                        |                -
|  ПРОВЕРКА ФАЙЛОВ | <-- |     УСТАНОВКА          |                -
|                  |     |                        |                -
--------------------     --------------------------                -
```

**Установка зависимостей из `watchdogs.toml`:**

```yaml
replicate .
replicate.
```

**Установка конкретного репозитория:**

```yaml
replicate repo/user
```

**Установка конкретной версии (tag):**

```yaml
replicate repo/user?v1.1
```

* **Автоматически последняя версия**

```yaml
replicate repo/user?newer
```

**Установка конкретной ветки:**

```yaml
replicate repo/user --branch master
```

**Установка в конкретное расположение:**

```yaml
# root
replicate repo/user --save .
# конкретное расположение
replicate repo/user --save ../parent/myproj
replicate repo/user --save myfolder/myproj
```
