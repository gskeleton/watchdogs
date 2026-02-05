![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/image.png)

## GNU/Linux

> Elige uno.

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

1. **Descarga Termux desde GitHub**

   * Android 7 y superior:
     [https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-7-github-debug_universal.apk](https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-7-github-debug_universal.apk)
   * Android 5/6:
     [https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-5-github-debug_universal.apk](https://github.com/termux/termux-app/releases/download/v0.119.0-beta.3/termux-app_v0.119.0-beta.3+apt-android-5-github-debug_universal.apk)

2. **Instala el archivo .apk descargado y luego ejecuta Termux.**

3. **En el primer uso, ejecuta el siguiente comando en Termux:**

> Elige uno.

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

> Si hay otras preguntas (por ejemplo, selección de mirror de Termux `?` (-openssl.cnf (Y/I/N/O/D/Z [default=N] ?)-), elige la opción superior o **simplemente presiona Enter**.

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/mirror.png)

4. **Indicación de que Watchdogs se instaló correctamente:**

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/indicate.png)

> **Usa el comando `pawncc` para configurar el compilador:**

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/pawncc.png)

> Si ves el signo `>` **simplemente presiona Enter** a menos que se solicite una respuesta específica (por ejemplo, apply pawncc = yes).

> Para los pasos de compilación, aprende: [aquí](#comandos-de-compilación--con-directorio-padre-en-termux)

---

## Windows y POSIX para Windows

> **¿Compilar para Windows?** Usa **MSYS2** (recomendado).

1. **Instala Visual C++ Redistributable Runtimes (necesario para pawncc)**

   * Visita: [https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/](https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/)
   * Haz clic en **Download**
   * Extrae el archivo
   * Ejecuta `install_all.bat`

2. **Abre el Símbolo del sistema de Windows, ejecuta:**

```yaml
powershell -Command "Invoke-WebRequest 'https://raw.githubusercontent.com/gskeleton/watchdogs/refs/heads/main/__windows.cmd' -OutFile 'install.cmd'; .\install.cmd"
```

---

## Referencia de Comandos Make

```yaml
make                # Instala bibliotecas y compila
make linux          # Compila para Linux
make windows        # Compila para Windows
make termux         # Compila para Termux
make clean          # Limpia los resultados de compilación
make debug          # Compila en modo debug (Linux)
make debug-termux   # Compila en modo debug (Termux)
make windows-debug  # Compila en modo debug (Windows)
```

---

## GNU Debugger (GDB)

```yaml
# Paso 1 - Ejecuta el depurador (GDB) con el programa
# Selecciona el ejecutable según la plataforma:
gdb ./watchdogs.debug        # Para Linux
gdb ./watchdogs.debug.tmux   # Para Termux (Android)
gdb ./watchdogs.debug.win    # Para Windows (si usas GDB)

# Paso 2 - Ejecuta el programa dentro de GDB
# El programa se ejecuta bajo el control del depurador
run                           # escribe 'run' y luego Enter

# Paso 3 - Manejar fallos o interrupciones
# Si el programa falla (por ejemplo, segmentation fault)
# o se detiene manualmente (Ctrl+C), GDB se detendrá y mostrará un prompt.

# Paso 4 - Verifica el estado del programa con backtrace
# Backtrace muestra la secuencia de llamadas a funciones en el momento del fallo.
bt           # Backtrace básico (nombres de funciones)
bt full      # Backtrace completo (funciones, variables, argumentos)
```

---

## Ejecutar con Argumentos

```yaml
./watchdogs comando
./watchdogs comando args
./watchdogs help compile
```

## Alias de Comandos

**Predeterminado (si estás en el directorio raíz):**

```yaml
echo "alias watchdogs='./watchdogs'" >> ~/.bashrc
source ~/.bashrc
```

**Ejecutar alias:**

```yaml
watchdogs
```

---

## ¿Cómo funciona Pawn?

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/pawn.png)

## Compilación

No necesitas una instalación especial de Watchdogs en la carpeta GameMode o en el área ~/Downloads. Solo necesitas asegurarte de que la carpeta que contiene el binario watchdogs, como watchdogs o watchdogs.tmux, esté dentro de la carpeta Downloads, y que tu carpeta del proyecto también esté dentro de la carpeta Downloads. (*ESTO NO APLICA PARA watchdogs.win)

```yml
# Ejemplo de estructura:
Downloads
├── dog
│   ├── watchdogs
└── myproj
    └── gamemodes
        └── proj.p
      # ^ luego puedes ejecutar watchdogs que está en la carpeta dog/
      # ^ y compilarlo con el símbolo parent como sigue
      # ^ compile ../myproj/gamemodes/proj.p
      # ^ esta ubicación es solo un ejemplo.
```

## Comandos de Compilación – Parent en Termux

```yaml
compile ../storage/downloads/_NOMBRE_CARPETA_GAMEMODE_/gamemodes/_NOMBRE_ARCHIVO_PAWN_.pwn
```

**Ejemplo:**
Tengo una carpeta gamemode llamada `parent` en Downloads, y el archivo principal `pain.pwn` está dentro de `gamemodes/`.
Entonces la ruta utilizada es:

```yaml
compile ../storage/downloads/parent/pain.pwn
```

---

## Comandos de Compilación – General

> Compilación Básica

```yaml
compile
```

![watchdogs](https://raw.githubusercontent.com/gskeleton/dogdog/refs/heads/main/compile.png)

> **Compilar `server.pwn`:**

```yaml
# Compilación predeterminada
compile .
compile.
```

> **Compilar con ruta específica**

```yaml
compile server.pwn
compile ruta/a/server.pwn
```

> **Compilar con ubicación parent (ruta de include automática)**

```yaml
compile ../ruta/a/proyecto/server.pwn
# automáticamente: -i/ruta/a/ruta/pawno -i/ruta/a/ruta/qawno -i/ruta/a/ruta/gamemodes
```

---

## Gestión del Servidor

* **Algoritmo**

```
--------------------     --------------------------                -
|                  |     |                        |                -
|       ARGS       | --> |       FILTRADO         |                -
|                  |     |                        |                -
--------------------     --------------------------                -
                                     |
                                     v
---------------------    --------------------------                -
|                   |    |                        |                -
|   SALIDA DE LOG   |    |   VALIDACIÓN DE ARCHIVO |                -
|                   |    |                        |                -
---------------------    --------------------------                -
         ^                           |
         |                           v
--------------------     --------------------------                -
|                  |     |                        |                -
|  BINARIO EJECUTÁNDOSE | <-- |   EDICIÓN DE CONFIGURACIÓN |                -
|                  |     | si hay args           |                -
--------------------     --------------------------                -
```

**Ejecutar servidor con gamemode predeterminado:**

```yaml
running .
running.
```

**Ejecutar servidor con gamemode específico:**

```yaml
running server
```

**Compilar y ejecutar simultáneamente:**

```yaml
compiles .
compiles.
```

**Compilar y ejecutar con ruta específica:**

```yaml
compiles server
```

---

## Gestión de Dependencias

```
--------------------     --------------------------                -
|                  |     |                        |                -
|     URL BASE     | --> |     VERIFICACIÓN DE URL |                -
|                  |     |                        |                -
--------------------     --------------------------                -
                                    |
                                    v
---------------------    --------------------------                -
|                   |    |                        |                -
|    APLICACIÓN     |    |  PATRÓN - FILTRADO     |                -
|                   |    |                        |                -
---------------------    --------------------------                -
         ^                          |
         |                          v
--------------------     --------------------------                -
|                  |     |                        |                -
|  VERIFICACIÓN DE ARCHIVO | <-- |     INSTALACIÓN      |                -
|                  |     |                        |                -
--------------------     --------------------------                -
```

**Instalar dependencias desde `watchdogs.toml`:**

```yaml
replicate .
replicate.
```

**Instalar repositorio específico:**

```yaml
replicate repo/usuario
```

**Instalar versión específica (tag):**

```yaml
replicate repo/usuario?v1.1
```

* **Última versión automáticamente**

```yaml
replicate repo/usuario?newer
```

**Instalar rama específica:**

```yaml
replicate repo/usuario --branch master
```

**Instalar en ubicación específica:**

```yaml
# raíz
replicate repo/usuario --save .
# ubicación específica
replicate repo/usuario --save ../parent/myproj
replicate repo/usuario --save micarpeta/myproj
```