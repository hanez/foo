# Laboratorio de RCE root por SUID — `foosd` (demonio) + `foosc` (exploit)

Un compañero del laboratorio principal (`food` / `fooc`, un demonio normal donde
un desbordamiento de búfer te da un shell de *usuario*). Este añade el cambio de
un solo carácter más peligroso de Unix: **el bit setuid**.

> `chmod u+s` convierte "el atacante puede ejecutar código en este host" en "el
> atacante puede ejecutar código como **root** en este host".

Esa frase es todo el laboratorio. Todo lo que sigue es el mecanismo que tiene
debajo, escrito, para que cuando escribas tu propio software sepas
exactamente qué dos o tres atributos del sistema de archivos y flags del
compilador deciden si un error de seguridad de memoria en tu código es una
molestia o un shell root.

La demo final, cuando `foosd` es setuid-root, es un **shell root** abierto a
través de la red ejecutando 32 bytes de shellcode escrita a mano.

---

## 1. Qué hace realmente el bit setuid

Cada proceso en Linux lleva tres user-ID, y el bit setuid toca la relación
entre ellos:

| ID | Nombre | Significado |
|----|------|---------|
| `ruid` | user-ID real | la cuenta que *inició* el proceso |
| `euid` | user-ID efectivo | lo que el kernel comprueba al imponer el acceso |
| (saved) | set-user-ID guardado | una "ranura" a la que un proceso privilegiado puede volver más tarde |

Un programa normal tiene `ruid == euid`. Cuando ejecutas un binario con el bit
setuid puesto, propiedad de root:

```text
ruid = tú        (p. ej. 1000, "hanez")
euid = el dueño  (p. ej. 0, "root")
```

El proceso tiene por tanto **la autoridad de root**, aunque el usuario que lo
inició sea perfectamente normal. Cada comprobación que hace el kernel — ¿puede
este proceso leer `/etc/shadow`? ¿escribir un archivo? ¿matar a otro proceso? —
se responde con `euid`, es decir, "sí, es root".

`foosd` es un demonio de red. Enlaza un puerto y luego hace `fork()` de un hijo
por conexión. Un fork *hereda* el euid, así que cada hijo que gestiona una
conexión también es root. El desbordamiento en `vulnerable_handler()` de
`foosd` es por tanto un desbordamiento *dentro de un proceso root*.

**Diagnostícalo tú mismo cuando el demonio esté corriendo:**

```console
$ ./foosd ...            # mira la línea de log que imprime al arrancar
[foosd 1234] startup: ruid=1000 euid=0 -> ROOT process
```

y desde el exploit:

```console
$ ./foosc -t leak
foosc: target euid=0 ruid=1000
```

---

## 2. El laboratorio de un vistazo

| Archivo | Rol |
|------|------|
| `foosd.c` | El demonio deliberadamente vulnerable (dueño de los errores). Ejecútalo como *binario setuid-root* para la demo del shell root. |
| `foosc.c` | El exploit. Usa por defecto la técnica de shellcode `setreuid + execve` de 32 bytes. |
| `shellcode.S` | El shellcode de referencia; `make verify` lo compara con el array de bytes en `foosc.c`. |
| `tests/pty_suid_test.c` | Harness de prueba. Conduce a `foosc` a través de un pseudo-terminal y prueba tanto "corrió un shell" *como* "era root" (`uid=0(`). |
| `Makefile` | Compilación, helpers `setuid`/`unsetuid`, matriz de prueba. |
| `README.md` | Este archivo. |

> **¿Por qué una pty?** La última acción del exploit es retransmitir tu
> terminal al shell que corre en la víctima. Un pipe o un here-doc llega al
> lado equivocado de esa retransmisión; se requiere un terminal real.

---

## 3. Inicio rápido

```console
$ make                       # compila todo, como tu usuario normal
$ make setuid                # una vez, pide sudo: chown root + chmod u+s
$ make run                   # arranca foosd en 127.0.0.1:2343
$ make test-suid             # matriz completa; shellcode + ret2win-root deben dar root
```

Prueba de humo interactiva:

```console
$ ./foosc -t shellcode
...
foosc: target euid=0 ruid=1000
foosc: shell is on the victim (root if foosd is SUID); relaying
# id
uid=0(root) gid=0(root) groups=0(root)      <-- eres root, en la víctima
# exit
```

Cuando termines:

```console
$ make stop
$ make unsetuid             # higiene: no dejes nunca un binario root SUID suelto
```

---

## 4. *¿Cuándo pongo el bit SUID?* — la respuesta que pediste

Exactamente **una vez, después de compilar, antes de arrancar el demonio para
las demos de shell root** — y solo en una máquina que sea tuya, apta para tirar
y desconectada de la red:

```console
$ make            # compila foosd, foosc, las pruebas
$ make setuid     # <-- EL MOMENTO. sudo chown root:root foosd && sudo chmod u+s foosd
$ make run        # arranca DESPUÉS de poner el bit
```

Dos reglas que importan más que el momento exacto:

1. **Ponlo solo cuando el binario esté terminado.** Si recompilas (`make` /
   `make clean`) después de poner el bit, te topas con "Permission denied" al
   escribir los archivos de salida propiedad de root — y si fuerzas la
   recompilación, el toolchain recrea el archivo **sin** la `s` y deshace la
   configuración en silencio. El orden canónico en cualquier recompilación es
   por tanto

   ```console
   $ make unsetuid && make && make setuid
   ```

2. **Quítalo cuando termines.** `make unsetuid`. Un binario setuid vivo,
   propiedad de root, con un error explotable en tu árbol no es una herramienta
   pedagógica, es un agujero root con un error de compilación entre él y nada.
   En una máquina compartida o de producción: **no hagas nada de esto.** El
   demonio además se niega por defecto a enlazarse a nada que no sea loopback
   (ver §7).

Si ejecutas el exploit *sin* poner nunca el bit, nada se rompe — el payload
sigue aterrizando y sigues obteniendo un shell. La diferencia está en un solo
número, y el exploit lo dice en voz alta:

```console
foosc: WARNING: the daemon is NOT running with euid 0.
       The payload will still land, but the shell will be
       a plain user shell, not root.
       Fix:  sudo make setuid
```

El resultado "funcionó, pero no root" es en sí parte del laboratorio.
Recuérdalo para la siguiente sección.

---

## 5. El mecanismo — y el giro que hace interesante a SUID

### 5.1 El desbordamiento (idéntico a `food`)

El handler de `foosd` da a un `read()` 512 bytes de confianza mientras le
ofrece un búfer de pila de 64 bytes:

```c
char buf[64];
n = read(fd, buf, 512);        /* <- CWE-120: 448 bytes sobre el borde */
```

En x86-64 la pila crece hacia abajo. El exploit escribe 64 bytes de basura para
llenar `buf`, 8 para llenar el puntero de marco guardado y 8 más para
reemplazar la **dirección de retorno guardada**. Cuando `vulnerable_handler`
ejecuta `ret`, la CPU hace pop del valor del atacante en `RIP` — ejecución de
código controlada por el atacante. El exploit encuentra la distancia exacta (88
bytes para esta compilación) analizando la salida de `objdump` en lugar de
hardcodearla, así que el número sobrevive a las recompilaciones.

### 5.2 El giro: el shell se niega a ser root

Aquí es donde pensar "bug SUID → spawn /bin/sh → root" iría mal, y por qué este
laboratorio tiene exactamente la forma que tiene.

Cuando corre un programa setuid-root, su `ruid` sigue siendo el usuario que lo
inició y su `euid` es root. Si el programa — o el atacante — lanza ahora un
shell:

* `execve("/bin/sh")` **no** cambia los uids; el nuevo proceso hereda
  `(ruid=1000, euid=0)`.
* bash (y dash) **comprueba exactamente ese estado al arrancar**. Del manual de
  bash: *"If the shell is started with the effective user (group) id not equal
  to the real user (group) id, and the -p option is not supplied, … the
  effective user id is set to the real user id."*

Así que el shell se mira y *suelta root* — una defensa que los autores de
shell construyeron exactamente contra este ataque (la justificación histórica
era el problema de las shells setuid / scripts setuid). El resultado son los
casos "funcionó, pero no root":

| Técnica | Qué ejecuta | uid resultante |
|-----------|------------------|---------------|
| `ret2win` | el `win()` de `foosd` → `execl("/bin/sh")` | **1000** — shell aterrizado, root reseteado por bash |
| `ret2libc` | `system("/bin/sh")` → `sh -c '/bin/sh'` fresco | **1000** — el mismo reset, un nivel abajo |
| `ret2win-root` | el `win_root()` de `foosd` → `setreuid(0,0); execl("/bin/sh")` | **0** — ruid limpiado desde C |
| `shellcode` | 32 bytes: `setreuid(0,0); execve("/bin/sh")` | **0** — ruid limpiado desde código máquina |

Las que alcanzan root se diferencian de las que no lo hacen en exactamente una
idea: **limpian el uid *real*, no solo el efectivo.**

```c
setuid(0)          /* pone euid a 0, pero ruid sigue en 1000:
                      bash sigue viendo euid != ruid y resetea IGUAL.  */
setreuid(0, 0)     /* pone AMBOS: ruid = euid = 0.
                      bash ve uids iguales y conserva root.            */
```

Por eso el shellcode `/bin/sh` clásico que encuentras por todo internet
empieza con un syscall de limpieza de uid — y por eso el shellcode aquí es de
32 bytes en lugar de 23: las primeras cinco instrucciones son

```asm
xor    edi, edi      ; ruid = 0
xor    esi, esi      ; euid = 0
push   0x71          ; 113 = __NR_setreuid
pop    rax
syscall
```

### 5.3 Entonces, ¿qué es el exploit, de principio a fin?

1. `foosc` lee el banner de `foosd` por el socket. Obtiene:
   - `ids=0/1000` — euid/ruid (el autodiagnóstico SUID)
   - `stack=…` y `libc=…` — punteros (las fugas de ASLR)
   - `BUF=…` — la dirección exacta del búfer que está a punto de desbordar
2. Del binario objetivo (vía `objdump`) aprende `rip_off` y las direcciones de
   `win()` / `win_root()`.
3. De *su propia* libc (vía `/proc/self/maps` + `dlsym` + un escaneo de memoria)
   mide los offsets de `system`, `read`, `/bin/sh` y un gadget `pop rdi; ret` —
   nada está hardcodeado.
4. Ensambla el payload. Para `-t shellcode`, es:
   `[código setreuid+execve de 32 bytes][basura hasta RIP][ret-fix][dirección de buf]`.
5. El `read()` de `foosd` se desborda; el `ret` aterriza en el shellcode; el
   kernel ejecuta `setreuid(0,0)` (sin problema: euid 0 es privilegiado) y luego
   `execve` de `/bin/sh`. bash arranca con `ruid == euid == 0` y sigue siendo
   root.
6. `foosc` retransmite tu terminal a ese shell root, hasta que escribes `exit`.

Un detalle de comodidad que cuesta caro a la gente si se pasa por alto: el
exploit prueba cada comportamiento de limpieza de uid **sin** necesitar primero
el bit setuid. Ejecuta `make test` antes de `make setuid`, y verás cada técnica
aterrizar un shell con `ROOT=MISSING`; ejecuta `make test-suid` después de
`make setuid`, y `ROOT=SEEN` aparece en las dos técnicas que limpian el uid
real. Ese A/B es toda la lección, representada en diez segundos.

---

## 6. Los viejos one-liners — y por qué la mayoría están muertos

Si has leído sobre SUID, has leído sobre secuestro de `PATH`, `LD_PRELOAD` y
shells setuid. Los tres son clásicos, y los tres fallan en un sistema moderno
contra *este programa*. Vale la pena saber exactamente por qué, porque las
razones son las defensas que obtienes gratis:

| Clase de ataque | Vieja afirmación | Por qué falla en una máquina moderna |
|--------------|-----------|------------------------------|
| `LD_PRELOAD` de una biblioteca maliciosa | "El programa setuid carga mi `.so` y ejecuta mi código como root." | El kernel marca un binario setuid como **AT_SECURE**; glibc ignora entonces `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_DEBUG` y compañía. El entorno se trata como *entrada no confiable*. `LD_PRELOAD` contra un binario setuid es un no-op. |
| Secuestro de `PATH` (`system("ls")` con un PATH envenenado) | "Apunta PATH a un directorio con mi `ls` falso; el programa root lo ejecutará." | Otra cara de la misma defensa: un proceso AT_SECURE recibe un **PATH saneado** (un valor por defecto seguro, más o menos `/usr/local/bin:/usr/bin:/bin`) para `system()`/`execvp`, así que el directorio envenenado nunca se consulta. |
| Inyección de comando `system()` setuid | "El comando inyectado se ejecuta con euid 0." | `system()` ejecuta el comando en un `/bin/sh` nuevo, y ese shell — §5.2 — resetea `euid = ruid` al arrancar. El comando inyectado se ejecuta con el uid *real*. (Sigue siendo un error; solo que ya no escala vía `/bin/sh`.) |
| Shell root setuid en disco (`cp /bin/sh /tmp; chmod u+s`) | "Ejecútalo, consigue root." | Exactamente la defensa de arriba, y esa es la razón por la que las distros modernas no entregan ningún shell root setuid. Incluso si consigues fabricar uno, bash se niega a mantener euid 0 salvo que se inicie con `-p`. |

Lo que sigue vivo, y eso es este laboratorio: **el programa *ya* es root cuando
corre.** No necesitas el entorno ni `system()`; necesitas que el programa
ejecute *tu* código (vía un error de corrupción de memoria) mientras es
privilegiado, y que tu código sea lo bastante cuidadoso para corregir él mismo
el desajuste de uids — `setreuid(0,0)` — antes de entregarte un shell. La
corrupción de memoria + SUID es la combinación que todavía termina en `uid=0`,
y eso es exactamente por qué los lenguajes seguros en memoria, las canaries y
las pilas no-ejecutables no son una decisión de moda.

---

## 7. Las barandillas de seguridad integradas en el demonio

`foosd` es deliberadamente la *peor* pieza de software de este repositorio, así
que también lleva más barandillas:

1. **Solo loopback, impuesto.** `foosd` rechaza cualquier dirección de bind
   fuera del loopback, salvo que pases `-L`. Un listener setuid-root en una
   interfaz real es un servicio root remoto; el rechazo es el valor por defecto,
   para que el estado peligroso tenga que escribirse deliberadamente.
2. **Autodiagnóstico.** Al arrancar registra `ruid`/`euid` y si corre como root,
   para que la consola muestre el estado del que depende el exploit.
3. **El log nunca llega al cliente.** El demonio reserva un descriptor de log
   privado antes de que los sockets reemplacen a fd 1, para que la salida del
   crash-reporter y las rutas internas no puedan leerse de vuelta por el cable
   por el atacante.
4. **Crash-reporter.** Un handler de SIGSEGV registra `RIP`/`RSP` — el valor que
   el atacante escribió en la dirección de retorno — para que una toma de
   control exitosa sea visible en `foosd.log` en lugar de ser una muerte
   silenciosa.
5. **`make unsetuid`.** Quitar el bit está scripteado, porque dejarlo puesto es
   el modo de fallo que la gente realmente tiene.

---

## 8. Mitigaciones — qué detiene cada una y qué *no* detiene

Aplicadas a `foosd` vía `make hardened`, una a una o juntas:

| Mitigación | Qué detiene | Qué *no* detiene |
|------------|---------------|-------------------------|
| `-fstack-protector-strong` (canary) | El desbordamiento: `ret` detecta una canary destruida y aborta antes de que se use la dirección del atacante. Detiene aquí **las cuatro** técnicas — comparten el único `read()` vulnerable. | Nada por *diseño*: el binario sigue siendo setuid-root; otro error (format-string-`%n`, heap-overflow, use-after-free) no tiene canary que disparar. |
| `-fPIE -pie` (ASLR para el binario) | El uso de direcciones `win()`/`win_root()` predecibles (las técnicas ret2win). | La técnica de shellcode, si todavía se filtra una dirección de pila (línea `BUF=`). |
| `-z noexecstack` (NX / W^X) | El shellcode: la CPU se niega a buscar instrucciones en una página solo-de-datos, así que un salto a `buf` es un SIGSEGV. | ROP — ejecutar código que ya existe (`ret2libc`). |
| Las tres juntas | Un binario difícil de desbordar, randomizado, con pila no ejecutable. Así se ve una build endurecida normal. | El bit setuid. **Un binario SUID endurecido sigue siendo un binario SUID.** Si sobrevive cualquier error de memoria alcanzable, sigue siendo "error en un proceso root". |

La prueba en consola es `make test-hardened`, que intercambia la build
endurecida y muestra las técnicas muriendo en la canary, mientras
`foosd_hardened.log` captura `*** stack smashing detected ***`.

Dos mitigaciones de nivel de diseño que ningún flag de compilador entrega, y
que el laboratorio principal (`food`) también usa:

- **Mínimo privilegio.** Un demonio para un puerto no privilegiado (2343 >
  1024) no tiene ninguna necesidad legítima de root. Un `foosd` correcto
  enlazaría y luego haría `setgroups`/`setgid`/`setuid` a una cuenta no
  privilegiada y *confirmaría que se mantuvo* (la versión correcta está en la
  fuente como `drop_privs()`, nunca llamada — el no-lamarlo es el error n.º 3
  del laboratorio).
- **Limita el read.** `n = read(fd, buf, sizeof(buf) - 1)`. Una línea correcta
  supera a todos los flags de compilador de la tabla.

---

## 9. El protocolo wire (para que puedas leer el demonio con netcat)

```text
FOOSD 1.0 - deliberately vulnerable SUID service
Type 'quit' to disconnect. Buffer = 64 bytes, read accepts 512.
FOOSD 1.0 ids=0/1000 leak stack=0x7ffd... libc=0x7f...
BUF=0x7ffd...
```

* `ids=euid/ruid` — no podía imprimirse como `euid=`/`ruid=`, porque el harness
  de prueba prueba un shell haciendo grep del `uid=` literal, y el banner no
  debe contenerlo (una sonda que comparte la firma con la respuesta es una
  trampa clásica de falso positivo; ver el comentario en `foosd.c`). El harness
  además exige la forma estricta de salida `id` — `uid=NNN(...)` — para que nada
  de lo que imprima el demonio o el exploit pueda satisfacer la comprobación
  por accidente: el propio "target euid=… ruid=…" de `foosc` contiene `uid=`
  como subcadena, lo que una vez hizo que una prueba endurecida reportara un
  shell que nunca había corrido.
* `stack=`, `libc=`, `BUF=` — las fugas de ASLR: dejan que el shellcode y
  ret2libc calculen direcciones exactas.

---

## 10. Ejercicios

1. **Considera la degradación no-root.** Ejecuta `make test` *antes* de `make
   setuid`, y luego otra vez después. Explica el cambio a `ROOT=SEEN` con la
   historia ruid/euid de la §5.2.
2. **Lee el crash.** Ejecuta `./foosc -t demo -n` y luego lee `foosd.log`. La
   línea `RIP=0x4141414141414141` es la basura del atacante — la prueba de que
   es el desbordamiento, no el azar, quien controla la ejecución.
3. **Añade la canary.** `make hardened` y modifica tú mismo el bucle
   `test-hardened`; la línea de log `*** stack smashing detected ***` es la
   defensa funcionando.
4. **Desactiva la fuga.** Comenta la línea `BUF=` en `foosd.c`, recompila, y
   mira `-t shellcode` pasar de determinista a un juego de adivinanzas. Esa
   única línea es la razón por la que los bypass reales de ASLR son todo un
   campo.
5. **El experimento `-p`.** En una copia de `win()`, cambia `execl("/bin/sh",
   "sh", NULL)` por `execl("/bin/sh", "sh", "-p", NULL)` y observa root. `-p`
   es la salida de emergencia documentada del guardián del shell — y la razón
   por la que el consejo "solo haz spawn de un shell" de los viejos write-ups es
   incompleto.
6. **¿Por qué no `setuid(0)`?** Reescribe el shellcode para llamar a `setuid(0)`
   en lugar de `setreuid(0,0)` (syscall 105). El shell sigue aterrizando — y
   sigue cayendo a `uid=1000`. Es el experimento de una sola línea más
   instructivo de todo el repositorio.

---

## 11. Seguridad y limpieza

- Solo loopback, por defecto y por diseño; `-L` enlaza más lejos, y solo una VM
  apta para tirar debería siquiera considerarlo.
- Esto es un laboratorio de shell root. No lo ejecutes en una máquina que
  importe, y no apuntes `foosc -h` a algo que no poseas.
- Rito de limpieza: `make stop` y luego `make unsetuid`, y si quieres el árbol
  impecable otra vez: `sudo make clean`.

```console
$ make stop
$ make unsetuid
```