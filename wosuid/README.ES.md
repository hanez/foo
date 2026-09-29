# El laboratorio `wosuid` — RCE root **sin** bit setuid

```
  foowosd   un demonio deliberadamente vulnerable que es root porque fue
            *INICIADO* como root  (puerto 2344, solo loopback por defecto)
  foowosc   el exploit: convierte un desbordamiento de pila en un **shell**
            root ejecutando shellcode — los mismos 23 bytes que rompieron el
            demonio user-level `food` del laboratorio principal
```

Este es el tercer laboratorio de la serie. La misma cadena de herramientas de
exploit, el mismo estilo, una diferencia fundamental:

| Laboratorio | cómo el proceso objetivo se vuelve root              | ¿shell `uid=0(root)`? |
|----------|------------------------------------------------|----------------------|
| food/fooc | nunca — es un demonio de usuario normal       | no |
| foosd/foosc | el bit SUID (`chmod u+s`) — euid 0, ruid 1000 | sí (exige `setreuid` en el shellcode, porque bash resetea euid→ruid) |
| **foowosd/foowosc** | **ninguno — root *inicia* el demonio** (sudo / systemd `User=root`) | **sí (shellcode `execve` normal)** |

El bit setuid es un *medio de transporte* de privilegios — no los privilegios
mismos. Un demonio iniciado por root tiene uids real, efectivo y guardado todos
iguales a 0. Para el kernel es root, punto; no puede ni quiere saber si el
proceso llegó ahí vía `+s` en un archivo o vía `sudo ./foowosd`. El
desbordamiento de un demonio iniciado por root es por tanto un exploit root —
*"no tengo binarios SUID" no es lo mismo que "no soy explotable".*

Esa es toda la lección de este laboratorio. Todo lo demás es el mecanismo.

---

## Inicio rápido (lo que pidió el usuario)

```
cd wosuid
make                 # compila el demonio, el exploit y el harness de prueba
```

### Lo auténtico — ejecuta el demonio como **root**

```
sudo make run-root      # inicia foowosd como uid 0 (proceso, no estado de archivo)
make test-root          # cada técnica debe dar ahora uid=0(root)
```

### ¿Sin sudo? El camino de kernel idéntico vía un user namespace

```
make run-root-ns        # uid 0 en un user namespace — no se necesita contraseña
make test-root          # los mismos veredictos; lo usa la CI y todo el que no tenga sudo
```

### Referencia — demonio como tu usuario normal (root en ninguna parte)

```
make run                # foowosd corre con tus uids
make test               # los exploits aterrizan shells, pero se espera que `root` sea MISSING
```

### Rito de limpieza (siempre: esto es un laboratorio de shell root)

```
make stop
```

`foowosd` *no* es setuid, y nada en este directorio hace nunca `chmod +s` —
ese es el punto. El estado peligroso es **el proceso**, no el archivo.

---

## Cuando te digan que pongas el bit SUID

No te lo van **a** decir. Este laboratorio no tiene deliberadamente ningún bit
SUID:

- `foowosd` se compila, te pertenece y tiene permisos normales como cualquier
  otro programa.
- Se vuelve root como hacen los demonios reales — siendo *iniciado* por root.
- `make run-root` usa `sudo` para exactamente eso, y `make run-root-ns`
  consigue un proceso uid 0 real sin nada de eso.

El bit Suid pertenece al laboratorio *hermano* (`foosd`). El contraste entre los
dos es el plan de estudios:

1. Laboratorio SUID: el bit da **euid 0, pero ruid 1000** → `execve("/bin/sh")`
   es degradado por el guardián de bash (`euid != ruid` → reset) → el shellcode
   debe llamar primero a `setreuid(0,0)` (payload de 32 bytes).
2. Este laboratorio: root **inicia** el proceso → **ruid == euid == 0** → el
   guardián no tiene nada que resetear → el shellcode `execve` normal de 23
   bytes conserva root.

El mismo desbordamiento. La misma técnica. *Origen* de privilegios diferente,
forma de payload distinta. Esa es la lección en miniatura.

---

## El protocolo

Sea cual sea el tipo de cliente que se conecta, foowosd lo saluda con:

```
FOOWOSD 1.0 ids=0/0 leak stack=0x7ffd… libc=0x7f…      (el banner + las fugas)
BUF=0x7ffd…                                             (la dirección del búfer)
```

`ids=euid/ruid` es el canal *"¿soy root?"*. foowosc imprime una advertencia
fuerte cuando euid no es 0 (es decir, iniciaste el demonio como usuario
normal): el payload sigue aterrizando, pero el shell se convierte en un shell
de usuario, y llamar al exploit "roto" sería falso — solo que no escala.

> Nota ortográfica: `ids=`, no `euid=`/`ruid=`. El harness de prueba prueba un
> `id` vivo haciendo match de la forma literal `uid=NNN(`, así que el banner
> nunca debe contener una subcadena que satisfaga ella misma la comprobación.
> (En el laboratorio SUID, exactamente esa trampa produjo un falso positivo
> espectacular.)

---

## Las técnicas de exploit (`foowosc -t …`)

Las cuatro rutas de exploit de abajo funcionan contra foowosd. Cuando el demonio
es root, **todo lo que hace spawn de algo da root** — a diferencia del
laboratorio SUID, donde ret2win/ret2libc eran degradados silenciosamente a uid
1000 por el guardián de bash. Aquí no hay desajuste que vigilar.

| `-t`          | qué ocurre                                                       | cuando el demonio es root |
|---------------|---------------------------------------------------------------------|---------------------|
| `shellcode`   | `execve("/bin/sh", NULL, NULL)` de 23 bytes corre en la pila.        | **shell root** (por defecto) |
| `ret2win`     | salto a `win()` → `execl("/bin/sh")`                                | **shell root** |
| `ret2libc`    | ROP: `pop rdi; ret` → `"/bin/sh"` → `system()`                      | **shell root** |
| `demo`        | solo desbordamiento de basura — espera un SIGSEGV en el log del demonio | crash, por diseño |
| `leak`        | solo imprime fugas, no envía payload                                | n/a |

```
./foowosc -t shellcode       # interactivo; objetivo por defecto 127.0.0.1:2344
./foowosc -t shellcode -n    # enviar y reportar, sin sesión interactiva
```

Una sesión interactiva exitosa retransmite tu terminal al shell *en la víctima*
— hay exactamente un shell en el cuadro, y es `/bin/sh` corriendo como root
dentro de foowosd. Escribe `id` para ver `uid=0(root)`.

### Por qué no hay una técnica `ret2win-root` aquí

foosc tenía una — saltaba a un `win_root()` que llamaba a `setreuid(0,0)`
antes del exec, porque un proceso setuid corría con un uid real que todavía
decía 1000. Un proceso *iniciado* por root ya tiene el uid real en 0; no hay
nada que limpiar, así que la función y la técnica extra no enseñarían nada.
Eliminada.

---

## Qué hace foowosc, paso a paso

1. **Análisis estático** — `objdump -d` de `./foowosd`. Encuentra
   `vulnerable_handler`, `win()`, el `lea -0x50(%rbp)` que direcciona `buf`, y
   el primer `ret` desnudo. A partir del desplazamiento calcula
   `rip_off = 80 + 8 = 88`. Nada está hardcodeado; sobrevive a una
   recompilación.
2. **Auto-introspección** — lee su propio `/proc/self/maps` y hace `dlsym()` de
   `system`/`read` para aprender los *offsets* de libc. La base libc del
   objetivo es `leaked_read − off_read`, luego `system = base + off_system`,
   etc. Esa aritmética de delta es la razón por la que los exploits sobreviven
   a las versiones de libc.
3. **Conecta** — lee el banner/las fugas (`ids=`, `stack=`, `libc=`, `BUF=`).
4. **Construye el payload** — para `shellcode`: 23 bytes de código máquina,
   basura hasta `rip_off`, luego la RIP guardada = `buf` (para que el `ret`
   salte dentro del código). Para `ret2win`/`ret2libc`: direcciones calculadas
   del análisis — no se necesita ejecución de pila.
5. **El fix de alineación** — un `ret` desnudo secuestrado da a la callee
   `rsp ≡ 8 (mod 16)`, y el código SSE2 de glibc falla con `movaps` en una pila
   mal alineada (el crash-reporter registra `si_addr=(nil)` — la pista).
   foowosc inserta un gadget `ret` extra antes del objetivo real y restaura la
   invariante. Una técnica de guante de seda en un laboratorio de shellcode,
   pero es la diferencia entre un payload que "a veces funciona" y uno que
   siempre funciona.
6. **Envía, luego retransmite** — el proceso víctima *es* el shell; este
   proceso solo splissea bytes. Sin shell local, sin otro lector — el bug del
   cursor de lectura único (un byte comido por trozo) está documentado en
   `become_shell()`.

---

## Los errores deliberados del demonio (todos en `foowosd.c`, todas clases CWE reales)

| # | error | CWE | nota |
|---|-----|-----|------|
| 1 | `read(fd, buf, 512)` en un búfer de pila de 64 bytes | CWE-120 | el desbordamiento: 448 bytes más allá de `buf`, RIP guardada en +88 |
| 2 | solo `snprintf(line, …, "%.*s", …)`; pero `%` del atacante en el camino de eco | CWE-134 | la fuga es aquí el payload real; un `%n` en un proceso *root* sería write-what-where como root |
| 3 | los hijos conservan root mientras manejan entradas no confiables | CWE-271 | el `drop_privs()` correcto (setgroups→setgid→setuid, en ese orden, con verificación) está en el archivo, comentado, *deliberadamente nunca llamado* |
| 4 | `ids=`, `stack=`, `libc=`, `BUF=` revelados a cualquier cliente | CWE-200 | sin estas fugas, las técnicas de shellcode y ret2libc no podrían calcular direcciones (ASLR las vencería) |

El handler tiene exactamente la misma forma `buf[64]`/`read(512)` que los otros
dos laboratorios, así que el pipeline común de reconocimiento basado en objdump
funciona sin cambios.

---

## Cómo inspeccionar el demonio (camino de aprendizaje)

```
make status            # ¿corre? ¿como qué uid? se muestra el estado del archivo
make run-root          # o run / run-root-ns
./foowosc -t leak      # mira el banner y las fugas, no envíes nada
./foowosc -t demo      # desbordamiento de basura -> SIGSEGV, registrado con RIP/rsp
./foowosc -t shellcode # el shell root interactivo
make test-root         # matriz completa, todas las técnicas, --must-root
```

Crash-reporter: En SIGSEGV, el demonio registra la dirección de error, RIP y
RSP. Un `ret` dentro de un `0x4141…` no canónico falla en el `ret` mismo (RIP
como `0x4028xx`, `si_addr=(nil)`) — bueno saberlo antes de leer mal una línea
de log como desreferencia NULL.

---

## Por qué el shellcode es de 23 bytes, no de 32

```
31 f6        xor esi, esi            ; argv = NULL
31 d2        xor edx, edx            ; envp = NULL
48 bf 2f62696e2f736800 movabs rdi, "/bin/sh\0"
57           push rdi
48 89 e7     mov rdi, rsp
6a 3b        push 0x3b               ; 59 = execve
58           pop rax
0f 05        syscall
```

El laboratorio SUID necesita `setreuid(0,0)` delante de esto. Este laboratorio
no, por la razón repetida en todas partes: **ruid ya es 0**, porque root inició
el proceso. `make verify` prueba que los bytes en `foowosc.c` son, byte a byte,
lo que `shellcode.S` ensambla.

---

## Mitigaciones — qué cambia `make hardened`

Build endurecida (`-fstack-protector-strong -fPIE -pie -z noexecstack`):

| técnica | `foowosd` vulnerable | `foowosd_hardened` endurecido |
|-----------|----------------------|------------------------------|
| `shellcode` | shell root (pila ejecutable) | SIGSEGV en la comprobación de canary / NX |
| `ret2win` / `ret2libc` | shell root | la canary aborta el `ret` — pero nota: una build *PIE* también vuelve aleatorias estas direcciones |
| `demo` | SIGSEGV, registrado | SIGSEGV, registrado |

`make test-hardened` lo demuestra en vivo. La observación importante no es solo
que las mitigaciones mataron las técnicas — es que **no** convirtieron al
demonio en "no-root". Una build endurecida que todavía se *inicia* como root
sigue siendo un demonio root; la mitigación solo sube el listón para el
atacante. Mínimo privilegio (`drop_privs()`) y seguridad de memoria son dos
errores distintos, y un demonio que no necesita root no debería tenerlo.

---

## Barandillas de seguridad (la misma política que el laboratorio SUID)

- **Solo loopback.** foowosd se niega a enlazarse a nada que no sea `127.0.0.1`
  / `localhost` / `::1`, salvo que des `-L`. Un demonio root en una interfaz
  real es un *servicio root remoto*. `-L` existe solo para mostrar la
  barandilla; no lo uses en algo que importe.
- **El estado se registra en voz alta.** Al arrancar imprime `ruid/euid` y si
  esto es un proceso root, para que siempre sepas qué resultado de exploit
  esperar.
- **Los veredictos vienen del código de salida** en `make test*` (el código de
  retorno del harness pty), nunca de hacer grep de su stdout — la salida
  grepable miente.
- **La pty debe correr en cooked + ECHO off**, si no, el harness ecoa su propia
  línea de comandos y falsifica el marcador. El harness apaga ECHO y mantiene
  ECHONL activo.
- **Rito de limpieza:** `make stop` después de cada sesión. Si el demonio es
  propiedad de root, `stop` te dice que ejecutes `sudo pkill -x foowosd`.
- Nunca ejecutes esto en un host que te importe. Existe para repartir shells
  `uid=0` por la interfaz loopback.

---

## Ejercicios

1. Ejecuta `make run` (demonio de usuario), luego `./foowosc -t shellcode`.
   ¿Por qué el shell no es root? (Comprueba `ids=` en el banner — foowosc te
   lo dice antes de que siquiera te conectes.)
2. `make stop && sudo make run-root && make test-root`. Explica a partir de la
   línea del banner por qué las cuatro técnicas dan ahora `uid=0(root)`.
3. Encuentra `drop_privs()` en `foowosd.c` y lee *por qué el orden* de
   `setgroups → setgid → setuid` importa. Decide dónde en `main()` encajaría, y
   qué se vuelve la superficie de ataque del laboratorio cuando de verdad se
   llama.
4. Calcula `rip_off` a mano desde `objdump -d foowosd`: encuentra el
   `lea -0xNN(%rbp)` de `buf` dentro de `vulnerable_handler`, luego `NN + 8`.
   foowosc hace exactamente eso; comprueba su cálculo contra el tuyo.
5. `make hardened && make test-hardened`. ¿Qué técnica cae ante la canary, y
   cuál ante NX? ¿Por qué el endurecimiento no cambia lo que `make status`
   reporta sobre *el proceso*?
6. Compara los shellcodes de los dos laboratorios: 23 bytes aquí, 32 para
   foosd. ¿Qué hacen los 9 bytes extra, y por qué solo se necesitan en el caso
   SUID?
7. Lee el comentario de `become_shell()` sobre el cursor de lectura único.
   Reconstruye mentalmente el estado de fallo: dos lectores en un socket
   significa que el shell de login come un byte por trozo — "uid=1000…" llega
   como "id=1000…". ¿Por qué un proceso relay no puede tener nunca este error?

---

## Archivos

```
foowosd.c                 el demonio root vulnerable (cada línea comentada)
foowosc.c                 el exploit (cada línea comentada)
shellcode.S               el assembly de referencia para el payload de 23 bytes
tests/pty_wosuid_test.c   el harness pty (marcador + comprobación estricta de forma id)
Makefile                  build / run / run-root / run-root-ns / test /
                          test-root / verify / hardened / clean …
```

Laboratorios hermanos: `../food.c`/`../fooc.c` (referencia user-level, puerto
2342) y `../suid/` (demonio root SUID `foosd`/`foosc`, puerto 2343). Los
puertos son deliberadamente distintos — puedes ejecutar los tres a la vez y
cruzar sus líneas `ids=` en el banner.