# food / fooc — un desbordamiento de búfer de pila, desde ambos lados

Un laboratorio de seguridad en C99 en dos mitades:

- **`food.c`** — un demonio TCP deliberadamente vulnerable. Tiene un
  desbordamiento de búfer de pila real, de libro de texto ([CWE-120](https://cwe.mitre.org/data/definitions/120.html)), más un par
  de errores de propina.
- **`fooc.c`** — un exploit contra él. Calcula el offset del desbordamiento
  desensamblando el programa objetivo en tiempo de ejecución, lee las fugas de
  direcciones del demonio y consigue un shell en la "víctima" sobrescribiendo
  una dirección de retorno guardada.

El punto no es el shell. El punto es que puedas seguir de principio a fin cómo
un error de seguridad de memoria se convierte en ejecución de código arbitrario
— y después ver exactamente qué mitigaciones detienen cada eslabón de esa
cadena. Cada línea de ambos programas está comentada, porque el mecanismo es la
lección.

```
                  tu terminal
                         |
                     ./fooc   (exploit)
                         |
                    TCP 127.0.0.1:2342
                         |
                     ./food   (demonio vulnerable)
                         |
                 fork() -> vulnerable_handler() -> overflow -> ret -> tu código
```

---

## ⚠️ Lee esto primero

**`food` es un servicio de red deliberadamente roto. Solo se enlaza a
`127.0.0.1`, y ese valor por defecto es deliberado — déjalo así.**

- **No** lo ejecutes en una máquina que te importe, ni en nada que contenga
  datos.
- **No** lo enlaces a `0.0.0.0` ni a una interfaz de red real. Está
  deliberadamente diseñado para ser explotable de forma remota.
- Apuntar `fooc` a un host que no posees o para el que no tienes permiso
  escrito de prueba es un delito informático en la mayoría de las
  jurisdicciones — también bajo la UK Computer Misuse Act y la US Computer
  Fraud and Abuse Act.
- Se enlaza a un puerto no privilegiado (>1024), así que no necesitas root. No
  lo "mejores" añadiendo capabilities o ejecutándolo como servicio del sistema.
- Cada conexión se gestiona en un hijo `fork()`, y `food` hace reap de él, así
  que los crashes no se acumulan. Si luego encuentras docenas de `sh`
  sueltos, `pkill -x sh` es la limpieza.

En caso de duda: este laboratorio es para una máquina virtual o un contenedor,
en una red que tú controlas, en una máquina sin nada que echaras de menos.

---

## Inicio rápido

```sh
make            # compila food, fooc y los harness de prueba
make run        # arranca food en 127.0.0.1:2342, desacoplado en segundo plano
make test       # ejecuta las tres técnicas de exploit
make stop       # detiene el demonio
```

Después, a mano:

```sh
./fooc -t leak        # mira las fugas de direcciones que food revela
./fooc -t demo -v     # envía basura; ve morir a food con SIGSEGV
./fooc -t ret2win -i  # salta a una función que ya existe -> shell
```

### Requisitos

| Herramienta | Para qué | Notas |
|---|---|---|
| `gcc` (o clang) | compilar | C99. Probado con gcc 16.2 |
| `objdump` | `fooc` | binutils. `fooc` lo invoca en tiempo de ejecución |
| `nasm` | `make verify` | solo para contrastar el shellcode; se omite si falta |
| `gdb` | `make debug` | opcional |
| Linux, x86-64 | ambos | el payload y la caza de gadgets dependen de la arquitectura |

`fooc` también necesita `-ldl` para `dlsym()`; el Makefile lo gestiona.

---

## El bug

Una línea en `food.c` es toda la superficie de ataque:

```c
char buf[FOOD_BUFSZ];                  /* 64 bytes  */
n = read(fd, buf, FOOD_READMAX);       /* hasta 512 bytes de la red */
```

64 bytes de destino, 512 aceptados. El atacante sobrescribe 448 bytes más allá
del final del búfer, y como la pila crece hacia abajo, "más allá del final"
significa "dentro del marco superior" — y ahí es exactamente donde están el
puntero de marco guardado y la **dirección de retorno guardada**.

En una función x86-64 compilada a `-O0`:

```
  direcciones altas
  +------------------------+  rbp + 16 : locales de la llamadora
  |  ...                   |
  +------------------------+  rbp +  8 : DIRECCIÓN DE RETORNO GUARDADA   <-- se vuelve RIP
  |  saved rbp (8 bytes)   |
  +------------------------+  rbp      : nuestro puntero de marco
  |  line[128]             |
  |  buf[64]               |  <- rsp: lo que read() llena
  +------------------------+
  direcciones bajas
```

Cuando la función retorna, `leave; ret` hace pop de los 8 bytes en `RIP`, y la
CPU salta donde el atacante ha decidido. Todo lo demás en este laboratorio es
aritmética sobre hacia dónde apuntar.

Para esta compilación, los números son: `buf` mide 64 bytes, el `rbp` guardado
mide 8, así que la dirección de retorno está en el offset **88** desde el
inicio de `buf`. `fooc` no hardcodea eso — desensambla `food` y encuentra el
`lea -0x50(%rbp)` delante de `call read@plt`, así que sigue funcionando si
cambias `FOOD_BUFSZ`.

> gcc ya te lo dice. Compilar `food` imprime:
> `warning: 'read' writing 512 bytes into a region of size 64 overflows the
> destination [-Wstringop-overflow=]`. Nunca silencies esa advertencia en
> código real. Es seguridad gratuita.

---

## Las tres técnicas

`fooc -t <technique>`. Están en el orden en que un atacante real trabajaría en
ellas, porque cada una necesita lo que la anterior te enseñó.

### 1. `ret2win` — controla el puntero de instrucción

```
[ 88 bytes de basura ][ la dirección del win() de food ]
                       ^ saved rbp
                                        ^ se vuelve RIP
```

`win()` es una función del programa objetivo que hace exec de `/bin/sh`.
Sobrescribir la dirección de retorno con su dirección es todo el exploit.

**Lo que enseña:** tienes control arbitrario del puntero de instrucción.
Tampoco necesita fuga, porque el binario está compilado con `-no-pie`, así que
`win()` está en una dirección fija para siempre.

**El equivalente del mundo real** no es "los ataques son fáciles", sino "no
envíes backdoors no documentadas en binarios de red". Si existe una función
como `win()` en tu binario, un desbordamiento de búfer la encontrará. Es
literalmente la clase de CVE de backdoor de Juniper ScreenOS.

**Defensa:** `-fPIE` (o ASLR) randomiza la dirección de carga, así que el
atacante debe conocer la dirección — lo que normalmente significa que primero
necesita una fuga. Por eso `ret2win` falla contra `food_hardened`.

### 2. `ret2libc` — llama a lo que sea, por su nombre

```
[ basura ][ pop rdi; ret ][ dirección de "/bin/sh" ][ dirección de system() ]
          ^^^^^^^^^^^^     ^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^
          pone rdi          la cadena a enviar      la función a llamar
```

En ejecución: `ret` hace pop de `pop rdi; ret` en RIP; eso hace pop del puntero
`"/bin/sh"` en `RDI`; su `ret` hace pop de `system()` en RIP, mientras `RDI`
sigue sosteniendo la cadena. `system("/bin/sh")` se ejecuta.

Los gadgets (`pop rdi; ret`) no están en `food` — esta glibc no tiene
`__libc_csu_init` — así que `fooc` los encuentra escaneando la memoria viva de
libc en busca del par de bytes `5f c3`. Localiza libc vía `/proc/self/maps`,
encuentra los offsets de `system` y `"/bin/sh"` con `dlsym()` y calcula la base
a partir de la fuga que `food` divulga. Nada está hardcodeado, así que
sobrevive a una actualización de libc.

**Lo que enseña:** una vez que puedes controlar `RIP`, puedes encadenar
instrucciones *existentes*. Eso es return-oriented programming, y así se ven
casi todos los exploits reales, porque no requiere memoria ejecutable provista
por el atacante.

**Defensa:** ninguno de los flags del compilador lo detiene solo. Funciona
contra un binario PIE, con NX, con canary — mientras el atacante tenga una
fuga. Las defensas son "no tengas el desbordamiento" y "no fugues
direcciones". Ver la tabla más abajo.

### 3. `shellcode` — ejecuta tu propio código máquina

23 bytes, colocados al inicio del búfer, con `RIP` apuntando a ellos:

```asm
xor    esi, esi                    ; envp = NULL
xor    edx, edx                    ; argv = NULL
movabs rdi, 0x68732f6e69622f       ; rdi = "/bin/sh\0" como 8 bytes crudos
push   rdi                         ; deja la cadena en la pila
mov    rdi, rsp                    ; rdi = &"/bin/sh"
push   0x3b                        ; 59 = __NR_execve
pop    rax
syscall                           ; ahora somos un shell
```

Esta es la forma más pura del bug: el atacante entrega *las instrucciones*, no
solo la dirección de instrucciones que ya existen. No se necesitan offsets de
libc, así que en principio funciona contra un objetivo estáticamente enlazado,
totalmente randomizado.

`make verify` ensambla `shellcode.S` y lo compara con el array de bytes embebido
en `fooc.c`, para que no puedan divergir.

**Defensa:** **NX** (también llamado W^X, "no execute"). Marcar la pila como no
ejecutable hace que el hardware se niegue a buscar instrucciones en ella, y el
`ret` aterriza en una página que no puede ejecutarse. Por eso `make food` pasa
`-z execstack`: una pila Linux normal es `rw-p`, no `rwx`, y la técnica muere
con SIGSEGV en `RIP = la dirección del payload`. La lección más importante del
laboratorio es que cada uno de estos bytes funciona solo porque se le dijo al
compilador que dejara la pila ejecutable. Ese flag está activado para bien de
nadie.

### También incluido

| Modo | Qué hace |
|---|---|
| `-t leak` | se conecta, imprime fugas, no envía nada |
| `-t demo` | envía `rip_off + 8` bytes de `0x41`, así que `RIP` se vuelve `0x4141...` y el demonio muere. Prueba el bug sin ningún conocimiento de direcciones |
| `-t sled` | un ret-sled, conservado deliberadamente como ejemplo **fallido**. Sin una fuga, harías fuerza bruta a ASLR llenando el búfer con la dirección de un `ret`. No puede funcionar aquí: `food` acepta 512 bytes, así que el sled tiene ~53 ranuras frente a ~28 bits de entropía. Implementado para que puedas verlo fallar y confirmar que el mecanismo es de verdad "la CPU sigue una cadena de rets" |

---

## La tabla de mitigaciones

Esta es la parte que hay que recordar. Cada fila es una defensa real, y la
columna derecha muestra qué hace realmente con la cadena de eventos.

| Mitigación | Cómo activarla | Qué detiene | Qué *no* detiene |
|---|---|---|---|
| **Limita read** | `n = read(fd, buf, sizeof buf - 1);` | **Todo.** El bug no existe, así que nada aguas abajo importa | Nada — es el único fix completo |
| **Canary de pila** | `-fstack-protector-strong` (por defecto en gcc) | El `ret`: la canary se comprueba al final de la función, así que la destrucción se detecta y el proceso aborta antes de que se haga pop de `RIP` | Un error en una función *sin* array (nada que proteger); un desbordamiento que se mantiene por debajo de la canary; todo lo que no retorna normalmente |
| **NX / W^X** | `-z noexecstack` (el valor por defecto) | Shellcode. Las instrucciones del payload no pueden buscarse | ret2win y ret2libc por completo. Son *la razón* de que exista ROP |
| **PIE + ASLR** | `-fPIE` + ASLR=2 (ambos por defecto) | Las direcciones hardcodeadas de ret2win. Todo se mueve en cada ejecución | Todo donde el atacante tenga una fuga. ASLR sube el precio de un exploit; no es un fix. Nota que la pila, el heap y mmap se randomizan, pero el *contenido* del binario principal no — eso es lo que usan las cadenas ROP |
| **No fugues** | ningún `printf("%p")` a clientes; inicializa antes de imprimir | La fuga de información que hace que ASLR sea "gratis" en vez de "caro" | — |
| **No uses `printf(user_data)`** | `printf("%s", buf)` en lugar de `printf(buf)` | Errores de cadena de formato: lecturas de pila `%x`, escrituras arbitrarias `%n` — un *otro* camino a RCE | — |
| **No uses rutas no confiables** | valida y `openat()` bajo un directorio fijo | Path traversal ([CWE-22](https://cwe.mitre.org/data/definitions/22.html)) | — |
| **CET / shadow stack** | `-fcf-protection=full`, soporte de kernel y CPU | El `ret` en sí: la shadow stack recuerda la *verdadera* dirección de retorno y falla ante un desajuste. Atrapa cadenas ROP que usan el `ret` de hardware | Ataques que nunca `ret` (call-oriented, o sobrescribir el objetivo de un puntero de función con una cadena de gadgets que no necesita retorno) |
| **Lenguajes seguros** | Rust, Go, C# para código nuevo | Toda la clase. Las comprobaciones de límites se imponen en ejecución, no se esperan en la revisión | — |

### Compruébalo por ti mismo

```sh
make run            # demonio vulnerable
make test           # las tres técnicas funcionan

make test-hardened  # el mismo código fuente, mitigaciones activadas
```

`test-hardened` compila `food_hardened` con `-fstack-protector-strong -fPIE
-pie -z noexecstack`, lo intercambia, vuelve a ejecutar las tres y luego
restaura el vulnerable. Verás:

```
### stack segment: 'rw-p' (NOT executable) is what you want to see
--- ret2win   was stopped by the mitigations (as expected)
--- ret2libc  was stopped by the mitigations (as expected)
--- shellcode was stopped by the mitigations (as expected)
```

Y en el log del demonio endurecido, la canary que se dispara:

```
*** stack smashing detected ***: terminated
```

Léelo con cuidado, porque es la línea más importante de todo el laboratorio:
**la canary atrapó a ret2win, no PIE.** Las tres técnicas mueren en la canary,
porque las tres pasan por el mismo `read()` y destruyen el mismo marco. NX solo
detiene además el *código* del shellcode; PIE solo rompe además la dirección
hardcodeada. Actívalas una a una, y descubrirás que la mayoría de las
mitigaciones individuales te dejan expuesto a algo.

---

## Archivos

| Archivo | Propósito |
|---|---|
| `food.c` | el demonio vulnerable. 6 errores numerados, cada uno con su fix en el comentario |
| `fooc.c` | el exploit. Reconocimiento de offset basado en objdump, reconocimiento de libc basado en `/proc`, 4 constructores de payload |
| `shellcode.S` | los 23 bytes de shellcode como assembly, para que sean legibles y verificables. `fooc` los lleva en línea y no lo necesita en ejecución |
| `Makefile` | compila, prueba y la comparación endurecida |
| `tests/pty_test.c` | conduce a `fooc` a través de un pseudo-terminal y comprueba salida real de shell |
| `tests/sock_test.c` | verificador independiente sobre un socket crudo, para que el resultado no dependa de `fooc` |
| `food.log` | el log del demonio. Tu prueba de lo que ocurrió |

---

## Dos errores de este laboratorio que merece la pena entender

No son los errores del programa objetivo. Son errores del exploit y de su
harness de prueba, y ambos produjeron mentiras convincentes. Están
documentados en la fuente donde viven; están aquí porque los patrones de fallo
son instructivos.

### Alineación de pila: el crash que no es una desreferencia NULL

**Síntoma.** La toma de control aterriza correctamente — `gdb` te muestra
dentro de `win()` — y entonces muere lo primero que hace `win()`, un
`dprintf()`. El handler de SIGSEGV informa de `RIP` profundo dentro del
formateador de glibc y una dirección de error de `(nil)`, lo que parece
exactamente un puntero corrupto.

**Causa.** La ABI System V AMD64 exige una alineación de pila de 16 bytes. Un
`ret` normal restaura `%rsp` exactamente como el `call` correspondiente lo
guardó, así que la invariante se preserva gratis. Nuestro `ret` desnudo no:
después de él, `%rsp = buf + rip_off`. Aquí, `buf` está alineado a 16 bytes y
`rip_off` es 88, así que la callee recibe una pila de 8 mod 16. glibc está
compilada con SSE2, y `movaps` **falla** ante un operando mal alineado. En x86
eso levanta `#GP`, no `#PF`, así que el kernel no tiene dirección de error e
informa `si_addr = 0`. Ese NULL es la pista: un error de alineación disfrazado
de desreferencia NULL.

**Fix.** Un gadget `ret` *en el offset `rip_off`*, que desplaza el objetivo
real 8 bytes, porque cada `ret` añade exactamente 8 a `%rsp`. El orden es
crítico: una versión anterior pegaba el `ret` *después* del objetivo y
producía `[ padding | target | ret ]`, donde el `ret` final nunca se alcanza y
el fix no hace nada en silencio. Un `ret` perdido que parece un error es casi
siempre intencional.

### Un socket, dos lectores: el byte que desapareció

**Síntoma.** El shellcode se reportó como funcionando. Luego se endureció el
harness pty (apagar `ECHO`, para que la terminal dejara de ecoar su propia
línea de comandos hacia sí misma), y la técnica empezó a fallar. Más
profundo, cada técnica perdía exactamente un byte del inicio de cada trozo de
salida: `uid=1000(hanez)` se imprimía como `id=1000(hanez)`, `PWNED-OK` como
`WNED-OK`, `Linux 7.2.7` como `inux 7.2.7`.

**Causa.** `fooc` solía hacer `dup2()` del socket sobre su propio stdin/stdout
y `execv()` de un `/bin/sh` *local*, mientras un hijo relay forkado también leía
el mismo socket para mover la salida al terminal. Al kernel le da igual que los
dos cooperen. Un socket de stream tiene **un** cursor de lectura, y cada lector
lo mueve, así que los bytes se reparten entre ellos de forma impredecible. El
shell local — un shell de login interactivo — leía exactamente un byte y lo
desechaba, cada vez. `strace -f` lo mostró de inmediato:

```
read(0, "u", 1)                              <- el shell local, comiéndose un byte
read(4, "id=1000(hanez) gid=1000(hanez) g".., 310)   <- el relay, 1 byte corto
```

**Fix.** No hay ningún shell en este lado, punto. Hay exactamente un shell en
todo el cuadro, y está en la víctima, dentro del proceso secuestrado, con la
conexión TCP como su stdin/stdout. Este lado solo mueve bytes. Si alguna vez
necesitas dos consumidores de un stream, ese stream necesita un único lector
que lo demultiplexe deliberadamente.

**La meta-lección.** El primer resultado "funcionante" fue un falso positivo,
producido porque la pty ecoaba su propia línea de comandos hacia sí misma, y el
fix de ese falso positivo es lo que reveló el error real. Las pruebas que no
pueden fallar son peores que ninguna prueba, porque convierten "no lo sé" en
"funciona". Un harness de prueba merece la misma sospecha que el código que
prueba.

---

## Experimentar con ello

Cosas que merece la pena probar, más o menos en el orden en que más aprendes de
ellas:

1. **Cambia `FOOD_BUFSZ` a 128.** Vuelve a ejecutar `fooc`. Debería seguir
   funcionando sin cambios, porque lee el offset del desensamblado. Luego
   rómpelo a mano — hardcodea 88 — y míralo crashear. Después añade un segundo
   array entre `buf` y los registros guardados, y mira cómo lo gestiona el
   reconocimiento automático.

2. **Añade `-Wformat-security` y mira qué hace el camino de cadena de
   formato.** Envía `%p %p %p %n` y mira a `food` fugando la pila.

3. **Usa gdb.** `make debug`, luego:
   ```gdb
   (gdb) break food.c:393        # el read() que se desborda
   (gdb) run -p 2342
   (gdb) info registers rsp rbp
   (gdb) x/24gx $rsp             # observa dónde está la dirección de retorno
   (gdb) c                        # en otra terminal: ./fooc -t ret2win
   ```
   El handler de SIGSEGV registra `REG_RIP` y `REG_RSP`, así que `food.log` te
   dice si la toma de control aterrizó, incluso cuando el hijo muere antes de
   que puedas adjuntarte.

4. **Borra el fix de alineación** en `fooc.c` y mira el error `#GP` con la
   firma `si_addr = 0`. Luego lee `/proc/sys/kernel/randomize_va_space` y
   piensa qué randomiza ASLR y qué no.

5. **Rompe la resolución de símbolos de libc** y mira cómo se adapta `fooc`.
   Todo el punto del enfoque `/proc/self/maps` es que ningún offset está
   hardcodeado.

6. **Escribe una cuarta técnica.** Una cadena tipo `ret2csu` si puedes
   encontrar `__libc_csu_init`, o una cadena SROP (los marcos `sigreturn` te
   dejan controlar todos los registros a la vez). Ambas son ROP puro y no
   necesitan memoria ejecutable.

7. **Arregla `food.c` de verdad**, un error a la vez, y vuelve a ejecutar el
   exploit después de cada fix. El orden de la tabla al inicio de `food.c` es
   más o menos el orden correcto en que pensar: limita primero el read, porque
   nada más importa hasta que el bug desaparece.

---

## Limpieza

```sh
make stop        # detiene food
make clean       # elimina los productos de compilación; deja food.log en paz
pkill -x sh      # solo si tienes shells sueltos de una prueba que salió mal
```

Nota: `pkill -x food` coincide exactamente con el **nombre** del proceso. No
uses `pkill -f ./food` — ese patrón también coincide con el shell donde lo
escribes y mata tu propia sesión. No es una hipótesis; ocurrió mientras se
construía este laboratorio.
