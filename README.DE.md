# food / fooc — ein Stack-Pufferüberlauf, von beiden Seiten

Ein C99-Sicherheitslabor in zwei Hälften:

- **`food.c`** — ein absichtlich angreifbarer TCP-Daemon. Er enthält einen
  echten, lehrbuchreifen Stack-Pufferüberlauf ([CWE-120](https://cwe.mitre.org/data/definitions/120.html)) und nebenbei noch ein
  paar weitere Bugs.
- **`fooc.c`** — ein Exploit dafür. Er berechnet das Overflow-Offset, indem er
  das Zielprogramm zur Laufzeit disassembliert, liest Adress-Leaks vom Daemon
  und erhält eine Shell auf dem „Opfer", indem er eine gespeicherte
  Rücksprungadresse überschreibt.

Es geht nicht um die Shell. Es geht darum, dass man Ende-zu-Ende mitverfolgen
kann, wie aus einem Speichersicherheitsfehler eine beliebige Codeausführung
wird — und dann genau sieht, welche Gegenmaßnahmen welchen Schritt dieser
Kette stoppen. Jede Zeile beider Programme ist kommentiert, denn der Mechanismus
ist die Lektion.

```
                   dein Terminal
                         |
                     ./fooc   (Exploit)
                         |
                    TCP 127.0.0.1:2342
                         |
                     ./food   (angreifbarer Daemon)
                         |
                 fork() -> vulnerable_handler() -> Overflow -> ret -> dein Code
```

---

## ⚠️ Bitte zuerst lesen

**`food` ist ein absichtlich kaputter Netzwerkdienst. Er bindet ausschließlich
an `127.0.0.1`, und dieser Standard ist Absicht — bitte lass ihn so.**

- Führe ihn **nicht** auf einer Maschine aus, die dir wichtig ist, oder auf
  irgendetwas mit Daten darauf.
- Binde ihn **nicht** an `0.0.0.0` oder eine echte Netzwerkschnittstelle. Er
  ist bewusst remote ausnutzbar.
- Ein `fooc` gegen einen Host zu richten, der dir nicht gehört bzw. für den du
  keine schriftliche Testgenehmigung hast, ist in den meisten Rechtsordnungen
  ein Computersabotage-Straftatbestand — auch nach dem UK Computer Misuse Act
  und dem US Computer Fraud and Abuse Act.
- Er bindet einen unprivilegierten Port (>1024), du brauchst also kein root.
  „Verbessere" ihn nicht, indem du Capabilities hinzufügst oder ihn als
  Systemdienst laufen lässt.
- Jede Verbindung wird in einem per `fork()` erzeugten Kindprozess behandelt,
  und `food` reaped ihn, sodass sich keine Abstürze ansammeln. Falls du danach
  dutzende streunende `sh`-Prozesse vorfindest, ist `pkill -x sh` die
  Aufräumlösung.

Im Zweifel: Dieses Labor ist für eine virtuelle Maschine oder einen Container
gedacht, in einem Netzwerk, das du kontrollierst, auf einer Maschine, auf der
dir nichts fehlen würde.

---

## Schnellstart

```sh
make            # baut food, fooc und die Test-Harnesses
make run        # startet food auf 127.0.0.1:2342, abgelöst im Hintergrund
make test       # führt alle drei Exploit-Techniken aus
make stop       # stoppt den Daemon
```

Danach von Hand:

```sh
./fooc -t leak        # sieh dir die Adress-Leaks an, die food ausgibt
./fooc -t demo -v     # sende Datenmüll; beobachte, wie food mit SIGSEGV stirbt
./fooc -t ret2win -i  # springe zu einer Funktion, die bereits existiert -> Shell
```

### Voraussetzungen

| Werkzeug | Wofür | Hinweise |
|---|---|---|
| `gcc` (oder clang) | Bauen | C99. Getestet mit gcc 16.2 |
| `objdump` | `fooc` | binutils. `fooc` ruft es zur Laufzeit auf |
| `nasm` | `make verify` | nur zum Gegenprüfen des Shellcodes; wird übersprungen, wenn nicht vorhanden |
| `gdb` | `make debug` | optional |
| Linux, x86-64 | beides | Payload und Gadget-Suche sind architekturspezifisch |

`fooc` benötigt außerdem `-ldl` für `dlsym()`; das erledigt das Makefile.

---

## Der Bug

Eine Zeile in `food.c` ist die gesamte Angriffsfläche:

```c
char buf[FOOD_BUFSZ];                  /* 64 Bytes   */
n = read(fd, buf, FOOD_READMAX);       /* bis zu 512 Bytes aus dem Netzwerk */
```

64 Bytes Ziel, 512 Bytes akzeptiert. Der Angreifer überschreibt 448 Bytes über
das Ende des Puffers hinaus, und weil der Stack nach unten wächst, bedeutet
„über das Ende hinaus" „in den darüberliegenden Frame hinein" — und genau dort
liegen der gespeicherte Frame-Pointer und die **gespeicherte
Rücksprungadresse**.

In einer kompilierten x86-64-Funktion bei `-O0`:

```
  hohe Adressen
  +------------------------+  rbp + 16 : Locals des Aufrufers
  |  ...                   |
  +------------------------+  rbp +  8 : GESPEICHERTE RÜCKSPRUNGSADRESSE <-- wird zu RIP
  |  saved rbp (8 Bytes)   |
  +------------------------+  rbp      : unser Frame-Pointer
  |  line[128]             |
  |  buf[64]               |  <- rsp: das, was read() füllt
  +------------------------+
  niedrige Adressen
```

Wenn die Funktion zurückkehrt, poppt `leave; ret` diese 8 Bytes in `RIP`, und
die CPU springt dorthin, wo der Angreifer es bestimmt hat. Alles andere in
diesem Labor ist Arithmetik darüber, wohin gedeutet werden soll.

Für diesen Build sind die Zahlen: `buf` ist 64 Bytes, das gespeicherte `rbp`
ist 8, die Rücksprungadresse liegt also bei Offset **88** vom Anfang von `buf`.
`fooc` härtet das nicht ein — es disassembliert `food` und findet das
`lea -0x50(%rbp)` vor dem `call read@plt`, sodass es weiter funktioniert, wenn
du `FOOD_BUFSZ` änderst.

> gcc weist bereits darauf hin. Das Bauen von `food` druckt:
> `warning: 'read' writing 512 bytes into a region of size 64 overflows the
> destination [-Wstringop-overflow=]`. Unterdrücke diese Warnung in echtem Code
> nie. Sie ist geschenkte Sicherheit.

---

## Die drei Techniken

`fooc -t <technique>`. Sie stehen in der Reihenfolge, in der ein echter
Angreifer sie durcharbeiten würde, denn jede braucht, was die vorherige dich
gelehrt hat.

### 1. `ret2win` — den Befehlszeiger kontrollieren

```
[ 88 Bytes Müll ][ Adresse von food's win() ]
                 ^ saved rbp
                                  ^ wird zu RIP
```

`win()` ist eine Funktion im Zielprogramm, die `/bin/sh` ausführt. Das
Überschreiben der Rücksprungadresse mit ihrer Adresse ist der gesamte Exploit.

**Was es lehrt:** Du hast beliebige Kontrolle über den Befehlszeiger. Es
braucht außerdem kein Leak, weil das Binärprogramm `-no-pie` gebaut ist, sodass
`win()` für immer an einer festen Adresse sitzt.

**Das reale Äquivalent** ist nicht „Angriffe sind einfach", sondern „verschiffe
keine undokumentierten Hintertüren in Netzwerk-Binärprogrammen". Wenn eine
Funktion wie `win()` in deinem Binärprogramm existiert, wird ein
Pufferüberlauf sie finden. Das ist wörtlich die Hintertür-Klasse von Juniper
ScreenOS (CVE).

**Verteidigung:** `-fPIE` (oder ASLR) randomisiert die Ladeadresse, sodass der
Angreifer die Adresse kennen muss — was meistens bedeutet, dass er zuerst ein
Leak braucht. Deshalb schlägt `ret2win` gegen `food_hardened` fehl.

### 2. `ret2libc` — Beliebiges aufrufen, beim Namen

```
[ Müll ][ pop rdi; ret ][ Adresse von "/bin/sh" ][ Adresse von system() ]
         ^^^^^^^^^^^^     ^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^
         setzt rdi        der zu übergebende String  die aufzurufende Funktion
```

Zur Ausführungszeit: `ret` poppt `pop rdi; ret` in `RIP`; das poppt den
`"/bin/sh"`-Pointer in `RDI`; dessen `ret` poppt `system()` in `RIP`, wobei
`RDI` weiterhin den String hält. `system("/bin/sh")` läuft.

Die Gadgets (`pop rdi; ret`) stecken nicht in `food` — diese glibc hat kein
`__libc_csu_init` — daher findet sie `fooc`, indem es den Live-libc-Speicher
nach dem Bytepaar `5f c3` durchsucht. Es lokalisiert libc über
`/proc/self/maps`, findet die Offsets von `system` und `"/bin/sh"` mit
`dlsym()` und berechnet die Basis aus dem Leak, das `food` veröffentlicht.
Nichts ist fest verdrahtet, sodass der Exploit ein libc-Update überlebt.

**Was es lehrt:** Wenn du einmal `RIP` kontrollierst, kannst du *vorhandene*
Befehle aneinanderreihen. Das ist Return-Oriented Programming, und es ist, wie
fast alle echten Exploits aussehen, weil es keinen vom Angreifer gelieferten
ausführbaren Speicher braucht.

**Verteidigung:** Keine der Compiler-Flags stoppt das allein. Es funktioniert
gegen ein PIE-Binärprogramm, mit NX, mit Canary — solange der Angreifer ein
Leak hat. Die Verteidigungen sind „habe den Overflow nicht" und „leake keine
Adressen". Siehe Tabelle unten.

### 3. `shellcode` — eigenen Maschinencode ausführen

23 Bytes, platziert am Anfang des Puffers, mit `RIP`, das auf sie zeigt:

```asm
xor    esi, esi                    ; envp = NULL
xor    edx, edx                    ; argv = NULL
movabs rdi, 0x68732f6e69622f       ; rdi = "/bin/sh\0" als 8 rohe Bytes
push   rdi                         ; lege den String auf den Stack
mov    rdi, rsp                    ; rdi = &"/bin/sh"
push   0x3b                        ; 59 = __NR_execve
pop    rax
syscall                           ; wir sind jetzt eine Shell
```

Das ist die reinste Form des Bugs: Der Angreifer liefert die *Befehle*, nicht
nur die Adresse von Befehlen, die bereits existieren. Keine libc-Offsets nötig,
also funktioniert es im Prinzip gegen ein statisch gelinktes, vollständig
randomisiertes Ziel.

`make verify` assembliert `shellcode.S` und vergleicht es mit dem Byte-Array,
das in `fooc.c` eingebettet ist, sodass die beiden nicht auseinanderlaufen
können.

**Verteidigung:** **NX** (auch W^X, „no execute"). Wenn der Stack als
nicht-ausführbar markiert ist, weigert sich die Hardware, Befehle von ihm zu
holen, und das `ret` landet auf einer Seite, die nicht ausführbar ist. Deshalb
übergibt `make food` die Flag `-z execstack`: Ein Standard-Linux-Stack ist
`rw-p`, nicht `rwx`, und die Technik stirbt mit SIGSEGV bei `RIP = die Adresse
des Payloads`. Die mit Abstand wichtigste Lektion des Labors ist, dass jedes
dieser Bytes nur funktioniert, weil dem Compiler gesagt wurde, den Stack
ausführbar zu lassen. Diese Flag ist für niemandes Wohl eingeschaltet.

### Außerdem enthalten

| Modus | Was es tut |
|---|---|
| `-t leak` | verbindet, druckt die Leaks, sendet nichts |
| `-t demo` | sendet `rip_off + 8` Bytes `0x41`, sodass `RIP` zu `0x4141...` wird und der Daemon stirbt. Beweist den Bug ganz ohne Adresswissen |
| `-t sled` | ein Ret-Sled, bewusst als **fehlschlagendes** Beispiel behalten. Ohne ein Leak würdest du ASLR brute-forcen, indem du den Puffer mit der Adresse eines `ret` füllst. Hier kann es nicht funktionieren: `food` akzeptiert 512 Bytes, der Sled hat also ~53 Slots gegen ~28 Bit Entropie. Implementiert, damit du zusehen kannst, wie es scheitert, und bestätigst, dass der Mechanismus wirklich „die CPU folgt einer Kette von rets" ist |

---

## Die Tabelle der Gegenmaßnahmen

Das ist der Teil, den man sich merken sollte. Jede Zeile ist eine echte
Verteidigung, und die rechte Spalte zeigt, was sie tatsächlich mit der
Ereigniskette macht.

| Gegenmaßnahme | So aktivierst du sie | Was sie stoppt | Was sie *nicht* stoppt |
|---|---|---|---|
| **Read begrenzen** | `n = read(fd, buf, sizeof buf - 1);` | **Alles.** Der Bug existiert nicht, also ist nichts nachgelagert relevant | Nichts — das ist der einzige vollständige Fix |
| **Stack-Canary** | `-fstack-protector-strong` (gcc-Standard) | Das `ret`: Der Canary wird beim Funktionsende geprüft, der Einschlag wird also erkannt und der Prozess bricht ab, bevor `RIP` gepoppt wird | Ein Bug in einer Funktion *ohne* Array (nichts zu schützen); ein Overflow, der unter dem Canary bleibt; alles, was nicht normal zurückkehrt |
| **NX / W^X** | `-z noexecstack` (der Standard) | Shellcode. Die eigenen Befehle des Payloads können nicht geholt werden | ret2win und ret2libc vollständig. Sie sind der *Grund*, warum ROP existiert |
| **PIE + ASLR** | `-fPIE` + ASLR=2 (beides Standard) | ret2wins fest verdrahtete Adressen. Alles bewegt sich bei jedem Lauf | Alles, wo der Angreifer ein Leak hat. ASLR erhöht die Kosten eines Exploits; es ist kein Fix. Beachte, dass Stack, Heap und mmap randomisiert sind, der *Inhalt* des Haupt-Binärprogramms jedoch nicht — das ist es, was ROP-Ketten verwenden |
| **Nicht leaken** | kein `printf("%p")` an Clients; vor dem Drucken initialisieren | Der Informations-Leak, der ASLR von „teuer" zu „gratis" macht | — |
| **Kein `printf(user_data)`** | `printf("%s", buf)` statt `printf(buf)` | Format-String-Bugs: `%x`-Stack-Reads, `%n`-beliebige Schreibzugriffe — ein *zweiter* Weg zu RCE | — |
| **Keine unvertrauenswürdigen Pfade** | validieren und `openat()` unter einem festen Verzeichnis | Pfad-Traversal ([CWE-22](https://cwe.mitre.org/data/definitions/22.html)) | — |
| **CET / Shadow Stack** | `-fcf-protection=full`, Kernel- und CPU-Unterstützung | Das `ret` selbst: Der Shadow Stack merkt sich die *echte* Rücksprungadresse und fault bei einem Mismatch. Fängt ROP-Ketten ab, die Hardware-`ret` verwenden | Angriffe, die nie `ret` ausführen (call-oriented, oder das Ziel eines Funktionspointers mit einer Gadget-Kette überschreiben, die keine Rückkehr braucht) |
| **Sichere Sprachen** | Rust, Go, C# für neuen Code | Die ganze Klasse. Bounds-Checks werden zur Laufzeit geprüft, nicht beim Review erhofft | — |

### Selbst ausprobieren

```sh
make run            # angreifbarer Daemon
make test           # alle drei Techniken funktionieren

make test-hardened  # gleicher Quellcode, Gegenmaßnahmen an
```

`test-hardened` baut `food_hardened` mit `-fstack-protector-strong -fPIE -pie
-z noexecstack`, tauscht es ein, führt alle drei erneut aus und legt danach
das angreifbare wieder zurück. Du wirst sehen:

```
### stack segment: 'rw-p' (NOT executable) is what you want to see
--- ret2win   was stopped by the mitigations (as expected)
--- ret2libc  was stopped by the mitigations (as expected)
--- shellcode was stopped by the mitigations (as expected)
```

Und im Log des gehärteten Daemons das Auslösen des Canarys:

```
*** stack smashing detected ***: terminated
```

Lies das genau, denn es ist die wichtigste Zeile des ganzen Labors: **der
Canary hat ret2win erwischt, nicht PIE.** Alle drei Techniken sterben am
Canary, weil alle drei durch dasselbe `read()` gehen und denselben Frame
zerstören. NX stoppt nur zusätzlich den *Code* des Shellcodes; PIE bricht nur
zusätzlich die hart verdrahtete Adresse. Schalte sie einzeln an, und du wirst
feststellen, dass dich die meisten einzelnen Gegenmaßnahmen irgendetwas
ausgesetzt lassen.

---

## Dateien

| Datei | Zweck |
|---|---|
| `food.c` | der angreifbare Daemon. 6 nummerierte Bugs, jeder mit seinem Fix im Kommentar |
| `fooc.c` | der Exploit. objdump-basierte Offset-Erkennung, `/proc`-basierte libc-Erkennung, 4 Payload-Builder |
| `shellcode.S` | die 23 Shellcode-Bytes als Assembly, damit man sie lesen und verifizieren kann. `fooc` trägt sie inline und braucht das zur Laufzeit nicht |
| `Makefile` | baut, testet und liefert den gehärteten Vergleich |
| `tests/pty_test.c` | treibt `fooc` über ein Pseudo-Terminal und prüft auf echte Shell-Ausgabe |
| `tests/sock_test.c` | unabhängiger Verifizierer über einen rohen Socket, damit das Ergebnis nicht von `fooc` abhängt |
| `food.log` | das Log des Daemons. Dein Beweis, was passiert ist |

---

## Zwei Bugs in diesem Labor, die es wert sind, verstanden zu werden

Das sind nicht die Bugs des Zielprogramms. Es sind Bugs im Exploit und in
seiner Test-Harness, und beide haben überzeugende Lügen produziert. Sie sind im
Quellcode an ihrem Ort dokumentiert; hier stehen sie, weil die Ausfallmuster
lehrreich sind.

### Stack-Ausrichtung: der Absturz, der kein NULL-Deref ist

**Symptom.** Die Übernahme landet korrekt — `gdb` zeigt dich in `win()` — und
dann stirbt das allererste, was `win()` tut, ein `dprintf()`. Der
`SIGSEGV`-Handler meldet `RIP` tief im glibc-Formatter und eine Fehleradresse
von `(nil)`, was exakt wie ein korrupter Pointer aussieht.

**Ursache.** Die System-V-AMD64-ABI verlangt 16-Byte-Stack-Ausrichtung. Ein
normales `ret` stellt `%rsp` exakt auf das wieder her, was das zugehörige
`call` gespeichert hat, sodass die Invariante gratis erhalten bleibt. Unser
nacktes `ret` tut das nicht: Danach gilt `%rsp = buf + rip_off`. Hier ist `buf`
16-Byte-ausgerichtet und `rip_off` ist 88, der Callee bekommt also einen Stack,
der 8 mod 16 ist. glibc ist mit SSE2 kompiliert, und `movaps` **fault** bei
einem nicht ausgerichteten Operanden. Auf x86 löst das `#GP` aus, nicht `#PF`,
der Kernel hat also keine Fehleradresse und meldet `si_addr = 0`. Dieses NULL
ist der Hinweis: ein Ausrichtungsfehler, verkleidet als NULL-Deref.

**Fix.** Ein `ret`-Gadget *bei Offset `rip_off`*, das das echte Ziel um 8 Bytes
nach oben verschiebt, denn jedes `ret` addiert exakt 8 auf `%rsp`. Die
Reihenfolge ist entscheidend: Eine frühere Version hängte das `ret` *hinter*
das Ziel an und erzeugte `[ padding | target | ret ]`, wo das abschließende
`ret` nie erreicht wird und der Fix still nichts tut. Ein versprengtes `ret`,
das wie ein Fehler aussieht, ist fast immer Absicht.

### Ein Socket, zwei Leser: das verschwundene Byte

**Symptom.** Shellcode wurde als funktionierend gemeldet. Dann wurde die
pty-Harness strenger gemacht (Abschalten von `ECHO`, sodass das Terminal seine
eigene Befehlszeile nicht mehr zurückspiegelte) und die Technik begann zu
scheitern. Im Kern ließ jede Technik exakt ein Byte vom Anfang jedes
Ausgabeblocks fallen: `uid=1000(hanez)` wurde zu `id=1000(hanez)` gedruckt,
`PWNED-OK` zu `WNED-OK`, `Linux 7.2.7` zu `inux 7.2.7`.

**Ursache.** `fooc` pflegte den Socket per `dup2()` auf sein eigenes
stdin/stdout zu legen und eine *lokale* `/bin/sh` per `execv()` zu starten,
während ein geforktes Relay-Kind denselben Socket ebenfalls las, um die Ausgabe
zum Terminal zu befördern. Dem Kernel ist egal, dass die beiden kooperieren. Ein
Stream-Socket hat **einen** Read-Cursor, und jeder Leser bewegt ihn, sodass
Bytes unvorhersehbar zwischen ihnen aufgeteilt werden. Die lokale Shell las als
interaktive Login-Shell exakt ein Byte und verwarf es — bei jedem einzelnen
Mal. `strace -f` zeigte es sofort:

```
read(0, "u", 1)                              <- die lokale Shell, frisst ein Byte
read(4, "id=1000(hanez) gid=1000(hanez) g".., 310)   <- das Relay, 1 Byte zu wenig
```

**Fix.** Auf dieser Seite gibt es überhaupt keine Shell. Es gibt genau eine
Shell im gesamten Bild, und sie ist auf dem Opfer, im übernommenen Prozess, mit
der TCP-Verbindung als stdin/stdout. Diese Seite bewegt nur Bytes. Wenn du je
zwei Konsumenten eines Streams brauchst, braucht dieser Stream einen einzigen
Leser, der ihn bewusst demultiplexiert.

**Die Meta-Lektion.** Das erste „funktionierende" Ergebnis war ein
Fehlpositiv, das dadurch entstand, dass die pty die eigene Befehlszeile der
Harness zurückwarf, und der Fix für dieses Fehlpositiv ist es, der den echten
Bug bloßlegte. Tests, die nicht scheitern können, sind schlimmer als keine
Tests, weil sie „ich weiß es nicht" in „es funktioniert" verwandeln. Eine
Test-Harness verdient denselben Argwohn wie der Code, den sie testet.

---

## Daran herumexperimentieren

Dinge, die einen Versuch wert sind, ungefähr in der Reihenfolge, in der man
mehr lernt:

1. **Ändere `FOOD_BUFSZ` auf 128.** Führe `fooc` erneut aus. Es sollte ohne
   jede Änderung weiter funktionieren, weil es das Offset aus der Disassembly
   liest. Brich es dann von Hand — härt 88 ein — und sieh zu, wie es abstürzt.
   Füge dann zwischen `buf` und den gespeicherten Registern ein zweites Array
   ein und beobachte, wie die automatische Erkennung es verkraftet.

2. **Füge `-Wformat-security` hinzu und schau, was der Format-String-Pfad
   tut.** Sende `%p %p %p %n` und beobachte, wie `food` den Stack leakt.

3. **Nutze gdb.** `make debug`, dann:
   ```gdb
   (gdb) break food.c:393        # das read(), das überläuft
   (gdb) run -p 2342
   (gdb) info registers rsp rbp
   (gdb) x/24gx $rsp             # beachte, wo die Rücksprungadresse liegt
   (gdb) c                        # in einem anderen Terminal: ./fooc -t ret2win
   ```
   Der `SIGSEGV`-Handler loggt `REG_RIP` und `REG_RSP`, sodass dir `food.log`
   sagt, ob die Übernahme gelandet ist, selbst wenn das Kind stirbt, bevor du
   dich anhängen kannst.

4. **Lösche den Ausrichtungs-Fix** in `fooc.c` und beobachte den `#GP`-Fault
   mit der `si_addr = 0`-Signatur. Lies dann
   `/proc/sys/kernel/randomize_va_space` und denke darüber nach, was ASLR
   randomisiert und was nicht.

5. **Brich die libc-Symbolauflösung** und beobachte, wie `fooc` sich anpasst.
   Der ganze Sinn des `/proc/self/maps`-Ansatzes ist, dass kein Offset hart
   verdrahtet ist.

6. **Schreibe eine vierte Technik.** Eine `ret2csu`-artige Kette, wenn du
   `__libc_csu_init` findest, oder eine SROP-Kette (`sigreturn`-Frames lassen
   dich alle Register gleichzeitig kontrollieren). Beides ist reines ROP und
   braucht keinen ausführbaren Speicher.

7. **Fixe `food.c` richtig**, Bug für Bug, und führe den Exploit nach jedem
   Fix erneut aus. Die Reihenfolge in der Tabelle am Anfang von `food.c` ist
   ungefähr die richtige Reihenfolge zum Nachdenken: begrenze zuerst das read,
   denn nichts anderes zählt, bis der Bug weg ist.

---

## Aufräumen

```sh
make stop        # stoppt food
make clean       # entfernt Build-Produkte; lässt food.log in Ruhe
pkill -x sh      # nur, wenn du streunende Shells aus einem schiefgelaufenen Test hast
```

Beachte: `pkill -x food` matcht den Prozess**namen** exakt. Verwende nicht
`pkill -f ./food` — dieses Muster matcht auch die Shell, in die du es getippt
hast, und tötet deine eigene Session. Das ist keine Hypothese; es ist beim Bau
dieses Labors passiert.
