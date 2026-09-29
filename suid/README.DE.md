# SUID-Root-RCE-Labor — `foosd` (Daemon) + `foosc` (Exploit)

Ein Begleiter zum übergeordneten Labor (`food` / `fooc`, ein gewöhnlicher
Daemon, bei dem ein Pufferüberlauf eine *Benutzer*-Shell liefert). Dieses fügt
die gefährlichste Ein-Zeichen-Änderung in Unix hinzu: das **Setuid-Bit**.

> `chmod u+s` verwandelt „der Angreifer kann Code auf diesem Host ausführen" in
> „der Angreifer kann auf diesem Host Code als **root** ausführen".

Dieser Satz ist das gesamte Labor. Alles darunter ist der Mechanismus darunter,
aufgeschrieben, damit du beim Schreiben eigener Software genau weißt, welche
zwei oder drei Dateisystem-Attribute und Compiler-Flags entscheiden, ob ein
Speichersicherheitsbug in deinem Code eine Belästigung oder eine Root-Shell ist.

Die finale Demo, wenn `foosd` setuid-root ist, ist eine **Root-Shell**, die
über das Netzwerk geöffnet wird, indem 32 Bytes handgeschriebener Shellcode
ausgeführt werden.

---

## 1. Was das Setuid-Bit tatsächlich tut

Jeder Prozess unter Linux trägt drei User-IDs, und das Setuid-Bit bastelt an
der Beziehung zwischen ihnen:

| ID | Name | Bedeutung |
|----|------|---------|
| `ruid` | reale User-ID | das Konto, das den Prozess *gestartet* hat |
| `euid` | effektive User-ID | was der Kernel bei der Durchsetzung von Zugriffsrechten prüft |
| (saved) | gespeicherte Set-User-ID | ein „Slot", in den ein privilegierter Prozess später zurückkehren darf |

Ein normales Programm hat `ruid == euid`. Wenn du ein Binärprogramm mit
gesetztem Setuid-Bit ausführst, das root gehört:

```text
ruid = du        (z. B. 1000, "hanez")
euid = der Besitzer  (z. B. 0, "root")
```

Der Prozess hat also **roots Autorität**, obwohl der Benutzer, der ihn
gestartet hat, völlig gewöhnlich ist. Jede Prüfung, die der Kernel durchführt —
kann dieser Prozess `/etc/shadow` lesen? eine Datei schreiben? einen anderen
Prozess töten? — wird mit `euid` beantwortet, d. h. „ja, es ist root".

`foosd` ist ein Netzwerk-Daemon. Er bindet einen Port und `fork()`t dann pro
Verbindung ein Kind. Ein Fork *erbt* die euid, also ist auch jedes Kind, das
eine Verbindung behandelt, root. Der Overflow in `foosd`s
`vulnerable_handler()` ist daher ein Overflow *in einem Root-Prozess*.

**Diagnostiziere es selbst, sobald der Daemon läuft:**

```console
$ ./foosd ...            # siehe die Log-Zeile beim Start
[foosd 1234] startup: ruid=1000 euid=0 -> ROOT process
```

und vom Exploit aus:

```console
$ ./foosc -t leak
foosc: target euid=0 ruid=1000
```

---

## 2. Das Labor auf einen Blick

| Datei | Rolle |
|------|------|
| `foosd.c` | Der absichtlich angreifbare Daemon (besitzt die Bugs). Für die Root-Shell-Demo als *setuid-root*-Binärprogramm ausführen. |
| `foosc.c` | Der Exploit. Standard: die 32-Byte-`setreuid + execve`-Shellcode-Technik. |
| `shellcode.S` | Der Referenz-Shellcode; `make verify` vergleicht ihn mit dem Byte-Array in `foosc.c`. |
| `tests/pty_suid_test.c` | Test-Harness. Treibt `foosc` durch ein Pseudo-Terminal und beweist sowohl „eine Shell lief" als auch „sie war root" (`uid=0(`). |
| `Makefile` | Build, `setuid`/`unsetuid`-Helfer, Test-Matrix. |
| `README.md` | Diese Datei. |

> **Warum eine pty?** Die letzte Aktion des Exploits ist es, dein Terminal an
> die Shell weiterzuleiten, die auf dem Opfer läuft. Eine Pipe oder ein
> Here-Doc landet am falschen Ende dieser Weiterleitung; ein echtes Terminal
> ist erforderlich.

---

## 3. Schnellstart

```console
$ make                       # alles bauen, als dein normaler Benutzer
$ make setuid                # einmalig, fragt nach sudo: chown root + chmod u+s
$ make run                   # startet foosd auf 127.0.0.1:2343
$ make test-suid             # volle Matrix; shellcode + ret2win-root müssen root ergeben
```

Interaktiver Smoke-Test:

```console
$ ./foosc -t shellcode
...
foosc: target euid=0 ruid=1000
foosc: shell is on the victim (root if foosd is SUID); relaying
# id
uid=0(root) gid=0(root) groups=0(root)      <-- du bist root, auf dem Opfer
# exit
```

Wenn du fertig bist:

```console
$ make stop
$ make unsetuid             # Hygiene: nie ein Root-SUID-Binärprogramm liegen lassen
```

---

## 4. *Wann sollte ich das SUID-Bit setzen?* — die Antwort, die du wolltest

Genau **einmal, nach dem Bauen, vor dem Start des Daemons für die
Root-Shell-Demos** — und nur auf einer Maschine, die dir gehört, wegwerfbar und
vom Netzwerk getrennt ist:

```console
$ make            # kompiliere foosd, foosc, tests
$ make setuid     # <-- DER Moment. sudo chown root:root foosd && sudo chmod u+s foosd
$ make run        # starte NACH dem Setzen des Bits
```

Zwei Regeln, die wichtiger sind als der exakte Zeitpunkt:

1. **Setze es erst, wenn das Binärprogramm final ist.** Wenn du das Bit setzt
   und danach neu baust (`make` / `make clean`), bekommst du beim Schreiben der
   root-gehörigen Ausgabedatei ein „Permission denied" — und wenn du den
   Rebuild erzwingst, erstellt die Toolchain die Datei **ohne** das `s` neu,
   womit die Einrichtung still rückgängig gemacht wird. Die kanonische
   Reihenfolge bei jedem Rebuild ist daher

   ```console
   $ make unsetuid && make && make setuid
   ```

2. **Entferne es, wenn du fertig bist.** `make unsetuid`. Ein lebendes,
   root-gehöriges Setuid-Binärprogramm mit einem ausnutzbaren Bug in deinem
   Baum ist kein Lernmittel, sondern ein Root-Loch mit einem Compilefehler
   zwischen ihm und nirgendwo. Auf einer geteilten oder Produktionsmaschine:
   **mach davon nichts.** Der Daemon weigert sich außerdem standardmäßig,
   etwas anderes als Loopback zu binden (siehe §7).

Wenn du den Exploit *ohne* je gesetztes Bit ausführst, bricht nichts — der
Payload landet trotzdem und du bekommst trotzdem eine Shell. Der Unterschied
steckt in einer Zahl, und der Exploit sagt sie laut:

```console
foosc: WARNING: the daemon is NOT running with euid 0.
       The payload will still land, but the shell will be
       a plain user shell, not root.
       Fix:  sudo make setuid
```

Dieses „funktioniert, aber nicht root" ist selbst Teil des Labors. Behalte es
für den nächsten Abschnitt im Kopf.

---

## 5. Der Mechanismus — und die Wendung, die SUID interessant macht

### 5.1 Der Overflow (identisch zu `food`)

`foosd`s Handler gibt einem `read()` 512 Bytes Vertrauen, während er ihm einen
64-Byte-Stack-Puffer reicht:

```c
char buf[64];
n = read(fd, buf, 512);        /* <- CWE-120: 448 Bytes über die Kante */
```

Auf x86-64 wächst der Stack nach unten. Der Exploit schreibt 64 Bytes Müll, um
`buf` zu füllen, 8, um den gespeicherten Frame-Pointer zu füllen, und 8 mehr,
um die **gespeicherte Rücksprungadresse** zu ersetzen. Wenn
`vulnerable_handler` das `ret` ausführt, poppt die CPU den Wert des Angreifers
in `RIP` — vom Angreifer kontrollierte Codeausführung. Der Exploit ermittelt
den exakten Abstand (88 Bytes für diesen Build), indem er die `objdump`-Ausgabe
parst, statt ihn hart zu verdrahten, sodass die Zahl Rebuilds überlebt.

### 5.2 Die Wendung: Die Shell weigert sich, root zu sein

Hier geht „SUID-Bug → /bin/sh spawne → root" fehl, und das ist der Grund,
warum dieses Labor genau diese Form hat.

Wenn ein setuid-root-Programm läuft, ist sein `ruid` immer noch der
startende Benutzer und sein `euid` ist root. Wenn das Programm — oder der
Angreifer — jetzt eine Shell startet:

* `execve("/bin/sh")` ändert die uids **nicht**; der neue Prozess erbt
  `(ruid=1000, euid=0)`.
* bash (und dash) **prüfen genau diese Bedingung beim Start**. Aus dem
  bash-Handbuch: *„If the shell is started with the effective user (group) id
  not equal to the real user (group) id, and the -p option is not supplied, …
  the effective user id is set to the real user id."*

Die Shell wirft also einen Blick auf sich selbst und *lässt root fallen* — eine
Verteidigung, die die Shell-Autoren genau gegen diesen Angriff gebaut haben
(die historische Rechtfertigung war das Setuid-Shell-/Setuid-Skript-Problem).
Das Ergebnis sind die „funktioniert, aber nicht root"-Fälle:

| Technik | Was sie ausführt | Resultierende uid |
|-----------|------------------|---------------|
| `ret2win` | `foosd`s `win()` → `execl("/bin/sh")` | **1000** — Shell gelandet, root von bash zurückgesetzt |
| `ret2libc` | `system("/bin/sh")` → frisches `sh -c '/bin/sh'` | **1000** — gleiches Zurücksetzen, eine Ebene tiefer |
| `ret2win-root` | `foosd`s `win_root()` → `setreuid(0,0); execl("/bin/sh")` | **0** — ruid aus C heraus geleert |
| `shellcode` | 32 Bytes: `setreuid(0,0); execve("/bin/sh")` | **0** — ruid aus Maschinencode geleert |

Die beiden, die root erreichen, unterscheiden sich von den beiden, die es
nicht tun, um genau eine Idee: **sie leeren die *reale* uid, nicht nur die
effektive.**

```c
setuid(0)          /* setzt euid auf 0, aber ruid bleibt 1000:
                      bash sieht weiterhin euid != ruid und setzt IMMER NOCH
                      zurück.                                              */
setreuid(0, 0)     /* setzt BEIDE: ruid = euid = 0.
                      bash sieht gleiche uids und behält root.             */
```

Deshalb beginnt der klassische `/bin/sh`-Shellcode, den du überall im Internet
findest, mit einem uid-leerenden Syscall — und deshalb ist der Shellcode hier
32 Bytes statt 23: Die ersten fünf Anweisungen sind

```asm
xor    edi, edi      ; ruid = 0
xor    esi, esi      ; euid = 0
push   0x71          ; 113 = __NR_setreuid
pop    rax
syscall
```

### 5.3 Also, was ist der Exploit Ende-zu-Ende?

1. `foosc` liest `foosd`s Banner über den Socket. Es bekommt:
   - `ids=0/1000` — euid/ruid (die SUID-Selbstdiagnose)
   - `stack=…` und `libc=…` — Pointer (die ASLR-Leaks)
   - `BUF=…` — die exakte Adresse des Puffers, den es gleich überlaufen lässt
2. Aus dem Ziel-Binärprogramm (via `objdump`) lernt es `rip_off` und die
   Adressen von `win()` / `win_root()`.
3. Aus *seiner eigenen* libc (via `/proc/self/maps` + `dlsym` + einen
   Speicherscan) misst es die Offsets von `system`, `read`, `/bin/sh` und
   eines `pop rdi; ret`-Gadgets — nichts ist hart verdrahtet.
4. Es setzt den Payload zusammen. Für `-t shellcode` ist das:
   `[32-Byte-setreuid+execve-Code][Padding bis RIP][ret-Fix][Adresse von buf]`.
5. `foosd`s `read()` läuft über; `ret` landet auf dem Shellcode; der Kernel
   führt `setreuid(0,0)` aus (ok: euid 0 ist privilegiert) und danach `execve`
   von `/bin/sh`. bash startet mit `ruid == euid == 0` und bleibt root.
6. `foosc` leitet dein Terminal an diese Root-Shell weiter, bis du `exit`
   tippst.

Ein Details zur Absicherung, das Leute viel Zeit kostet, wenn es übersehen
wird: Der Exploit testet jedes uid-leerende Verhalten **ohne** das benötigte
Setuid-Bit zuerst. Führe `make test` vor `make setuid` aus, und du siehst jede
Technik eine Shell landen, während `ROOT=MISSING` dasteht; führe `make
test-suid` nach `make setuid` aus, und `ROOT=SEEN` erscheint bei den zwei
Techniken, die die reale uid leeren. Dieses A/B ist die ganze Lektion,
ausführbar in zehn Sekunden.

---

## 6. Die alten Einzeiler — und warum die meisten von ihnen tot sind

Wenn du über SUID gelesen hast, hast du über `PATH`-Hijacking, `LD_PRELOAD`
und Setuid-Shells gelesen. Alle drei sind klassisch, und alle drei scheitern
auf einem modernen System gegen *dieses Programm*. Es lohnt sich, genau zu
wissen, warum, denn die Gründe sind die Verteidigungen, die du gratis
bekommst:

| Angriffsklasse | Alte Behauptung | Warum sie auf einem modernen Rechner scheitert |
|--------------|-----------|------------------------------|
| `LD_PRELOAD` einer bösartigen Bibliothek | „Das Setuid-Programm lädt meine `.so` und führt meinen Code als root aus." | Der Kernel markiert ein Setuid-Binärprogramm als **AT_SECURE**; glibc ignoriert daraufhin `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_DEBUG` und Verwandtes. Die Umgebung wird als *unvertrauenswürdige Eingabe* behandelt. `LD_PRELOAD` gegen ein Setuid-Binärprogramm ist eine No-Operation. |
| `PATH`-Hijack (`system("ls")` mit vergiftetem PATH) | „Zeige PATH auf ein Verzeichnis mit meinem falschen `ls`; das Root-Programm führt es aus." | Ein zweites Gesicht derselben Verteidigung: Ein AT_SECURE-Prozess bekommt einen **bereinigten `PATH`** (einen sicheren Standard, in etwa `/usr/local/bin:/usr/bin:/bin`) für `system()`/`execvp`, sodass das vergiftete Verzeichnis nie konsultiert wird. |
| Setuid-`system()`-Befehlsinjektion | „Der injizierte Befehl läuft mit euid 0." | `system()` führt den Befehl in einer frischen `/bin/sh` aus, und diese Shell — §5.2 — setzt `euid = ruid` beim Start zurück. Der injizierte Befehl läuft mit der *realen* uid. (Es ist immer noch ein Bug; er eskaliert nur nicht mehr über `/bin/sh`.) |
| Setuid-Root-Shell auf der Platte (`cp /bin/sh /tmp; chmod u+s`) | „Führe sie aus, bekomme root." | Genau die Verteidigung oben, und das ist der Grund, warum moderne Distributionen keine Setuid-Root-Shell ausliefern. Selbst wenn dir eine gelingt, weigert sich bash, euid 0 zu behalten, sofern es nicht mit `-p` gestartet wird. |

Was lebendig bleibt, und das ist dieses Labor: **Das Programm ist beim Laufen
*bereits* root.** Du brauchst weder die Umgebung noch `system()`; du brauchst,
dass das Programm *deinen* Code (über einen Memory-Corruption-Bug) ausführt,
solange es privilegiert ist, und dein Code muss vorsichtig genug sein, den
uid-Mismatch selbst zu beheben — `setreuid(0,0)` — bevor er dir eine Shell
übergibt. Memory Corruption + SUID ist die Kombination, die immer noch in
`uid=0` endet, und genau deshalb sind speichersichere Sprachen, Canaries und
No-Execute-Stacks keine Modeentscheidung.

---

## 7. Die in den Daemon eingebauten Sicherheitsleitplanken

`foosd` ist absichtlich das *schlechteste* Stück Software in diesem
Repository, also trägt es auch die meisten Leitplanken:

1. **Nur Loopback, erzwungen.** `foosd` weigert sich, eine andere Adresse als
   Loopback zu binden, sofern du nicht `-L` übergibst. Ein Setuid-Root-Listener
   auf einer echten Schnittstelle ist ein entfernter Root-Dienst; die Weigerung
   ist der Standard, damit der gefährliche Zustand bewusst eingetippt werden
   muss.
2. **Selbstdiagnose.** Beim Start loggt es `ruid`/`euid` und ob es als root
   läuft, sodass die Konsole den Zustand zeigt, von dem der Exploit abhängt.
3. **Das Log erreicht den Client nie.** Der Daemon reserviert einen privaten
   Log-Deskriptor, bevor Sockets fd 1 ersetzen, sodass Crash-Reporter-Ausgabe
   und interne Pfade vom Angreifer nicht über die Leitung zurückgelesen werden
   können.
4. **Crash-Reporter.** Ein SIGSEGV-Handler loggt `RIP`/`RSP` — den Wert, den
   der Angreifer in die Rücksprungadresse geschrieben hat — sodass eine
   erfolgreiche Übernahme in `foosd.log` sichtbar ist, statt ein stiller Tod zu
   sein.
5. **`make unsetuid`.** Das Entfernen des Bits ist skriptiert, denn es gesetzt
   zu lassen ist der Ausfallmodus, den Leute tatsächlich haben.

---

## 8. Gegenmaßnahmen — was jede stoppt und was nicht

Angewendet auf `foosd` via `make hardened`, einzeln oder zusammen:

| Gegenmaßnahme | Was sie stoppt | Was sie *nicht* stoppt |
|------------|---------------|-------------------------|
| `-fstack-protector-strong` (Canary) | Den Overflow: `ret` erkennt einen zerstörten Canary und bricht ab, bevor die Adresse des Angreifers verwendet wird. Stoppt hier **alle vier** Techniken — sie teilen sich das eine angreifbare `read()`. | Nichts am *Design*: Das Binärprogramm ist immer noch setuid-root; ein anderer Bug (Format-String-`%n`, Heap-Overflow, Use-after-Free) hat keinen Canary zum Auslösen. |
| `-fPIE -pie` (ASLR für das Binärprogramm) | Nutzung vorhersagbarer `win()`/`win_root()`-Adressen (die ret2win-Techniken). | Die Shellcode-Technik, wenn weiterhin eine Stack-Adresse leakt (die `BUF=`-Zeile). |
| `-z noexecstack` (NX / W^X) | Den Shellcode: Die CPU weigert sich, Befehle von einer daten-only-Seite zu holen, sodass ein Sprung auf `buf` ein SIGSEGV ist. | ROP — das Ausführen vorhandenen Codes (`ret2libc`). |
| Alle drei zusammen | Ein schwer zu überlaufendes, randomisiertes Binärprogramm mit nicht-ausführbarem Stack. So sieht ein normaler gehärteter Build aus. | Das Setuid-Bit. **Ein gehärtetes SUID-Binärprogramm ist immer noch ein SUID-Binärprogramm.** Wenn irgendein erreichbarer Speichersicherheitsbug überlebt, ist es immer noch „Bug in einem Root-Prozess". |

Der Konsolenbeweis ist `make test-hardened`, das den gehärteten Build
eintauscht und zeigt, wie alle Techniken am Canary sterben, während
`foosd_hardened.log` `*** stack smashing detected ***` aufzeichnet.

Zwei Designebenen-Gegenmaßnahmen, die keine Compiler-Flag liefert und die auch
das übergeordnete Labor (`food`) nutzt:

- **Least Privilege.** Ein Daemon für einen unprivilegierten Port (2343 > 1024)
  hat keinen legitimen Bedarf an root. Ein korrektes `foosd` würde binden und
  dann `setgroups`/`setgid`/`setuid` auf ein unprivilegiertes Konto ausführen
  und *verifizieren, dass es hielt* (die korrekte Version steht im Quellcode
  als `drop_privs()`, nie aufgerufen — die Nicht-Aufrufung ist Bug #3 des
  Labors).
- **Das read begrenzen.** `n = read(fd, buf, sizeof(buf) - 1)`. Eine korrekte
  Zeile schlägt jede Compiler-Flag in der Tabelle.

---

## 9. Das Wire-Protokoll (damit du den Daemon mit netcat lesen kannst)

```text
FOOSD 1.0 - deliberately vulnerable SUID service
Type 'quit' to disconnect. Buffer = 64 bytes, read accepts 512.
FOOSD 1.0 ids=0/1000 leak stack=0x7ffd... libc=0x7f...
BUF=0x7ffd...
```

* `ids=euid/ruid` — durfte nicht als `euid=`/`ruid=` gedruckt werden, weil die
  Test-Harness eine Shell anhand des wörtlichen `uid=` beweist und das Banner
  es nicht enthalten darf (eine Sonde, die die Signatur mit der Antwort teilt,
  ist eine klassische Fehlpositiv-Falle; siehe den Kommentar in `foosd.c`).
  Die Harness verlangt außerdem die strenge `id`-Ausgabeform — `uid=NNN(...)` —
  sodass nichts, was der Daemon oder der Exploit druckt, die Prüfung zufällig
  erfüllen kann: `foosc`s eigenes „target euid=… ruid=…" enthält `uid=` als
  Teilstring, was einmal einen gehärteten Test eine nie gelaufene Shell melden
  ließ.
* `stack=`, `libc=`, `BUF=` — die ASLR-Leaks: erlauben Shellcode und ret2libc,
  exakte Adressen zu berechnen.

---

## 10. Übungen

1. **Beobachte die Nicht-Root-Abstufung.** Führe `make test` *vor* `make
   setuid` aus, dann danach erneut. Erkläre die `ROOT=SEEN`-Änderung mit der
   ruid/euid-Geschichte aus §5.2.
2. **Lies den Absturz.** Führe `./foosc -t demo -n` aus und lies dann
   `foosd.log`. Die Zeile `RIP=0x4141414141414141` ist das Padding des
   Angreifers — der Beweis, dass der Overflow, nicht Pech, die Ausführung
   kontrolliert.
3. **Füge den Canary hinzu.** `make hardened` und ändere die
   `test-hardened`-Schleife selbst; die Log-Zeile
   `*** stack smashing detected ***` ist die arbeitende Verteidigung.
4. **Deaktiviere das Leak.** Kommentiere die `BUF=`-Zeile in `foosd.c` aus,
   baue neu und beobachte, wie `-t shellcode` von deterministisch zu einem
   Ratespiel wird. Diese eine Zeile ist der Grund, warum echte
   ASLR-Bypasses ein ganzes Feld sind.
5. **Das `-p`-Experiment.** Ändere in einer Kopie von `win()` `execl("/bin/sh",
   "sh", NULL)` zu `execl("/bin/sh", "sh", "-p", NULL)` und beobachte root.
   `-p` ist die dokumentierte Notluke aus dem Wächter der Shell — und der
   Grund, warum der Rat „spawne einfach eine Shell" aus alten Write-ups
   unvollständig ist.
6. **Warum nicht `setuid(0)`?** Schreibe den Shellcode so um, dass er
   `setuid(0)` statt `setreuid(0,0)` aufruft (Syscall 105). Die Shell landet
   trotzdem — und fällt trotzdem auf `uid=1000`. Das ist das lehrreichste
   Ein-Zeilen-Experiment im gesamten Repository.

---

## 11. Sicherheit und Aufräumen

- Nur Loopback, standardmäßig und per Design; `-L` bindet weiter, und nur eine
   Wegwerf-VM sollte es überhaupt in Betracht ziehen.
- Dies ist ein Root-Shell-Labor. Führe es nicht auf einer Maschine aus, die
   wichtig ist, und richte `foosc -h` nicht auf etwas, das dir nicht gehört.
- Aufräumritual: `make stop` und dann `make unsetuid`, und wenn du den Baum
   wieder makellos willst: `sudo make clean`.

```console
$ make stop
$ make unsetuid
```