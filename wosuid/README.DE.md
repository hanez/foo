# Das `wosuid`-Labor — Root-RCE **ohne** Setuid-Bit

```
  foowosd   ein absichtlich angreifbarer Daemon, der root ist, weil er als
            root *GESTARTET* wurde  (Port 2344, standardmäßig nur Loopback)
  foowosc   der Exploit: verwandelt einen Stack-Overflow in eine **root**-Shell,
            indem er Shellcode ausführt — dieselben 23 Bytes, mit denen der
            User-Level-`food`-Daemon im übergeordneten Labor geknackt wurde
```

Das ist das dritte Labor der Reihe. Gleiche Exploit-Toolchain, gleicher Stil,
ein fundamentaler Unterschied:

| Labor      | wie der Zielprozess root wird                          | `uid=0(root)`-Shell? |
|----------|------------------------------------------------|----------------------|
| food/fooc| nie — es ist ein gewöhnlicher User-Daemon        | nein                  |
| foosd/foosc | das SUID-Bit (`chmod u+s`) — euid 0, ruid 1000 | ja (braucht `setreuid` im Shellcode, weil bash euid→ruid zurücksetzt) |
| **foowosd/foowosc** | **keins — root *startet* den Daemon** (sudo / systemd `User=root`) | **ja (schlichter `execve`-Shellcode)** |

Das Setuid-Bit ist ein *Transportmittel* für Privilegien — nicht die
Privilegien selbst. Ein von root gestarteter Daemon hat reale, effektive und
gespeicherte uid alle gleich 0. Für den Kernel ist das root, Punkt; es kann und
will nicht wissen, ob der Prozess über `+s` an einer Datei dorthin kam oder
über `sudo ./foowosd`. Der Overflow in einem von root gestarteten Daemon ist
also ein Root-Exploit — *„Ich habe keine SUID-Binärprogramme" ist nicht
dasselbe wie „Ich bin nicht ausnutzbar".*

Das ist die ganze Lektion dieses Labors. Alles darunter ist die Maschinerie.

---

## Schnellstart (was der Benutzer angefordert hat)

```
cd wosuid
make                 # baut den Daemon, den Exploit und die Test-Harness
```

### Das Echte — den Daemon als **root** ausführen

```
sudo make run-root      # startet foowosd als uid 0 (Prozess, nicht Dateimodus)
make test-root          # jede Technik muss jetzt uid=0(root) ergeben
```

### Kein sudo? Derselbe Kernelpfad über einen User-Namespace

```
make run-root-ns        # uid 0 in einem User-Namespace — kein Passwort nötig
make test-root          # gleiche Urteile; für CI und alle ohne sudo
```

### Baseline — Daemon als dein normaler Benutzer (kein root irgendwo)

```
make run                # foowosd läuft mit deinen uids
make test               # Exploits landen Shells, aber `root` wird als MISSING erwartet
```

### Aufräumritual (immer: dies ist ein Root-Shell-Labor)

```
make stop
```

`foowosd` ist *nicht* setuid, und nichts in diesem Verzeichnis macht je
`chmod +s` — das ist der Punkt. Der gefährliche Zustand ist der **Prozess**,
nicht die Datei.

---

## Wenn dir gesagt wird, das SUID-Bit zu setzen

Du wirst es **nicht** tun. Dieses Labor hat bewusst kein SUID-Bit:

- `foowosd` wird gebaut, gehört dir und hat reguläre Modi wie jedes andere
  Programm.
- Es wird so root, wie es echte Daemons tun — indem es von *root* gestartet
  wird.
- `make run-root` nutzt dafür `sudo`, und `make run-root-ns` bekommt einen
  echten uid-0-Prozess ganz ohne das.

Das Suid-Bit gehört dem *Schwester*-Labor (`foosd`). Der Kontrast zwischen den
beiden ist der Lehrplan:

1. SUID-Labor: Das Bit gibt **euid 0, aber ruid 1000** → `execve("/bin/sh")`
   wird vom Wächter der bash herabgestuft (`euid != ruid` → Reset) →
   der Shellcode muss zuerst `setreuid(0,0)` aufrufen (32-Byte-Payload).
2. Dieses Labor: root **startet** den Prozess → **ruid == euid == 0** → der
   Wächter hat nichts zurückzusetzen → der schlichte 23-Byte-`execve`-Shellcode
   behält root.

Gleicher Overflow. Gleiche Technik. Anderer *Ursprung* der Privilegien, andere
Payload-Form. Das ist die Lektion in Miniatur.

---

## Das Protokoll

Egal welche Art Client sich verbindet, foowosd begrüßt ihn mit:

```
FOOWOSD 1.0 ids=0/0 leak stack=0x7ffd… libc=0x7f…      (das Banner + die Leaks)
BUF=0x7ffd…                                             (die Pufferadresse)
```

`ids=euid/ruid` ist der *„bin ich root?"*-Seitenkanal. foowosc druckt eine
laute Warnung, wenn euid nicht 0 ist (d. h., du hast den Daemon als normalen
Benutzer gestartet): Der Payload landet trotzdem, aber die Shell wird eine
Benutzer-Shell sein, und den Exploit „kaputt" zu nennen wäre falsch — er
eskaliert nur eben nicht.

> Schreibweise-Hinweis: `ids=`, nicht `euid=`/`ruid=`. Die Test-Harness beweist
> ein lebendes `id`, indem sie die wörtliche Form `uid=NNN(` matcht, daher darf
> das Banner nie einen Teilstring enthalten, der selbst die Prüfung erfüllt.
> (Im SUID-Labor erzeugte genau diese Falle ein spektakuläres Fehlpositiv.)

---

## Die Exploit-Techniken (`foowosc -t …`)

Alle vier Exploit-Pfade unten funktionieren gegen foowosd. Wenn der Daemon
root ist, ergeben **alle, die irgendetwas spawne, root** — anders als im
SUID-Labor, wo ret2win/ret2libc vom bash-Wächter still auf uid 1000
herabgestuft wurden. Hier gibt es keinen Mismatch, gegen den es zu wachen
gälte.

| `-t`          | was passiert                                                       | wenn der Daemon root ist |
|---------------|---------------------------------------------------------------------|---------------------|
| `shellcode`   | 23-Byte-`execve("/bin/sh", NULL, NULL)` läuft auf dem Stack.        | **root-Shell** (Standard) |
| `ret2win`     | Sprung zu `win()` → `execl("/bin/sh")`                              | **root-Shell** |
| `ret2libc`    | ROP: `pop rdi; ret` → `"/bin/sh"` → `system()`                      | **root-Shell** |
| `demo`        | nur Müll-Overflow — erwarte ein SIGSEGV im Daemon-Log               | Absturz, per Design |
| `leak`        | druckt nur die Leaks, sendet keinen Payload                         | n/a |

```
./foowosc -t shellcode       # interaktiv; Standardziel 127.0.0.1:2344
./foowosc -t shellcode -n    # senden und berichten, keine interaktive Session
```

Eine erfolgreiche interaktive Session leitet dein Terminal an die Shell *auf
dem Opfer* weiter — es gibt genau eine Shell im Bild, und es ist `/bin/sh`,
das als root in foowosd läuft. Tippe `id`, um `uid=0(root)` zu sehen.

### Warum es hier keine `ret2win-root`-Technik gibt

foosc hatte eine — sie sprang zu einem `win_root()`, das vor dem exec
`setreuid(0,0)` aufrief, weil ein Setuid-Prozess mit einer realen uid lief, die
immer noch 1000 sagte. Ein von root *gestarteter* Prozess hat die reale uid
schon 0; es gibt nichts zu leeren, also würden die zusätzliche Funktion und
Technik nichts lehren. Entfernt.

---

## Was foowosc Schritt für Schritt tut

1. **Statische Analyse** — `objdump -d` von `./foowosd`. Findet
   `vulnerable_handler`, `win()`, das `lea -0x50(%rbp)`, das `buf` adressiert,
   und das erste nackte `ret`. Aus der Verschiebung berechnet es
   `rip_off = 80 + 8 = 88`. Nichts ist hart verdrahtet; das überlebt einen
   Rebuild.
2. **Selbst-Introspektion** — liest sein eigenes `/proc/self/maps` und ruft per
   `dlsym()` `system`/`read` auf, um die libc-*Offsets* zu lernen. Die
   libc-Basis des Ziels ist `leaked_read − off_read`, dann ist
   `system = base + off_system`, usw. Diese Delta-Arithmetik ist der Grund,
   warum Exploits über libc-Versionen hinweg am Leben bleiben.
3. **Verbinden** — liest das Banner/die Leaks (`ids=`, `stack=`, `libc=`,
   `BUF=`).
4. **Payload bauen** — für `shellcode`: 23 Bytes Maschinencode, Padding bis
   `rip_off`, dann die gespeicherte RIP = `buf` (sodass `ret` auf den Code
   springt). Für `ret2win`/`ret2libc`: aus der Analyse berechnete Adressen —
   keine Ausführung des Stacks nötig.
5. **Der Ausrichtungs-Fix** — ein gekapertes nacktes `ret` übergibt dem Callee
   `rsp ≡ 8 (mod 16)`, und glibcs SSE2-Code `movaps`-fault auf einem nicht
   ausgerichteten Stack (der Crash-Reporter loggt `si_addr=(nil)` — der
   Hinweis). foowosc fügt vor dem echten Ziel ein zusätzliches `ret`-Gadget ein
   und stellt die Invariante wieder her. Samthandschuh-Ingenieurkunst in einem
   Shellcode-Labor, aber es ist der Unterschied zwischen einem Payload, der
   „manchmal funktioniert", und einem, der immer funktioniert.
6. **Senden, dann weiterleiten** — der Opferprozess *ist* die Shell; dieser
   Prozess nur splißt Bytes. Keine lokale Shell, kein zweiter Leser — der
   Single-Read-Cursor-Fehler (ein gefressenes Byte pro Block) ist in
   `become_shell()` dokumentiert.

---

## Die absichtlichen Bugs des Daemons (alle in `foowosd.c`, alle echte CWE-Klassen)

| # | Bug | CWE | Hinweis |
|---|-----|-----|------|
| 1 | `read(fd, buf, 512)` in einen 64-Byte-Stack-Puffer | [CWE-120](https://cwe.mitre.org/data/definitions/120.html) | der Overflow: 448 Bytes über `buf` hinaus, gespeicherte RIP bei +88 |
| 2 | nur `snprintf(line, …, "%.*s", …)`; aber Angreifer-`%` im Echo-Pfad | [CWE-134](https://cwe.mitre.org/data/definitions/134.html) | das Leak ist hier der eigentliche Payload; ein `%n` in einem *root*-Prozess wäre write-what-where als root |
| 3 | Kinder behalten root, während sie unvertrauenswürdige Eingaben behandeln | [CWE-271](https://cwe.mitre.org/data/definitions/271.html) | das korrekte `drop_privs()` (setgroups→setgid→setuid, in dieser Reihenfolge, mit Verifikation) steht in der Datei, kommentiert, *bewusst nie aufgerufen* |
| 4 | `ids=`, `stack=`, `libc=`, `BUF=` an jeden Client offengelegt | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | ohne diese Leaks könnten Shellcode- und ret2libc-Techniken keine Adressen berechnen (ASLR würde sie schlagen) |

Der Handler hat exakt dieselbe `buf[64]`/`read(512)`-Form wie die beiden
anderen Labore, sodass die geteilte objdump-basierte Erkennungspipeline
unverändert funktioniert.

---

## So inspizierst du den Daemon (Lernpfad)

```
make status            # läuft er? als welche uid? Dateimodus wird gezeigt
make run-root          # oder run / run-root-ns
./foowosc -t leak      # sieh das Banner und die Leaks, sende nichts
./foowosc -t demo      # Müll-Overflow -> SIGSEGV, geloggt mit RIP/rsp
./foowosc -t shellcode # die interaktive Root-Shell
make test-root         # volle Matrix, alle Techniken, --must-root
```

Crash-Reporter: Bei SIGSEGV loggt der Daemon die Fehleradresse, RIP und RSP.
Ein `ret` in eine nicht-kanonische `0x4141…` fault am `ret` selbst (RIP wie
`0x4028xx`, `si_addr=(nil)`) — wissenswert, bevor du eine Log-Zeile als
NULL-Deref fehlliest.

---

## Warum der Shellcode 23 Bytes sind, nicht 32

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

Das SUID-Labor braucht `setreuid(0,0)` davor. Dieses Labor nicht, aus dem
Grund, der überall wiederholt wird: **ruid ist bereits 0**, weil root den
Prozess gestartet hat. `make verify` beweist, dass die Bytes in `foowosc.c`
Byte für Byte das sind, was `shellcode.S` assembliert.

---

## Gegenmaßnahmen — was `make hardened` ändert

Gehärteter Build (`-fstack-protector-strong -fPIE -pie -z noexecstack`):

| Technik | angreifbares `foowosd` | gehärtetes `foowosd_hardened` |
|-----------|----------------------|------------------------------|
| `shellcode` | root-Shell (ausführbarer Stack) | SIGSEGV bei der Canary-Prüfung / NX |
| `ret2win` / `ret2libc` | root-Shell | Canary bricht `ret` ab — aber Achtung: ein *PIE*-Build macht diese Adressen auch zufällig |
| `demo` | SIGSEGV, geloggt | SIGSEGV, geloggt |

`make test-hardened` demonstriert das live. Die wichtige Beobachtung ist nicht
nur, dass die Gegenmaßnahmen die Techniken getötet haben — es ist, dass sie
den Daemon **nicht** „nicht-root" gemacht haben. Ein gehärteter Build, der
immer noch als root *gestartet* wird, ist immer noch ein Root-Daemon; die
Gegenmaßnahme erhöht nur die Latte für den Angreifer. Least Privilege
(`drop_privs()`) und Speichersicherheit sind zwei verschiedene Bugs, und ein
Daemon, der root nicht braucht, sollte es nicht haben.

---

## Sicherheitsleitplanken (gleiche Politik wie das SUID-Labor)

- **Nur Loopback.** foowosd weigert sich, etwas anderes als `127.0.0.1` /
  `localhost` / `::1` zu binden, sofern du nicht `-L` übergibst. Ein
  Root-Daemon auf einer echten Schnittstelle ist ein *entfernter* Root-Dienst.
  `-L` dient nur dazu, den Wächter zu zeigen; verwende es nicht auf irgendetwas,
  das wichtig ist.
- **Der Zustand wird laut geloggt.** Beim Start druckt es `ruid/euid` und ob
  dies ein Root-Prozess ist, sodass du immer weißt, welches Exploit-Ergebnis
  zu erwarten ist.
- **Urteile kommen aus Exit-Status** in `make test*` (dem Rückgabecode der
  pty-Harness), nie aus dem Greppen ihrer stdout-Ausgabe — greppbare Ausgabe
  lügt.
- **pty muss cooked + ECHO off laufen**, sonst spiegelt die Harness ihre eigene
  Befehlszeile zurück und fälscht den Marker. Die Harness schaltet ECHO aus und
  lässt ECHONL an.
- **Aufräumritual:** `make stop` nach jeder Session. Wenn der Daemon
  root-gehörig ist, sagt dir `stop`, dass du `sudo pkill -x foowosd` ausführen
  sollst.
- Führe dies nie auf einem Host aus, der dir wichtig ist. Es existiert, um
  `uid=0`-Shells über die Loopback-Schnittstelle auszugeben.

---

## Übungen

1. Führe `make run` (User-Daemon) aus, dann `./foowosc -t shellcode`. Warum
   ist die Shell nicht root? (Prüfe `ids=` im Banner — foowosc sagt es dir,
   bevor du dich überhaupt verbindest.)
2. `make stop && sudo make run-root && make test-root`. Erkläre anhand der
   Banner-Zeile, warum alle vier Techniken jetzt `uid=0(root)` ergeben.
3. Finde in `foowosd.c` `drop_privs()` und lies, *warum die Reihenfolge* von
   `setgroups → setgid → setuid` zählt. Entscheide, wo in `main()` es
   hingehören würde, und was aus der Angriffsfläche des Labors wird, sobald es
   tatsächlich aufgerufen wird.
4. Berechne `rip_off` von Hand aus `objdump -d foowosd`: finde `buf`s
   `lea -0xNN(%rbp)` in `vulnerable_handler`, dann `NN + 8`. foowosc macht
   genau das; prüfe seine Rechnung gegen deine eigene.
5. `make hardened && make test-hardened`. Welche Technik erliegt dem Canary und
   welche NX? Warum ändert Härten nicht, was `make status` über den *Prozess*
   meldet?
6. Vergleiche die Shellcodes der beiden Labore: 23 Bytes hier, 32 für foosd.
   Was tun die zusätzlichen 9 Bytes, und warum werden sie nur im SUID-Fall
   gebraucht?
7. Lies `become_shell()`s Kommentar über den einzelnen Read-Cursor. Stelle den
   Ausfallmodus gedanklich nach: zwei Leser an einem Socket bedeuten, dass die
   Login-Shell ein Byte pro Block frisst — „uid=1000…" kommt als „id=1000…" an.
   Warum kann ein Relay-Prozess diesen Bug nie haben?

---

## Dateien

```
foowosd.c                 der angreifbare Root-Daemon (jede Zeile kommentiert)
foowosc.c                 der Exploit (jede Zeile kommentiert)
shellcode.S               Referenz-Assembly für den 23-Byte-Payload
tests/pty_wosuid_test.c   die pty-Harness (Marker + strenge id-Form-Prüfungen)
Makefile                  build / run / run-root / run-root-ns / test /
                          test-root / verify / hardened / clean …
```

Schwester-Labore: `../food.c`/`../fooc.c` (User-Level-Baseline, Port 2342) und
`../suid/` (SUID-Root-Daemon `foosd`/`foosc`, Port 2343). Die Ports sind
bewusst verschieden — du kannst alle drei gleichzeitig laufen lassen und ihre
`ids=`-Zeilen im Banner gegeneinander prüfen.
