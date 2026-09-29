# SUID-root-RCE-lab — `foosd` (daemon) + `foosc` (exploit)

Een begeleider van het hoofdlaboratorium (`food` / `fooc`, een gewone daemon
waar een bufferoverloop je een *gebruiker*-shell geeft). Dit voegt de
gevaarlijkste wijziging van één teken in Unix toe: **de setuid-bit**.

> `chmod u+s` verandert "de aanvaller kan code draaien op deze host" in "de
> aanvaller kan code draaien als **root** op deze host".

Die zin is het hele lab. Alles hieronder is het mechanisme eronder,
opgeschreven, zodat je wanneer je je eigen software schrijft precies weet welke
twee of drie bestandssysteem-attributen en compilerflags bepalen of een
geheugenveiligheidsbug in jouw code een ergernis of een root-shell is.

De uiteindelijke demo, wanneer `foosd` setuid-root is, is een **root-shell**
die over het netwerk wordt geopend door 32 bytes handgeschreven shellcode uit
te voeren.

---

## 1. Wat de setuid-bit daadwerkelijk doet

Elk proces op Linux draagt drie user-ID's, en de setuid-bit rommelt aan de
verhouding ertussen:

| ID | Naam | Betekenis |
|----|------|---------|
| `ruid` | reële user-ID | de account die het proces *startte* |
| `euid` | effectieve user-ID | wat de kernel controleert wanneer hij toegang handhaaft |
| (saved) | opgeslagen set-user-ID | een "spoor" waarnaar een bevoorrecht proces later kan terugkeren |

Een normaal programma heeft `ruid == euid`. Wanneer je een binair bestand
uitvoert met de setuid-bit gezet, eigendom van root:

```text
ruid = jij        (bijv. 1000, "hanez")
euid = de eigenaar (bijv. 0, "root")
```

Het proces heeft dus **roots autoriteit**, ook al is de gebruiker die het
startte volkomen gewoon. Elke controle die de kernel uitvoert — kan dit proces
`/etc/shadow` lezen? een bestand schrijven? een ander proces doden? — wordt
beantwoord met `euid`, dus "ja, het is root".

`foosd` is een netwerkdaemon. Hij bindt een poort en `fork()`t daarna een kind
per verbinding. Een fork *erft* de euid, dus elk kind dat een verbinding
afhandelt, is ook root. De overloop in `foosd`s `vulnerable_handler()` is
daarom een overloop *binnenin een root-proces*.

**Diagnosticeer het zelf wanneer de daemon draait:**

```console
$ ./foosd ...            # zie de logregel die hij bij de start print
[foosd 1234] startup: ruid=1000 euid=0 -> ROOT process
```

en vanuit het exploit:

```console
$ ./foosc -t leak
foosc: target euid=0 ruid=1000
```

---

## 2. Het lab in één oogopslag

| Bestand | Rol |
|------|------|
| `foosd.c` | De bewust kwetsbare daemon (eigenaar van de bugs). Draai als *setuid-root*-binary voor de root-shell-demo. |
| `foosc.c` | Het exploit. Gebruikt standaard de 32-byte `setreuid + execve`-shellcodetechniek. |
| `shellcode.S` | De referentie-shellcode; `make verify` diff't het tegen de byte-array in `foosc.c`. |
| `tests/pty_suid_test.c` | Test-harness. Drijft `foosc` door een pseudo-terminal en bewijst zowel "er draaide een shell" *als* "die was root" (`uid=0(`). |
| `Makefile` | Build, `setuid`/`unsetuid`-helpers, testmatrix. |
| `README.md` | Dit bestand. |

> **Waarom een pty?** De laatste actie van het exploit is je terminal
> doorschakelen naar de shell die op het slachtoffer draait. Een pipe of
> here-doc komt aan de verkeerde kant van die doorschakeling terecht; een echte
> terminal is vereist.

---

## 3. Snelle start

```console
$ make                       # bouw alles, als je normale gebruiker
$ make setuid                # één keer, vraagt om sudo: chown root + chmod u+s
$ make run                   # start foosd op 127.0.0.1:2343
$ make test-suid             # volledige matrix; shellcode + ret2win-root moeten root geven
```

Interactieve rooktest:

```console
$ ./foosc -t shellcode
...
foosc: target euid=0 ruid=1000
foosc: shell is on the victim (root if foosd is SUID); relaying
# id
uid=0(root) gid=0(root) groups=0(root)      <-- je bent root, op het slachtoffer
# exit
```

Wanneer je klaar bent:

```console
$ make stop
$ make unsetuid             # hygiëne: laat nooit een root-SUID-binary achter
```

---

## 4. *Wanneer moet ik de SUID-bit zetten?* — het antwoord dat je vroeg

Precies **één keer, na het bouwen, vóór je de daemon start voor de
root-shell-demo's** — en alleen op een machine die van jou is, geschikt om weg
te gooien en losgekoppeld van het netwerk:

```console
$ make            # compileer foosd, foosc, tests
$ make setuid     # <-- HET MOMENT. sudo chown root:root foosd && sudo chmod u+s foosd
$ make run        # start NÁ het zetten van de bit
```

Twee regels die belangrijker zijn dan het precieze tijdstip:

1. **Zet hem alleen als de binary klaar is.** Als je herbouwt (`make` /
   `make clean`) nadat je de bit hebt gezet, krijg je een "Permission denied"
   bij het schrijven van root-bezeten outputbestanden — en als je de herbouw
   forceert, herschept de toolchain het bestand **zonder** de `s` en maak je de
   opzet stilletjes ongedaan. De canonieke volgorde bij elke herbouw is daarom

   ```console
   $ make unsetuid && make && make setuid
   ```

2. **Haal hem weg als je klaar bent.** `make unsetuid`. Een levende,
   root-bezeten setuid-binary met een exploiteerbare bug in je boom is geen
   leermiddel, het is een root-gat met een compilerfout tussen zichzelf en
   niets. Op een gedeelde of productiemachine: **doe niets van dit alles.** De
   daemon weigert bovendien standaard iets anders dan loopback te binden (zie
   §7).

Als je het exploit *zonder* ooit de bit te zetten draait, gaat er niets
kapot — de payload landt nog steeds, en je krijgt nog steeds een shell. Het
verschil zit in één getal, en het exploit zegt het hardop:

```console
foosc: WARNING: the daemon is NOT running with euid 0.
       The payload will still land, but the shell will be
       a plain user shell, not root.
       Fix:  sudo make setuid
```

Het "werkte, maar niet root"-resultaat is zelf onderdeel van het lab. Onthoud
dat voor de volgende sectie.

---

## 5. Het mechanisme — en de twist die SUID interessant maakt

### 5.1 De overloop (identiek aan `food`)

De handler van `foosd` geeft een `read()` 512 bytes vertrouwen terwijl hij er
een 64-byte stack-buffer aan reikt:

```c
char buf[64];
n = read(fd, buf, 512);        /* <- CWE-120: 448 bytes over de rand */
```

Op x86-64 groeit de stack naar beneden. Het exploit schrijft 64 bytes rommel
om `buf` te vullen, 8 om de opgeslagen framepointer te vullen en nog 8 om de
**opgeslagen retouradres** te vervangen. Wanneer `vulnerable_handler` de `ret`
uitvoert, poppt de CPU de waarde van de aanvaller in `RIP` —
aanvaller-gecontroleerde code-uitvoering. Het exploit vindt de exacte afstand
(88 bytes voor deze build) door `objdump`-output te parsen in plaats van die te
hardcoden, zodat het getal herbouwen overleeft.

### 5.2 De twist: de shell weigert root te zijn

Hier is waar "SUID-bug → spawn /bin/sh → root" fout zou gaan, en waarom dit lab
precies de vorm heeft die het heeft.

Wanneer een setuid-root-programma draait, is zijn `ruid` nog steeds de
startende gebruiker en is zijn `euid` root. Als het programma — of de aanvaller
— nu een shell start:

* `execve("/bin/sh")` verandert de uids **niet**; het nieuwe proces erft
  `(ruid=1000, euid=0)`.
* bash (en dash) **controleert die exacte toestand bij de start**. Uit de
  bash-handleiding: *"If the shell is started with the effective user (group)
  id not equal to the real user (group) id, and the -p option is not supplied,
  … the effective user id is set to the real user id."*

Dus de shell kijkt naar zichzelf en *laat root vallen* — een verdediging die de
shell-auteurs precies tegen dit aanval bouwden (de historische reden was het
setuid-shell-/setuid-scriptprobleem). Het resultaat is de "werkte, maar niet
root"-gevallen:

| Techniek | Wat hij uitvoert | Resulterende uid |
|-----------|------------------|---------------|
| `ret2win` | `foosd`s `win()` → `execl("/bin/sh")` | **1000** — shell landde, root gereset door bash |
| `ret2libc` | `system("/bin/sh")` → verse `sh -c '/bin/sh'` | **1000** — dezelfde reset, één niveau lager |
| `ret2win-root` | `foosd`s `win_root()` → `setreuid(0,0); execl("/bin/sh")` | **0** — ruid opgeruimd vanuit C |
| `shellcode` | 32 bytes: `setreuid(0,0); execve("/bin/sh")` | **0** — ruid opgeruimd vanuit machinecode |

Degene die root bereiken, verschillen van degene die dat niet doen in precies
één idee: **ze ruimen de *reële* uid op, niet alleen de effectieve.**

```c
setuid(0)          /* zet euid op 0, maar ruid blijft 1000:
                      bash ziet nog steeds euid != ruid en reset NOG STEEDS.  */
setreuid(0, 0)     /* zet BEIDE: ruid = euid = 0.
                      bash ziet gelijke uids en houdt root.                  */
```

Daarom begint de klassieke `/bin/sh`-shellcode die je overal op internet vindt
met een uid-opruimend syscall — en daarom is de shellcode hier 32 bytes in
plaats van 23: de eerste vijf instructies zijn

```asm
xor    edi, edi      ; ruid = 0
xor    esi, esi      ; euid = 0
push   0x71          ; 113 = __NR_setreuid
pop    rax
syscall
```

### 5.3 Dus wat is het exploit, van begin tot eind?

1. `foosc` leest het banner van `foosd` over de socket. Het krijgt:
   - `ids=0/1000` — euid/ruid (de SUID-zelfdiagnose)
   - `stack=…` en `libc=…` — pointers (de ASLR-leaks)
   - `BUF=…` — het exacte adres van de buffer die het op het punt staat te
     laten overlopen
2. Uit de doel-binary (via `objdump`) leert het `rip_off` en de adressen van
   `win()` / `win_root()`.
3. Uit *zijn eigen* libc (via `/proc/self/maps` + `dlsym` + een geheugenscan)
   meet het de offsets van `system`, `read`, `/bin/sh` en een
   `pop rdi; ret`-gadget — niets is hardcoded.
4. Het stelt de payload samen. Voor `-t shellcode` is dat:
   `[32-byte-setreuid+execve-code][padding tot RIP][ret-fix][adres van buf]`.
5. `foosd`s `read()` loopt over; de `ret` landt op de shellcode; de kernel
   voert `setreuid(0,0)` uit (geen probleem: euid 0 is bevoorrecht) en daarna
   `execve` van `/bin/sh`. bash start met `ruid == euid == 0` en blijft root.
6. `foosc` schakelt je terminal door naar die root-shell, tot je `exit` typt.

Eén gemakdetail dat mensen veel tijd kost als het wordt gemist: het exploit
test elk uid-opruimgedrag **zonder** eerst de setuid-bit nodig te hebben. Draai
`make test` vóór `make setuid`, en je ziet elke techniek een shell landen terwijl
`ROOT=MISSING` staat; draai `make test-suid` ná `make setuid`, en `ROOT=SEEN`
verschijnt bij de twee technieken die de reële uid opruimen. Die A/B is de hele
les, in tien seconden uitgevoerd.

---

## 6. De oude one-liners — en waarom de meeste dood zijn

Heb je over SUID gelezen, dan heb je over `PATH`-kapingen, `LD_PRELOAD` en
setuid-shells gelezen. Alle drie zijn klassiek, en alle drie falen op een
modern systeem tegen *dit programma*. Het is de moeite waard om precies te
weten waarom, want de redenen zijn de verdedigingen die je gratis krijgt:

| Aanvalsklasse | Oude bewering | Waarom hij faalt op een moderne machine |
|--------------|-----------|------------------------------|
| `LD_PRELOAD` van een kwaadaardige bibliotheek | "Het setuid-programma laadt mijn `.so` en draait mijn code als root." | De kernel markeert een setuid-binary als **AT_SECURE**; glibc negeert daarna `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_DEBUG` en vrienden. De omgeving wordt behandeld als *onbetrouwbare input*. `LD_PRELOAD` tegen een setuid-binary is een no-op. |
| `PATH`-kaping (`system("ls")` met een vergiftigde PATH) | "Wijs PATH naar een map met mijn neppe `ls`; het root-programma draait hem." | Een ander gezicht van hetzelfde verdedigingen: een AT_SECURE-proces krijgt een **gesaneerde `PATH`** (een veilige standaard, grofweg `/usr/local/bin:/usr/bin:/bin`) voor `system()`/`execvp`, dus de vergiftigde map wordt nooit geraadpleegd. |
| Setuid-`system()`-commando-injectie | "Het geïnjecteerde commando draait met euid 0." | `system()` draait het commando in een verse `/bin/sh`, en die shell — §5.2 — reset `euid = ruid` bij de start. Het geïnjecteerde commando wordt uitgevoerd met de *reële* uid. (Het blijft een bug; het escaleert alleen niet meer via `/bin/sh`.) |
| Setuid-root-shell op de schijf (`cp /bin/sh /tmp; chmod u+s`) | "Draai hem, krijg root." | Precies wat hierboven verdedigd wordt, en dat is waarom moderne distro's geen enkele setuid-root-shell leveren. Zelfs als je er één kunt maken, weigert bash euid 0 te houden tenzij hij met `-p` wordt gestart. |

Wat blijft leven, en dat is dit lab: **het programma is *al* root wanneer het
draait.** Je hebt de omgeving of `system()` niet nodig; je hebt nodig dat het
programma *jouw* code uitvoert (via een geheugenbeschadigingsbug) terwijl het
bevoorrecht is, en dat jouw code zorgvuldig genoeg is om zelf de uid-mismatch
recht te zetten — `setreuid(0,0)` — voordat het je een shell overhandigt.
Geheugenbeschadiging + SUID is de combinatie die nog steeds in `uid=0` eindigt,
en dat is precies waarom geheugenveilige talen, canaries en no-execute-stacks
geen modebeslissing zijn.

---

## 7. De veiligheidsheurlingen die in de daemon zijn ingebouwd

`foosd` is bewust het *slechtste* stuk software in dit repository, dus het
draagt ook de meeste leuningen:

1. **Alleen loopback, afgedwongen.** `foosd` weigert elke bind-adres buiten
   loopback, tenzij je `-L` geeft. Een setuid-root-listener op een echte
   interface is een externe root-dienst; de weigering is de standaard, zodat de
   gevaarlijke toestand bewust moet worden ingetypt.
2. **Zelfdiagnose.** Bij de start logt hij `ruid`/`euid` en of hij als root
   draait, zodat de console de toestand toont waarvan het exploit afhangt.
3. **De log bereikt de client nooit.** De daemon reserveert een privé
   log-descriptor vóór sockets fd 1 vervangen, zodat crash-reporter-output en
   interne paden niet door de aanvaller over de draad teruggelezen kunnen
   worden.
4. **Crash-reporter.** Een SIGSEGV-handler logt `RIP`/`RSP` — de waarde die de
   aanvaller in het retouradres schreef — zodat een succesvolle overname
   zichtbaar is in `foosd.log` in plaats van een stille dood.
5. **`make unsetuid`.** Het verwijderen van de bit is gescript, omdat hem laten
   staan de faaltoestand is die mensen daadwerkelijk hebben.

---

## 8. Tegenmaatregelen — wat elke stopt en wat hij *niet* stopt

Toegepast op `foosd` via `make hardened`, één voor één of samen:

| Tegenmaatregel | Wat hij stopt | Wat hij *niet* stopt |
|------------|---------------|-------------------------|
| `-fstack-protector-strong` (canary) | De overloop: `ret` detecteert een beschadigde canary en aborted vóór het adres van de aanvaller wordt gebruikt. Stopt hier **alle vier** de technieken — ze delen het ene kwetsbare `read()`. | Niets aan *het ontwerp*: de binary is nog steeds setuid-root; een andere bug (format-string-`%n`, heap-overflow, use-after-free) heeft geen canary om af te laten gaan. |
| `-fPIE -pie` (ASLR voor de binary) | Gebruik van voorspelbare `win()`/`win_root()`-adressen (de ret2win-technieken). | De shellcode-techniek, als er nog een stack-adres lekt (`BUF=`-regel). |
| `-z noexecstack` (NX / W^X) | De shellcode: de CPU weigert instructies op te halen van een data-only-pagina, dus een sprong naar `buf` is een SIGSEGV. | ROP — code draaien die al bestaat (`ret2libc`). |
| Alle drie samen | Een moeilijk-te-laten-overlopen, gerandomiseerde binary met een niet-uitvoerbare stack. Zo ziet een normale geharde build eruit. | De setuid-bit. **Een geharde SUID-binary is nog steeds een SUID-binary.** Overleeft er een bereikbare geheugenveiligheidsbug, dan is het nog steeds "bug in een root-proces". |

Het consolebewijs is `make test-hardened`, dat de geharde build inwisselt en
laat zien hoe alle technieken bij de canary sterven, terwijl
`foosd_hardened.log` `*** stack smashing detected ***` opvangt.

Twee tegenmaatregelen op ontwerpniveau die geen enkele compilerflag levert, en
die het hoofdlaboratorium (`food`) ook gebruikt:

- **Minste privilege.** Een daemon voor een onbevoordeelde poort (2343 > 1024)
  heeft geen legitieme behoefte aan root. Een correcte `foosd` zou binden en
  daarna `setgroups`/`setgid`/`setuid` naar een onbevoorrechte account en
  *bevestigen dat het hield* (de correcte versie staat in de bron als
  `drop_privs()`, nooit aangeroepen — het niet-aanroepen is bug nr. 3 van het
  lab).
- **Beperk de read.** `n = read(fd, buf, sizeof(buf) - 1)`. Eén correcte regel
  overtreft elke compilerflag in de tabel.

---

## 9. Het wire-protocol (zodat je de daemon met netcat kunt lezen)

```text
FOOSD 1.0 - deliberately vulnerable SUID service
Type 'quit' to disconnect. Buffer = 64 bytes, read accepts 512.
FOOSD 1.0 ids=0/1000 leak stack=0x7ffd... libc=0x7f...
BUF=0x7ffd...
```

* `ids=euid/ruid` — kon niet als `euid=`/`ruid=` geprint worden, omdat de
  test-harness een shell bewijst door op het letterlijke `uid=` te greppen, en
  het banner mag dat niet bevatten (een sonde die de handtekening met het
  antwoord deelt, is een klassieke fout-positief- val; zie de commentaar in
  `foosd.c`). De harness vereist bovendien de strikte `id`-outputvorm —
  `uid=NNN(...)` — zodat niets wat de daemon of het exploit print het aan
  toeval kan laten voldoen: `foosc`s eigen "target euid=… ruid=…" bevat `uid=`
  als deelstring, wat ooit een geharde test een shell liet melden die nooit had
  gedraaid.
* `stack=`, `libc=`, `BUF=` — de ASLR-leaks: laten shellcode en ret2libc exacte
  adressen berekenen.

---

## 10. Oefeningen

1. **Beschouw de niet-root-degradatie.** Draai `make test` *vóór* `make
   setuid`, en daarna nog eens achteraf. Verklaar de `ROOT=SEEN`-verandering
   met het ruid/euid-verhaal in §5.2.
2. **Lees de crash.** Draai `./foosc -t demo -n` en lees daarna `foosd.log`.
   De regel `RIP=0x4141414141414141` is de padding van de aanvaller — het bewijs
   dat de overloop, niet toeval, de uitvoering bestuurt.
3. **Voeg de canary toe.** `make hardened` en verander zelf de
   `test-hardened`-lus; de logregel `*** stack smashing detected ***` is de
   verdediging die werkt.
4. **Schakel het lek uit.** Commentaar de `BUF=`-regel in `foosd.c` uit, bouw
   opnieuw, en zie `-t shellcode` van deterministisch naar een raadspel
   veranderen. Die ene regel is de reden dat echte ASLR-bypasses een heel veld
   zijn.
5. **Het `-p`-experiment.** Verander in een kopie van `win()`
   `execl("/bin/sh", "sh", NULL)` naar `execl("/bin/sh", "sh", "-p", NULL)` en
   observeer root. `-p` is de gedocumenteerde nooduitgang uit de wacht van de
   shell — en de reden dat het advies "spawn gewoon een shell" uit oude
   write-ups onvolledig is.
6. **Waarom niet `setuid(0)`?** Herschrijf de shellcode om `setuid(0)` te
   roepen in plaats van `setreuid(0,0)` (syscall 105). De shell landt nog
   steeds — en zakt nog steeds naar `uid=1000`. Dat is het meest leerzame
   één-regel-experiment van het hele repository.

---

## 11. Veiligheid en opruimen

- Alleen loopback, als standaard en volgens ontwerp; `-L` bindt verder, en
  alleen een weg-te-gooien-VM zou het überhaupt moeten overwegen.
- Dit is een root-shell-lab. Draai het niet op een machine die ertoe doet, en
  richt `foosc -h` niet op iets dat je niet bezit.
- Opruimritueel: `make stop` en daarna `make unsetuid`, en als je de boom weer
  vlekkeloos wilt: `sudo make clean`.

```console
$ make stop
$ make unsetuid
```