# food / fooc — een stack-bufferoverloop, van beide kanten

Een C99-beveiligingslab in twee helften:

- **`food.c`** — een bewust kwetsbare TCP-daemon. Hij heeft een echte,
  schoolboekachtige stack-bufferoverloop (CWE-120), plus een paar bugs
  extra.
- **`fooc.c`** — een exploit daarvoor. Hij berekent de overflow-offset door
  het doelprogramma tijdens het draaien te disassembleren, leest
  adres-leaks van de daemon en krijgt een shell op het "slachtoffer" door
  een opgeslagen retouradres te overschrijven.

Het punt is niet de shell. Het punt is dat je van begin tot eind kunt volgen hoe
een geheugenveiligheidsbug uitgroeit tot willekeurige code-uitvoering — en
daarna precies ziet welke tegenmaatregelen elke stap in die keten stoppen.
Elke regel in beide programma's is gecommentarieerd, want het mechanisme is de
les.

```
                   jouw terminal
                         |
                     ./fooc   (exploit)
                         |
                    TCP 127.0.0.1:2342
                         |
                     ./food   (kwetsbare daemon)
                         |
                 fork() -> vulnerable_handler() -> overflow -> ret -> jouw code
```

---

## ⚠️ Lees dit eerst

**`food` is een bewust kapotte netwerkdienst. Hij bindt alleen aan
`127.0.0.1`, en die standaard is bewust — laat hem daar.**

- Draai hem **niet** op een machine waar je om geeft, of op iets met data.
- Bind hem **niet** aan `0.0.0.0` of een echte netwerkinterface. Hij is
  bewust extern exploiteerbaar.
- `fooc` richten op een host die je niet bezit of waarvoor je geen schriftelijke
  toestemming hebt om te testen, is in de meeste rechtsgebieden een
  computercriminaliteitsovertreding — ook onder de UK Computer Misuse Act en
  de US Computer Fraud and Abuse Act.
- Hij bindt aan een onbevoordeelde poort (>1024), dus je hebt geen root nodig.
  "Verbeter" hem niet door capabilities toe te voegen of hem als
  systeemdienst te draaien.
- Elke verbinding wordt afgehandeld in een `fork()`-kind, en `food` reapt
  het, dus crashes stapelen zich niet op. Vind je daarna tientallen losse
  `sh`-processen, dan is `pkill -x sh` de opruiming.

Bij twijfel: dit lab is voor een virtuele machine of container, op een netwerk
dat jij beheert, op een machine zonder iets dat je zou missen.

---

## Snelle start

```sh
make            # bouwt food, fooc en de test-harnesses
make run        # start food op 127.0.0.1:2342, losgekoppeld op de achtergrond
make test       # draait alle drie de exploit-technieken
make stop       # stopt de daemon
```

Daarna met de hand:

```sh
./fooc -t leak        # bekijk de adres-leaks die food prijsgeeft
./fooc -t demo -v     # stuur rommel; zie food sterven met SIGSEGV
./fooc -t ret2win -i  # spring naar een functie die al bestaat -> shell
```

### Vereisten

| Hulpmiddel | Waarvoor | Opmerkingen |
|---|---|---|
| `gcc` (of clang) | bouwen | C99. Getest met gcc 16.2 |
| `objdump` | `fooc` | binutils. `fooc` roept het tijdens het draaien aan |
| `nasm` | `make verify` | alleen om de shellcode te verifiëren; wordt overgeslagen als het ontbreekt |
| `gdb` | `make debug` | optioneel |
| Linux, x86-64 | beide | payload en gadget-jacht zijn architectuurafhankelijk |

`fooc` heeft ook `-ldl` nodig voor `dlsym()`; de Makefile regelt dat.

---

## De bug

Eén regel in `food.c` is het hele aanvalsoppervlak:

```c
char buf[FOOD_BUFSZ];                  /* 64 bytes  */
n = read(fd, buf, FOOD_READMAX);       /* tot 512 bytes van het netwerk */
```

64 bytes bestemming, 512 bytes geaccepteerd. De aanvaller overschrijft 448
bytes voorbij het einde van de buffer, en omdat de stack naar beneden groeit,
betekent "voorbij het einde" "in het frame erboven" — en daar liggen precies de
opgeslagen framepointer en de **opgeslagen retouradres**.

In een gecompileerde x86-64-functie bij `-O0`:

```
  hoge adressen
  +------------------------+  rbp + 16 : locals van de aanroeper
  |  ...                   |
  +------------------------+  rbp +  8 : OPGESLAGEN RETOURADRES   <-- wordt RIP
  |  saved rbp (8 bytes)   |
  +------------------------+  rbp      : onze framepointer
  |  line[128]             |
  |  buf[64]               |  <- rsp: wat read() vult
  +------------------------+
  lage adressen
```

Wanneer de functie terugkeert, poppen `leave; ret` de 8 bytes in `RIP`, en de
CPU springt waar de aanvaller het heeft bepaald. Al het andere in dit lab is
rekenkunde over waarheen je moet wijzen.

Voor deze build zijn de getallen: `buf` is 64 bytes, de opgeslagen `rbp` is 8,
dus het retouradres ligt op offset **88** vanaf het begin van `buf`. `fooc`
hardcoded dat niet — het disassembleert `food` en vindt `lea -0x50(%rbp)`
vóór `call read@plt`, zodat het blijft werken als je `FOOD_BUFSZ` verandert.

> gcc vertelt je dit al. `food` bouwen print:
> `warning: 'read' writing 512 bytes into a region of size 64 overflows the
> destination [-Wstringop-overflow=]`. Onderdruk die waarschuwing nooit in
> echte code. Het is gratis beveiliging.

---

## De drie technieken

`fooc -t <technique>`. Ze staan in de volgorde waarin een echte aanvaller er
doorheen zou werken, omdat elke techniek nodig heeft wat de vorige je leerde.

### 1. `ret2win` — bestuur de instructiepointer

```
[ 88 bytes rommel ][ het adres van food's win() ]
                   ^ saved rbp
                                    ^ wordt RIP
```

`win()` is een functie in het doelprogramma die `/bin/sh` exec't. Het
overschrijven van het retouradres met haar adres is het hele exploit.

**Wat het leert:** je hebt volledige controle over de instructiepointer. Het
heeft ook geen leak nodig, want het binaire bestand is gebouwd met `-no-pie`,
dus `win()` staat voor altijd op een vast adres.

**De tegenhanger in de echte wereld** is niet "aanvallen zijn makkelijk",
maar "lever geen ongedocumenteerde backdoors in netwerk-binaries". Zit er een
functie als `win()` in jouw binaire bestand, dan zal een bufferoverloop haar
vinden. Dat is letterlijk de Juniper ScreenOS-backdoor-CVE-klasse.

**Verdediging:** `-fPIE` (of ASLR) randomiseert het laadadres, dus de aanvaller
moet het adres kennen — wat meestal betekent dat ze eerst een lek nodig hebben.
Daarom faalt `ret2win` tegen `food_hardened`.

### 2. `ret2libc` — roep om het even wat aan, bij naam

```
[ rommel ][ pop rdi; ret ][ adres van "/bin/sh" ][ adres van system() ]
          ^^^^^^^^^^^^     ^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^
          zet rdi          de string om te sturen de functie om aan te roepen
```

Bij uitvoering: `ret` poppt `pop rdi; ret` in RIP; dat poppt de
`"/bin/sh"`-pointer in `RDI`; zijn `ret` poppt `system()` in RIP, terwijl `RDI`
de string nog vasthoudt. `system("/bin/sh")` draait.

Gadgets (`pop rdi; ret`) zitten niet in `food` — deze glibc heeft geen
`__libc_csu_init` — dus `fooc` vindt ze door live libc-geheugen te scannen op
het bytepaar `5f c3`. Het lokaliseert libc via `/proc/self/maps`, vindt de
offsets van `system` en `"/bin/sh"` met `dlsym()` en berekent de base uit het
lek dat `food` prijsgeeft. Niets is hardcoded, dus het overleeft een
libc-update.

**Wat het leert:** zodra je RIP kunt controleren, kun je *bestaande*
instructies aan elkaar rijgen. Dat is return-oriented programming, en zo ziet
bijna elk echt exploit eruit, omdat het geen door de aanvaller geleverd
uitvoerbaar geheugen nodig heeft.

**Verdediging:** geen van de compilerflags stopt dit alleen. Het werkt tegen
een PIE-binary, met NX, met canary — zolang de aanvaller een lek heeft. De
verdedigingen zijn "heb de overloop niet" en "lek geen adressen". Zie de tabel
hieronder.

### 3. `shellcode` — voer je eigen machinecode uit

23 bytes, geplaatst aan het begin van de buffer, met `RIP` ernaar wijzend:

```asm
xor    esi, esi                    ; envp = NULL
xor    edx, edx                    ; argv = NULL
movabs rdi, 0x68732f6e69622f       ; rdi = "/bin/sh\0" als 8 ruwe bytes
push   rdi                         ; leg de string op de stack
mov    rdi, rsp                    ; rdi = &"/bin/sh"
push   0x3b                        ; 59 = __NR_execve
pop    rax
syscall                           ; we zijn nu een shell
```

Dit is de puurste vorm van de bug: de aanvaller levert de *instructies*, niet
alleen het adres van instructies die al bestaan. Geen libc-offsets nodig, dus
het werkt in principe tegen een statisch gelinkt, volledig gerandomiseerd
doelwit.

`make verify` assembleert `shellcode.S` en diff't het tegen de byte-array die
in `fooc.c` is ingebed, zodat de twee niet uiteen kunnen drijven.

**Verdediging:** **NX** (ook wel W^X, "no execute" genoemd). De stack als
niet-uitvoerbaar markeren zorgt ervoor dat de hardware weigert er instructies
uit te halen, en de `ret` landt op een pagina die niet kan draaien. Daarom
geeft `make food` `-z execstack`: een normale Linux-stack is `rw-p`, niet
`rwx`, en de techniek sterft met SIGSEGV bij `RIP = het adres van de payload`.
De allerbelangrijkste les van het lab is dat elk van deze bytes alleen werkt
omdat de compiler opdracht kreeg de stack uitvoerbaar te laten. Dat vlaggetje
staat aan voor niemands gewin.

### Ook inbegrepen

| Modus | Wat hij doet |
|---|---|
| `-t leak` | verbindt, print leaks, stuurt niets |
| `-t demo` | stuurt `rip_off + 8` bytes `0x41`, zodat `RIP` `0x4141...` wordt en de daemon sterft. Bewijst de bug zonder enige adreskennis |
| `-t sled` | een ret-sled, bewust bewaard als **fout** voorbeeld. Zonder lek zou je ASLR brute-forcen door de buffer te vullen met het adres van een `ret`. Dat kan hier niet werken: `food` accepteert 512 bytes, dus de sled heeft ~53 slots tegenover ~28 bits entropie. Zo geïmplementeerd dat je het kunt zien falen en kunt bevestigen dat het mechanisme echt "de CPU volgt een keten van rets" is |

---

## De tabel met tegenmaatregelen

Dit is het deel om te onthouden. Elke rij is een echte verdediging, en de
rechterkolom laat zien wat die daadwerkelijk met de gebeurtenisketen doet.

| Tegenmaatregel | Zo activeer je | Wat hij stopt | Wat hij *niet* stopt |
|---|---|---|---|
| **Beperk read** | `n = read(fd, buf, sizeof buf - 1);` | **Alles.** De bug bestaat niet, dus niets stroomafwaarts doet ertoe | Niets — dit is de enige volledige fix |
| **Stack-canary** | `-fstack-protector-strong` (gcc-standaard) | De `ret`: de canary wordt aan het einde van de functie gecontroleerd, dus de beschadiging wordt gedetecteerd en het proces aborted vóórdat `RIP` wordt gepopt | Een bug in een functie *zonder* array (niets om te beschermen); een overloop die onder de canary blijft; alles wat niet normaal return't |
| **NX / W^X** | `-z noexecstack` (de standaard) | Shellcode. De eigen instructies van de payload kunnen niet worden opgehaald | ret2win en ret2libc volledig. Die zijn *de reden* dat ROP bestaat |
| **PIE + ASLR** | `-fPIE` + ASLR=2 (beide standaard) | De hardcoded adressen van ret2win. Alles verschuift bij elke run | Alles waar de aanvaller een lek heeft. ASLR verhoogt de prijs van een exploit; het is geen fix. Merk op dat stack, heap en mmap worden gerandomiseerd, maar de *inhoud* van de hoofd-binary niet — dat is wat ROP-ketens gebruiken |
| **Lek niets** | geen `printf("%p")` naar clients; initialiseer vóór je print | Het informatielek dat ASLR van "duur" naar "gratis" verandert | — |
| **Gebruik geen `printf(user_data)`** | `printf("%s", buf)` in plaats van `printf(buf)` | Format-string-bugs: `%x`-stack-reads, `%n`-willekeurige schrijfbewerkingen — een *andere* weg naar RCE | — |
| **Gebruik geen onbetrouwbare paden** | valideer en `openat()` onder een vaste map | Pad-traversal (CWE-22) | — |
| **CET / shadow stack** | `-fcf-protection=full`, kernel- en CPU-ondersteuning | De `ret` zelf: de shadow stack onthoudt het *echte* retouradres en faalt bij een mismatch. Vangt ROP-ketens die hardware-`ret` gebruiken | Aanvallen die nooit `ret`-en (call-oriented, of het doel van een functiepointer overschrijven met een gadget-keten die geen retour nodig heeft) |
| **Veilige talen** | Rust, Go, C# voor nieuwe code | De hele klasse. Bounds-checks worden tijdens de uitvoering afgedwongen, niet vertrouwd bij review | — |

### Zie het zelf

```sh
make run            # kwetsbare daemon
make test           # alle drie de technieken werken

make test-hardened  # dezelfde broncode, tegenmaatregelen aan
```

`test-hardened` bouwt `food_hardened` met `-fstack-protector-strong -fPIE -pie
-z noexecstack`, wisselt hem in, draait alle drie opnieuw en legt daarna de
kwetsbare terug. Je ziet:

```
### stack segment: 'rw-p' (NOT executable) is what you want to see
--- ret2win   was stopped by the mitigations (as expected)
--- ret2libc  was stopped by the mitigations (as expected)
--- shellcode was stopped by the mitigations (as expected)
```

En in de log van de geharde daemon, de canary die afgaat:

```
*** stack smashing detected ***: terminated
```

Lees dat goed, want het is de belangrijkste regel van het hele lab: **de canary
ving ret2win, niet PIE.** Alle drie de technieken sterven bij de canary, omdat
alle drie door dezelfde `read()` gaan en hetzelfde frame beschadigen. NX stopt
alleen nog de *code* van de shellcode; PIE breekt alleen nog het hardcoded
adres. Zet ze één voor één aan, en je ontdekt dat de meeste enkele
tegenmaatregelen je ergens kwetsbaar achterlaten.

---

## Bestanden

| Bestand | Doel |
|---|---|
| `food.c` | de kwetsbare daemon. 6 genummerde bugs, elk met zijn fix in de commentaar |
| `fooc.c` | het exploit. objdump-gebaseerde offenderkenning, `/proc`-gebaseerde libc-herkenning, 4 payload-bouwers |
| `shellcode.S` | de 23 shellcode-bytes als assembly, zodat ze leesbaar en verifieerbaar zijn. `fooc` draagt ze inline en heeft dit tijdens het draaien niet nodig |
| `Makefile` | bouwt, test en de harde vergelijking |
| `tests/pty_test.c` | drijft `fooc` door een pseudo-terminal en controleert op echte shell-output |
| `tests/sock_test.c` | onafhankelijke verificateur over een rauwe socket, zodat het resultaat niet van `fooc` afhangt |
| `food.log` | de log van de daemon. Jouw bewijs van wat er gebeurde |

---

## Twee bugs in dit lab die de moeite van het begrijpen waard zijn

Dit zijn niet de bugs van het doelprogramma. Het zijn bugs in het exploit en in
zijn test-harness, en beide produceerden overtuigende leugens. Ze zijn
gedocumenteerd in de bron waar ze wonen; hier staan ze omdat de faalpatronen
leerzaam zijn.

### Stack-uitlijning: de crash die geen NULL-dereferentie is

**Symptoom.** De overname landt correct — `gdb` laat je in `win()` zien — en
dan sterft het allereerste wat `win()` doet, een `dprintf()`. De
SIGSEGV-handler rapporteert `RIP` diep in glibc's formatter en een foutadres
van `(nil)`, wat er precies uitziet als een corrupte pointer.

**Oorzaak.** De System V AMD64-ABI vereist 16-byte stack-uitlijning. Een
normale `ret` herstelt `%rsp` precies zoals de bijbehorende `call` het
opsloeg, dus de invariant blijft gratis behouden. Onze kale `ret` doet dat
niet: daarna geldt `%rsp = buf + rip_off`. Hier is `buf` 16-byte uitgelijnd en
is `rip_off` 88, dus de callee krijgt een stack die 8 mod 16 is. glibc is met
SSE2 gecompileerd, en `movaps` **faalt** op een verkeerd uitgelijnde operand.
Op x86 werpt dat `#GP` op, niet `#PF`, dus de kernel heeft geen foutadres en
rapporteert `si_addr = 0`. Die NULL is de hint: een uitlijnfout vermomd als
NULL-dereferentie.

**Fix.** Eén `ret`-gadget *op offset `rip_off`*, dat het echte doelwit 8 bytes
omhoog schuift, omdat elke `ret` precies 8 bij `%rsp` optelt. De volgorde is
kritiek: een eerdere versie plakte de `ret` *achter* het doelwit en produceerde
`[ padding | target | ret ]`, waarbij de afsluitende `ret` nooit wordt bereikt
en de fix stilletjes niets doet. Een verdwaalde `ret` die op een bug lijkt, is
bijna altijd bewust.

### Eén socket, twee lezers: de byte die verdween

**Symptoom.** Shellcode werd gerapporteerd als werkend. Toen werd de
pty-harness strenger gemaakt (`ECHO` uitzetten, zodat de terminal ophield de
eigen commandoregel van de harness naar zichzelf terug te echoën), en de
techniek begon te falen. Dieper ging elke techniek precies één byte van het
begin van elke uitvoer-chunk kwijt: `uid=1000(hanez)` werd geprint als
`id=1000(hanez)`, `PWNED-OK` als `WNED-OK`, `Linux 7.2.7` als `inux 7.2.7`.

**Oorzaak.** `fooc` deed vroeger de socket `dup2()`en naar zijn eigen
stdin/stdout en een *lokale* `/bin/sh` `execv()`en, terwijl een geforkt
relay-kind dezelfde socket ook las om output naar de terminal te verplaatsen.
De kernel kan het niets schelen dat die twee samenwerken. Een streamsocket heeft
**één** lees-cursor, en elke lezer verplaatst hem, dus bytes worden
onvoorspelbaar tussen hen verdeeld. De lokale shell — een interactieve
login-shell — las precies één byte en gooide het weg, elke keer weer.
`strace -f` liet het onmiddellijk zien:

```
read(0, "u", 1)                              <- de lokale shell, eet een byte op
read(4, "id=1000(hanez) gid=1000(hanez) g".., 310)   <- het relay, 1 byte te kort
```

**Fix.** Er is hier helemaal geen shell aan deze kant. Er is precies één shell
in het hele plaatje, en die zit op het slachtoffer, in het gekaapte proces,
met de TCP-verbinding als zijn stdin/stdout. Deze kant verplaatst alleen bytes.
Als je ooit twee consumenten van een stream nodig hebt, heeft die stream één
enkele lezer nodig die hem bewust demultiplext.

**De meta-les.** Het eerste "werkende" resultaat was een fout-positief,
geproduceerd doordat de pty de eigen commandoregel van de harness terug naar
zichzelf echoëde, en de fix voor dat fout-positief is wat de echte bug
onthulde. Tests die niet kunnen falen, zijn erger dan geen tests, omdat ze "ik
weet het niet" veranderen in "het werkt". Een test-harness verdient hetzelfde
wantrouwen als de code die hij test.

---

## Ermee spelen

Dingen die de moeite waard zijn om te proberen, ongeveer in de volgorde waarin
je er het meest van leert:

1. **Verander `FOOD_BUFSZ` naar 128.** Draai `fooc` opnieuw. Het zou nog
   steeds moeten werken zonder wijzigingen, omdat het de offset uit de
   disassembly leest. Breek het dan met de hand — hardcode 88 — en zie het
   crashen. Voeg daarna een tweede array toe tussen `buf` en de opgeslagen
   registers, en zie hoe de automatische herkenning het afhandelt.

2. **Voeg `-Wformat-security` toe en kijk wat het format-string-pad doet.**
   Stuur `%p %p %p %n` en zie `food` de stack lekken.

3. **Gebruik gdb.** `make debug`, daarna:
   ```gdb
   (gdb) break food.c:393        # de read() die overloopt
   (gdb) run -p 2342
   (gdb) info registers rsp rbp
   (gdb) x/24gx $rsp             # merk op waar het retouradres ligt
   (gdb) c                        # in een andere terminal: ./fooc -t ret2win
   ```
   De SIGSEGV-handler logt `REG_RIP` en `REG_RSP`, dus `food.log` vertelt je of
   de overname geland is, zelfs wanneer het kind sterft vóór je kunt aanhaken.

4. **Verwijder de uitlijnfix** in `fooc.c` en zie de `#GP`-fout met de
   `si_addr = 0`-handtekening. Lees dan `/proc/sys/kernel/randomize_va_space`
   en denk na over wat ASLR randomiseert en wat niet.

5. **Breek de libc-symbolresolutie** en zie hoe `fooc` zich aanpast. Het hele
   punt van de `/proc/self/maps`-benadering is dat geen enkele offset
   hardcoded is.

6. **Schrijf een vierde techniek.** Een `ret2csu`-achtige keten als je
   `__libc_csu_init` kunt vinden, of een SROP-keten (`sigreturn`-frames laten
   je alle registers tegelijk controleren). Beide zijn puur ROP en hebben geen
   uitvoerbaar geheugen nodig.

7. **Fix `food.c` goed**, één bug tegelijk, en draai het exploit opnieuw na
   elke fix. De volgorde in de tabel bovenaan `food.c` is ongeveer de juiste om
   in te denken: beperk eerst de read, want niets anders doet ertoe voordat de
   bug weg is.

---

## Opruiming

```sh
make stop        # stopt food
make clean       # verwijdert bouwproducten; laat food.log met rust
pkill -x sh      # alleen als je losse shells hebt van een test die misging
```

Merk op: `pkill -x food` matcht de proces**naam** precies. Gebruik geen
`pkill -f ./food` — dat patroon matcht ook de shell waarin je het typt en doodt
je eigen sessie. Dat is geen hypothese; het gebeurde terwijl dit lab werd
gebouwd.