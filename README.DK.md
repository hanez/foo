# food / fooc — et stack-bufferoverløb, fra begge sider

Et C99-sikkerhedslaboratorium i to halvdele:

- **`food.c`** — en bevidst sårbar TCP-daemon. Den har et ægte,
  lærebogsagtigt stack-bufferoverløb (CWE-120) og et par fejl oveni.
- **`fooc.c`** — et exploit til den. Det beregner overflow-offsettet ved at
  disassemblere target-programmet ved kørsel, læser adresse-leaks fra daemonen
  og får en shell på "offeret" ved at overskrive en gemt returadresse.

Pointen er ikke shellen. Pointen er, at du kan følge med hele vejen, hvordan
en hukommelsessikkerhedsfejl bliver til vilkårlig kodeudførelse — og derefter
se præcist, hvilke modforanstaltninger der stopper hvert trin i den kæde. Hver
linje i begge programmer er kommenteret, fordi mekanismen er lektionen.

```
                   din terminal
                         |
                     ./fooc   (exploit)
                         |
                    TCP 127.0.0.1:2342
                         |
                     ./food   (sårbar daemon)
                         |
                 fork() -> vulnerable_handler() -> overflow -> ret -> din kode
```

---

## ⚠️ Læs dette først

**`food` er en bevidst ødelagt netværkstjeneste. Den binder kun til
`127.0.0.1`, og den standard er bevidst — lad den være der.**

- Kør den **ikke** på en maskine, du holder af, eller på noget med data på.
- Bind den **ikke** til `0.0.0.0` eller en rigtig netværksgrænseflade. Den er
  bevidst eksternt udnyttelig.
- At rette `fooc` mod en host, du ikke ejer eller ikke har skriftlig tilladelse
  til at teste, er en computerindbrudsforseelse i de fleste jurisdiktioner —
  også efter UK Computer Misuse Act og US Computer Fraud and Abuse Act.
- Den binder til en uprivilegeret port (>1024), så du behøver ikke root. Forbedr
  den ikke ved at tilføje capabilities eller køre den som systemtjeneste.
- Hver forbindelse håndteres i et `fork()`et barn, og `food` reaper det, så
  nedbrud hober sig ikke op. Hvis du bagefter finder dusinvis af strejfende
  `sh`-processer, er `pkill -x sh` oprydningen.

I tvivlstilfælde: Dette laboratorium er til en virtuel maskine eller container,
på et netværk du kontrollerer, på en maskine uden noget, du ville savne.

---

## Hurtig start

```sh
make            # bygger food, fooc og test-harnessene
make run        # starter food på 127.0.0.1:2342, frakoblet i baggrunden
make test       # kører alle tre exploit-teknikker
make stop       # stopper daemonen
```

Derefter i hånden:

```sh
./fooc -t leak        # se de adresse-leaks, food udleverer
./fooc -t demo -v     # send junk; se food dø med SIGSEGV
./fooc -t ret2win -i  # hop til en funktion, der allerede findes -> shell
```

### Krav

| Værktøj | Hvortil | Bemærkninger |
|---|---|---|
| `gcc` (eller clang) | bygning | C99. Testet med gcc 16.2 |
| `objdump` | `fooc` | binutils. `fooc` kalder det ved kørsel |
| `nasm` | `make verify` | kun til at krydstjekke shellcoden; springes over, hvis ikke til stede |
| `gdb` | `make debug` | valgfrit |
| Linux, x86-64 | begge | payload og gadget-jagt er arkitekturafhængige |

`fooc` har også brug for `-ldl` til `dlsym()`; Makefile'et klarer det.

---

## Fejlen

Én linje i `food.c` er hele angrebsfladen:

```c
char buf[FOOD_BUFSZ];                  /* 64 bytes  */
n = read(fd, buf, FOOD_READMAX);       /* op til 512 bytes fra netværket */
```

64 bytes destination, 512 bytes accepteret. Angriberen overskriver 448 bytes
forbi enden af bufferen, og fordi stacken vokser nedad, betyder "forbi enden"
"ind i det ovenstående frame" — og det er præcis der, den gemte
framepointer og den **gemte returadresse** ligger.

I en kompileret x86-64-funktion ved `-O0`:

```
  høje adresser
  +------------------------+  rbp + 16 : callerens lokale
  |  ...                   |
  +------------------------+  rbp +  8 : GEMT RETURADRESSE   <-- bliver til RIP
  |  saved rbp (8 bytes)   |
  +------------------------+  rbp      : vores framepointer
  |  line[128]             |
  |  buf[64]               |  <- rsp: det, read() fylder
  +------------------------+
  lave adresser
```

Når funktionen returnerer, popper `leave; ret` de 8 bytes ind i `RIP`, og CPU'en
hopper, hvor angriberen har bestemt. Alt andet i dette laboratorium er
aritmetik om, hvorhen der skal peges.

For denne build er tallene: `buf` er 64 bytes, det gemte `rbp` er 8, så
returadressen ligger på offset **88** fra starten af `buf`. `fooc` hardkoder
ikke det — det disassemblerer `food` og finder `lea -0x50(%rbp)` foran
`call read@plt`, så det fortsat virker, hvis du ændrer `FOOD_BUFSZ`.

> gcc fortæller dig allerede om det. At bygge `food` printer:
> `warning: 'read' writing 512 bytes into a region of size 64 overflows the
> destination [-Wstringop-overflow=]`. Undertryk aldrig den advarsel i ægte
> kode. Den er gratis sikkerhed.

---

## De tre teknikker

`fooc -t <technique>`. De står i den rækkefølge, en ægte angriber ville
arbejde sig igennem dem, fordi hver enkelt har brug for det, den forrige lærte
dig.

### 1. `ret2win` — kontrollér instruktionsmarkøren

```
[ 88 bytes junk ][ adressen på food's win() ]
                ^ saved rbp
                                 ^ bliver til RIP
```

`win()` er en funktion i target-programmet, der exec'er `/bin/sh`. At
overskrive returadressen med dens adresse er hele exploitet.

**Hvad det lærer:** du har vilkårlig kontrol over instruktionsmarkøren. Det
kræver heller ikke noget leak, fordi binærfilen er bygget `-no-pie`, så `win()`
sidder på en fast adresse for evigt.

**Den virkelige verdens ækvivalent** er ikke "angreb er nemme", men "skib ikke
udokumenterede bagdøre i netværks-binærfiler". Hvis en funktion som `win()`
findes i din binærfil, vil et bufferoverløb finde den. Det er bogstaveligt talt
Juniper ScreenOS-bagdør-CVE-klassen.

**Forsvar:** `-fPIE` (eller ASLR) randomiserer load-adressen, så angriberen må
kende adressen — hvilket som regel betyder, at de først har brug for et leak.
Derfor fejler `ret2win` mod `food_hardened`.

### 2. `ret2libc` — kald hvad som helst, ved navn

```
[ junk ][ pop rdi; ret ][ adressen på "/bin/sh" ][ adressen på system() ]
        ^^^^^^^^^^^^     ^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^
        sætter rdi       strengen at sende      funktionen at kalde
```

Ved udførelse: `ret` popper `pop rdi; ret` ind i RIP; det popper
`"/bin/sh"`-pointeren ind i `RDI`; dets `ret` popper `system()` ind i RIP, mens
`RDI` stadig holder strengen. `system("/bin/sh")` kører.

Gadgets (`pop rdi; ret`) er ikke i `food` — denne glibc har intet
`__libc_csu_init` — så `fooc` finder dem ved at scanne live libc-hukommelse
efter byteparret `5f c3`. Det lokaliserer libc via `/proc/self/maps`, finder
offsets for `system` og `"/bin/sh"` med `dlsym()` og beregner basen ud fra det
leak, `food` offentliggør. Intet er hardkodet, så det overlever en
libc-opdatering.

**Hvad det lærer:** når du først kan kontrollere `RIP`, kan du kæde
*eksisterende* instruktioner sammen. Det er return-oriented programming, og det
er sådan næsten alle virkelige exploits ser ud, fordi det ikke kræver
angriberleveret eksekverbar hukommelse.

**Forsvar:** ingen af compiler-flagene stopper det alene. Det virker mod en
PIE-binærfil, med NX, med canary — så længe angriberen har et leak.
Forsvarene er "hav ikke overløbet" og "læk ikke adresser". Se tabellen nedenfor.

### 3. `shellcode` — kør din egen maskinkode

23 bytes, placeret i starten af bufferen, med `RIP` pegende på dem:

```asm
xor    esi, esi                    ; envp = NULL
xor    edx, edx                    ; argv = NULL
movabs rdi, 0x68732f6e69622f       ; rdi = "/bin/sh\0" som 8 rå bytes
push   rdi                         ; læg strengen på stacken
mov    rdi, rsp                    ; rdi = &"/bin/sh"
push   0x3b                        ; 59 = __NR_execve
pop    rax
syscall                           ; vi er nu en shell
```

Det er den reneste form for fejlen: angriberen leverer *instruktionerne*, ikke
bare adressen på instruktioner, der allerede findes. Ingen libc-offsets
nødvendige, så det virker i princippet mod et statisk linket, fuldt
randomiseret target.

`make verify` assemblerer `shellcode.S` og diff'er det mod byte-arrayet, der er
indlejret i `fooc.c`, så de to ikke kan drive fra hinanden.

**Forsvar:** **NX** (også kaldet W^X, "no execute"). At markere stacken som
ikke-eksekverbar får hardwaren til at nægte at hente instruktioner fra den, og
`ret`-et lander på en side, der ikke kan køre. Det er derfor `make food`
giver `-z execstack`: en normal Linux-stack er `rw-p`, ikke `rwx`, og teknikken
dør med SIGSEGV ved `RIP = payloadens adresse`. Den absolut vigtigste lektion i
laboratoriet er, at hver eneste af disse bytes kun virker, fordi compileren fik
besked på at lade stacken være eksekverbar. Det flag er tændt til gavn for
ingen.

### Også inkluderet

| Tilstand | Hvad den gør |
|---|---|
| `-t leak` | forbinder, printer leaks, sender intet |
| `-t demo` | sender `rip_off + 8` bytes `0x41`, så `RIP` bliver `0x4141...` og daemonen dør. Beviser fejlen helt uden adresseviden |
| `-t sled` | et ret-sled, bevidst beholdt som et **fejlende** eksempel. Uden et leak ville du brute-force ASLR ved at fylde bufferen med adressen på et `ret`. Det kan ikke virke her: `food` accepterer 512 bytes, så sleden har ~53 slots mod ~28 bit entropi. Implementeret, så du kan se det fejle og bekræfte, at mekanismen virkelig er "CPU'en følger en kæde af rets" |

---

## Tabellen over modforanstaltninger

Det er den del, man skal huske. Hver række er et ægte forsvar, og højre kolonne
viser, hvad den rent faktisk gør ved begivenhedskæden.

| Modforanstaltning | Sådan aktiveres | Hvad den stopper | Hvad den *ikke* stopper |
|---|---|---|---|
| **Begræns read** | `n = read(fd, buf, sizeof buf - 1);` | **Alt.** Fejlen findes ikke, så intet nedstrøms betyder noget | Intet — det er den eneste fuldstændige fix |
| **Stack-canary** | `-fstack-protector-strong` (gccs standard) | `ret`-et: canaryen tjekkes ved funktionens afslutning, så smadringen opdages, og processen abort'er, før `RIP` poppes | En fejl i en funktion *uden* array (intet at beskytte); et overflow, der holder sig under canaryen; alt, der ikke returnerer normalt |
| **NX / W^X** | `-z noexecstack` (standarden) | Shellcode. Payloadens egne instruktioner kan ikke hentes | ret2win og ret2libc fuldstændigt. De er *grunden* til, at ROP findes |
| **PIE + ASLR** | `-fPIE` + ASLR=2 (begge standard) | ret2wins hardkodede adresser. Alt flytter sig ved hver kørsel | Alt, hvor angriberen har et leak. ASLR hæver prisen på et exploit; det er ikke en fix. Bemærk, at stack, heap og mmap randomiseres, men hoved-binærfilens *indhold* gør ikke — det er det, ROP-kæder bruger |
| **Læk ikke** | ingen `printf("%p")` til klienter; initialisér før du printer | Det informationsleak, der gør ASLR til "gratis" i stedet for "dyrt" | — |
| **Brug ikke `printf(user_data)`** | `printf("%s", buf)` i stedet for `printf(buf)` | Format-string-fejl: `%x`-stack-reads, `%n`-vilkårlige skrivninger, hvilket er en *anden* vej til RCE | — |
| **Brug ikke utroverdige stier** | validér og `openat()` under en fast mappe | Sti-traversal (CWE-22) | — |
| **CET / shadow stack** | `-fcf-protection=full`, kernel- og CPU-understøttelse | `ret`-et selv: shadow stacken husker den *rigtige* returadresse og fault'er ved mismatch. Fanger ROP-kæder, der bruger hardware-`ret` | Angreb, der aldrig `ret` (call-oriented, eller at overskrive en funktionspegers mål med en gadget-kæde, der ikke behøver en retur) |
| **Sikre sprog** | Rust, Go, C# til ny kode | Hele klassen. Bounds-tjek udføres ved kørsel, ikke håbet på ved review | — |

### Se det selv

```sh
make run            # sårbar daemon
make test           # alle tre teknikker virker

make test-hardened  # samme kildekode, modforanstaltninger på
```

`test-hardened` bygger `food_hardened` med `-fstack-protector-strong -fPIE -pie
-z noexecstack`, bytter den ind, kører alle tre igen og lægger derefter den
sårbare tilbage. Du vil se:

```
### stack segment: 'rw-p' (NOT executable) is what you want to see
--- ret2win   was stopped by the mitigations (as expected)
--- ret2libc  was stopped by the mitigations (as expected)
--- shellcode was stopped by the mitigations (as expected)
```

Og i den hærdede daemons log, canaryen der udløses:

```
*** stack smashing detected ***: terminated
```

Læs det grundigt, for det er den vigtigste linje i hele laboratoriet: **canaryen
fangede ret2win, ikke PIE.** Alle tre teknikker dør ved canaryen, fordi alle tre
går gennem det samme `read()` og smadrer den samme frame. NX stopper kun
yderligere shellcodens *kode*; PIE bryder kun yderligere den hardkodede adresse.
Tænd dem enkeltvis, og du vil opdage, at de fleste enkelte modforanstaltninger
efterlader dig udsat over for noget.

---

## Filer

| Fil | Formål |
|---|---|
| `food.c` | den sårbare daemon. 6 nummererede fejl, hver med sin fix i kommentaren |
| `fooc.c` | exploitet. objdump-baseret offseterkendelse, `/proc`-baseret libc-erkendelse, 4 payload-buildere |
| `shellcode.S` | de 23 shellcode-bytes som assembly, så de kan læses og verificeres. `fooc` bærer dem inline og behøver ikke dette ved kørsel |
| `Makefile` | bygger, tester og den hærdede sammenligning |
| `tests/pty_test.c` | driver `fooc` gennem et pseudo-terminal og tjekker for ægte shell-output |
| `tests/sock_test.c` | uafhængig verifikator over en rå socket, så resultatet ikke afhænger af `fooc` |
| `food.log` | daemonens log. Dit bevis på, hvad der skete |

---

## To fejl i dette laboratorium, der er værd at forstå

Det er ikke target-programmets fejl. Det er fejl i exploitet og i dets
test-harness, og begge producerede overbevisende løgne. De er dokumenteret i
kilden, hvor de bor; her står de, fordi fiaskomønstrene er lærerige.

### Stack-justering: nedbruddet, der ikke er en NULL-dereference

**Symptom.** Kapringen lander korrekt — `gdb` viser dig i `win()` — og så dør
det allerførste, `win()` gør, et `dprintf()`. `SIGSEGV`-handleren rapporterer
`RIP` dybt inde i glibcs formatter og en fejladresse på `(nil)`, hvilket ser
præcis ud som en korrupt pointer.

**Årsag.** System V AMD64-ABI'en kræver 16-byte stack-justering. Et normalt
`ret` genskaber `%rsp` præcis som det tilsvarende `call` gemte det, så
invarianten bevares gratis. Vores nøgne `ret` gør ikke: efter det gælder
`%rsp = buf + rip_off`. Her er `buf` 16-byte justeret og `rip_off` er 88, så
callee'en får en stack, der er 8 mod 16. glibc er kompileret med SSE2, og
`movaps` **fault'er** ved et fejljusteret operand. På x86 rejser det `#GP`, ikke
`#PF`, så kernen har ingen fejladresse og rapporterer `si_addr = 0`. Det NULL
er fingerpeg: en justeringsfejl forklædt som en NULL-dereference.

**Fix.** Et `ret`-gadget *ved offset `rip_off`*, der flytter det rigtige target
8 bytes op, fordi hvert `ret` lægger præcis 8 til `%rsp`. Rækkefølgen er
kritisk: en tidligere version hæftede `ret`-et *efter* target og producerede
`[ padding | target | ret ]`, hvor det afsluttende `ret` aldrig nås, og fixen
stille og roligt intet gør. Et vildfarent `ret`, der ligner en fejl, er næsten
altid bevidst.

### Én socket, to læsere: det byte, der forsvandt

**Symptom.** Shellcode blev rapporteret som fungerende. Derefter blev
pty-harnessen gjort strengere (slukning af `ECHO`, så terminalen holdt op med at
ekko harnessens egen kommandolinje tilbage til sig selv), og teknikken begyndte
at fejle. Dybere set tabte hver teknik præcis ét byte fra starten af hver
udgangschunk: `uid=1000(hanez)` blev printet som `id=1000(hanez)`, `PWNED-OK`
som `WNED-OK`, `Linux 7.2.7` som `inux 7.2.7`.

**Årsag.** `fooc` plejede at `dup2()`e socket'en på sit eget stdin/stdout og
`execv()`e en *lokal* `/bin/sh`, mens et forket relay-barn også læste den samme
socket for at flytte output til terminalen. Kernen er ligeglad med, at de to
samarbejder. En streamsocket har **én** læse-cursor, og hver læser flytter den,
så bytes deles uforudsigeligt mellem dem. Den lokale shell, der er en
interaktiv login-shell, læste præcis ét byte og smed det væk — hver eneste
gang. `strace -f` viste det øjeblikkeligt:

```
read(0, "u", 1)                              <- den lokale shell, æder et byte
read(4, "id=1000(hanez) gid=1000(hanez) g".., 310)   <- relay'et, 1 byte for kort
```

**Fix.** Der er slet ingen shell på denne side. Der er præcis én shell i hele
billedet, og den er på offeret, inde i den kaprede proces, med
TCP-forbindelsen som dens stdin/stdout. Denne side flytter kun bytes. Hvis du
nogensinde har brug for to forbrugere af en stream, skal den stream have én
eneste læser, der bevidst demultiplekser den.

**Meta-lektionen.** Det første "fungerende" resultat var et falsk positivt,
produceret af at pty'en ekkoede harnessens egen kommandolinje tilbage til den,
og fixen for det falske positive er det, der afslørede den rigtige fejl. Tests,
der ikke kan fejle, er værre end ingen tests, fordi de forvandler "jeg ved
ikke" til "det virker". En test-harness fortjener samme mistænksomhed som den
kode, den tester.

---

## At pille ved det

Ting, der er værd at prøve, nogenlunde i den rækkefølge, du lærer mest af dem:

1. **Ændr `FOOD_BUFSZ` til 128.** Kør `fooc` igen. Det burde stadig virke uden
   ændringer, fordi det læser offset ud af disassembly'en. Bræk det så i
   hånden — hardkod 88 — og se det crashe. Tilføj derefter et andet array
   mellem `buf` og de gemte registre, og se den automatiske erkendelse klare
   det.

2. **Tilføj `-Wformat-security` og se, hvad format-string-stien gør.** Send
   `%p %p %p %n` og se `food` lække stacken.

3. **Brug gdb.** `make debug`, derefter:
   ```gdb
   (gdb) break food.c:393        # det read(), der løber over
   (gdb) run -p 2342
   (gdb) info registers rsp rbp
   (gdb) x/24gx $rsp             # bemærk, hvor returadressen ligger
   (gdb) c                        # i et andet terminal: ./fooc -t ret2win
   ```
   `SIGSEGV`-handleren logger `REG_RIP` og `REG_RSP`, så `food.log` fortæller
   dig, om kapringen landede, selv når barnet dør, før du kan koble på.

4. **Slet justeringsfixen** i `fooc.c` og se `#GP`-fejlen med
   `si_addr = 0`-signaturen. Læs derefter `/proc/sys/kernel/randomize_va_space`
   og tænk over, hvad ASLR randomiserer, og hvad det ikke gør.

5. **Bræk libc-symbolopløsningen** og se `fooc` tilpasse sig. Hele pointen med
   `/proc/self/maps`-tilgangen er, at intet offset er hardkodet.

6. **Skriv en fjerde teknik.** En `ret2csu`-lignende kæde, hvis du kan finde
   `__libc_csu_init`, eller en SROP-kæde (`sigreturn`-frames lader dig
   kontrollere alle registre på én gang). Begge er rent ROP og behøver ingen
   eksekverbar hukommelse.

7. **Fix `food.c` ordentligt**, én fejl ad gangen, og kør exploitet igen efter
   hver fix. Rækkefølgen i tabellen øverst i `food.c` er nogenlunde den rigtige
   rækkefølge at tænke i: begræns først read'et, for intet andet betyder noget,
   før fejlen er væk.

---

## Oprydning

```sh
make stop        # stopper food
make clean       # fjerner build-produkter; lader food.log være i fred
pkill -x sh      # kun hvis du har strejfende shells fra en test, der gik skævt
```

Bemærk: `pkill -x food` matcher proces**navnet** præcist. Brug ikke
`pkill -f ./food` — det mønster matcher også den shell, du har skrevet det i,
og dræber din egen session. Det er ikke en hypotese; det skete, mens dette
laboratorium blev bygget.