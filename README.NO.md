# food / fooc — et stack-bufferoverløp, fra begge sider

Et C99-sikkerhetslaboratorium i to halvdeler:

- **`food.c`** — en bevisst sårbar TCP-daemon. Den har et ekte,
  lærebokaktig stack-bufferoverløp (CWE-120), og noen flere feil i tillegg.
- **`fooc.c`** — et exploit for det. Det beregner overflow-offsetet ved å
  disassemblere målprogrammet under kjøring, leser adresse-leaks fra daemonen,
  og får en shell på "offeret" ved å overskrive en lagret returadresse.

Poenget er ikke shellen. Poenget er at du kan følge med fra ende til annen
hvordan en minnesikkerhetsfeil blir til vilkårlig kodeutførelse — og deretter
se nøyaktig hvilke mottiltak som stopper hvert trinn i den kjeden. Hver linje i
begge programmene er kommentert, fordi mekanismen er leksjonen.

```
                   terminalen din
                         |
                     ./fooc   (exploit)
                         |
                    TCP 127.0.0.1:2342
                         |
                     ./food   (sårbar daemon)
                         |
                 fork() -> vulnerable_handler() -> overflow -> ret -> koden din
```

---

## ⚠️ Les dette først

**`food` er en bevisst ødelagt nettverkstjeneste. Den binder bare til
`127.0.0.1`, og den standarden er bevisst — la den være der.**

- Kjør den **ikke** på en maskin du bryr deg om, eller på noe med data på.
- Bind den **ikke** til `0.0.0.0` eller en ekte nettverksgrensesnitt. Den er
  bevisst eksternt utnyttbar.
- Å peke `fooc` mot en vert du ikke eier eller ikke har skriftlig tillatelse
  til å teste, er en datainnbruddsforseelse i de fleste jurisdiksjoner — også
  etter UK Computer Misuse Act og US Computer Fraud and Abuse Act.
- Den binder til en uprivilegert port (>1024), så du trenger ikke root. Ikke
  "forbedre" den ved å legge til capabilities eller kjøre den som
  systemtjeneste.
- Hver tilkobling håndteres i et `fork()`et barn, og `food` reaper det, så
  krasj hoper seg ikke opp. Hvis du etterpå finner dusinvis av løse
  `sh`-prosesser, er `pkill -x sh` oppryddingen.

I tvilstilfeller: Dette laboratoriet er for en virtuell maskin eller en
container, på et nettverk du kontrollerer, på en maskin uten noe du ville
savnet.

---

## Rask start

```sh
make            # bygger food, fooc og test-harnessene
make run        # starter food på 127.0.0.1:2342, løsrevet i bakgrunnen
make test       # kjører alle tre exploit-teknikkene
make stop       # stopper daemonen
```

Deretter for hånd:

```sh
./fooc -t leak        # se adresse-leaksene food gir fra seg
./fooc -t demo -v     # send søppel; se food dø med SIGSEGV
./fooc -t ret2win -i  # hopp til en funksjon som allerede finnes -> shell
```

### Krav

| Verktøy | Til hva | Merknader |
|---|---|---|
| `gcc` (eller clang) | bygging | C99. Testet med gcc 16.2 |
| `objdump` | `fooc` | binutils. `fooc` kaller det under kjøring |
| `nasm` | `make verify` | bare for å kryssjekke shellcoden; hoppes over hvis det mangler |
| `gdb` | `make debug` | valgfritt |
| Linux, x86-64 | begge | payload og gadget-jakt er arkitekturavhengige |

`fooc` trenger også `-ldl` for `dlsym()`; Makefile-et ordner det.

---

## Feilen

Én linje i `food.c` er hele angrepsflaten:

```c
char buf[FOOD_BUFSZ];                  /* 64 bytes  */
n = read(fd, buf, FOOD_READMAX);       /* opptil 512 bytes fra nettverket */
```

64 bytes destinasjon, 512 bytes akseptert. Angriperen overskriver 448 bytes
forbi slutten av bufferen, og fordi stacken vokser nedover, betyr "forbi
slutten" "inn i rammen over" — og det er akkurat der den lagrede
rammepekeren og den **lagrede returadressen** ligger.

I en kompilert x86-64-funksjon ved `-O0`:

```
  høye adresser
  +------------------------+  rbp + 16 : kallers lokale
  |  ...                   |
  +------------------------+  rbp +  8 : LAGRET RETURADRESSE   <-- blir til RIP
  |  saved rbp (8 bytes)   |
  +------------------------+  rbp      : vår rammepeker
  |  line[128]             |
  |  buf[64]               |  <- rsp: det read() fyller
  +------------------------+
  lave adresser
```

Når funksjonen returnerer, popper `leave; ret` de 8 bytene inn i `RIP`, og
CPU-en hopper dit angriperen har valgt. Alt annet i dette laboratoriet er
aritmetikk om hvorhen man skal peke.

For denne builden er tallene: `buf` er 64 bytes, det lagrede `rbp` er 8, så
returadressen ligger på offset **88** fra starten av `buf`. `fooc` hardkoder
ikke det — det disassemblerer `food` og finner `lea -0x50(%rbp)` foran
`call read@plt`, så det fortsatt virker hvis du endrer `FOOD_BUFSZ`.

> gcc forteller deg allerede om dette. Å bygge `food` skriver ut:
> `warning: 'read' writing 512 bytes into a region of size 64 overflows the
> destination [-Wstringop-overflow=]`. Aldri undertrykk den advarselen i ekte
> kode. Den er gratis sikkerhet.

---

## De tre teknikkene

`fooc -t <technique>`. De står i den rekkefølgen en ekte angriper ville
arbeidet seg gjennom dem, fordi hver enkelt trenger det den forrige lærte deg.

### 1. `ret2win` — kontroller instruksjonspekeren

```
[ 88 bytes søppel ][ adressen til food's win() ]
                   ^ saved rbp
                                    ^ blir til RIP
```

`win()` er en funksjon i målprogrammet som exec'er `/bin/sh`. Å overskrive
returadressen med dens adresse er hele exploitet.

**Hva det lærer:** du har vilkårlig kontroll over instruksjonspekeren. Det
trenger heller ikke noe leak, fordi binærfilen er bygget `-no-pie`, så `win()`
sitter på en fast adresse for alltid.

**Den virkelige verdens ekvivalent** er ikke "angrep er enkle", men "ikke
send ut udokumenterte bakdører i nettverks-binærfiler". Hvis en funksjon som
`win()` finnes i binærfilen din, vil et bufferoverløp finne den. Det er
bokstavelig talt Juniper ScreenOS-bakdør-CVE-klassen.

**Forsvar:** `-fPIE` (eller ASLR) randomiserer lasteadressen, så angriperen må
kjenne adressen — noe som vanligvis betyr at de først trenger et leak. Derfor
feiler `ret2win` mot `food_hardened`.

### 2. `ret2libc` — kall hva som helst, ved navn

```
[ søppel ][ pop rdi; ret ][ adressen til "/bin/sh" ][ adressen til system() ]
          ^^^^^^^^^^^^     ^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^
          setter rdi       strengen å sende       funksjonen å kalle
```

Ved utførelse: `ret` popper `pop rdi; ret` inn i RIP; det popper
`"/bin/sh"`-pekeren inn i `RDI`; dets `ret` popper `system()` inn i RIP, mens
`RDI` fortsatt holder strengen. `system("/bin/sh")` kjører.

Gadgets (`pop rdi; ret`) er ikke i `food` — denne glibc-en har ikke noe
`__libc_csu_init` — så `fooc` finner dem ved å skanne live libc-minne etter
byte-paret `5f c3`. Den lokaliserer libc via `/proc/self/maps`, finner
offsets for `system` og `"/bin/sh"` med `dlsym()` og beregner basen fra
leaket `food` publiserer. Ingenting er hardkodet, så det overlever en
libc-oppdatering.

**Hva det lærer:** når du først kan kontrollere `RIP`, kan du kjede sammen
*eksisterende* instruksjoner. Dette er return-oriented programming, og det er
slik nesten alle ekte exploits ser ut, fordi det ikke krever
angriperlevert kjørbart minne.

**Forsvar:** ingen av kompilator-flagene stopper dette alene. Det virker mot
en PIE-binærfil, med NX, med canary — så lenge angriperen har et leak.
Forsvarene er "ikke ha overløpet" og "ikke lek adresser." Se tabellen nedenfor.

### 3. `shellcode` — kjør din egen maskinkode

23 bytes, plassert ved starten av bufferen, med `RIP` pekende på dem:

```asm
xor    esi, esi                    ; envp = NULL
xor    edx, edx                    ; argv = NULL
movabs rdi, 0x68732f6e69622f       ; rdi = "/bin/sh\0" som 8 rå bytes
push   rdi                         ; legg strengen på stacken
mov    rdi, rsp                    ; rdi = &"/bin/sh"
push   0x3b                        ; 59 = __NR_execve
pop    rax
syscall                           ; vi er nå en shell
```

Dette er den reneste formen for feilen: angriperen leverer *instruksjonene*,
ikke bare adressen til instruksjoner som allerede finnes. Ingen libc-offsets
nødvendig, så det virker i prinsippet mot et statisk linket, fullt
randomisert mål.

`make verify` assemblerer `shellcode.S` og diff'er det mot byte-arrayet
innebygd i `fooc.c`, så de to ikke kan drive fra hverandre.

**Forsvar:** **NX** (også kalt W^X, "no execute"). Å markere stacken som
ikke-kjørbar gjør at maskinvaren nekter å hente instruksjoner fra den, og
`ret`-et lander på en side som ikke kan kjøres. Det er derfor `make food`
sender `-z execstack`: en vanlig Linux-stack er `rw-p`, ikke `rwx`, og
teknikken dør med SIGSEGV ved `RIP = payloadens adresse`. Den absolutt
viktigste leksjonen i laboratoriet er at hver eneste av disse bytene bare
virker fordi kompilatoren fikk beskjed om å la stacken være kjørbar. Det
flagget er på til gagn for ingen.

### Også inkludert

| Modus | Hva den gjør |
|---|---|
| `-t leak` | kobler til, skriver ut leaks, sender ingenting |
| `-t demo` | sender `rip_off + 8` bytes `0x41`, så `RIP` blir `0x4141...` og daemonen dør. Beviser feilen helt uten adressekunnskap |
| `-t sled` | et ret-sled, bevisst beholdt som et **feilende** eksempel. Uten et leak ville du brute-force ASLR ved å fylle bufferen med adressen til et `ret`. Det kan ikke virke her: `food` aksepterer 512 bytes, så sleden har ~53 slots mot ~28 bits entropi. Implementert så du kan se det feile og bekrefte at mekanismen virkelig er "CPU-en følger en kjede av rets" |

---

## Mottiltak-tabellen

Dette er delen å huske. Hver rad er et ekte forsvar, og høyre kolonne viser hva
den faktisk gjør med hendelseskjeden.

| Mottiltak | Slik aktiverer du | Hva den stopper | Hva den *ikke* stopper |
|---|---|---|---|
| **Begrens read** | `n = read(fd, buf, sizeof buf - 1);` | **Alt.** Feilen finnes ikke, så ingenting nedstrøms betyr noe | Ingenting — dette er den eneste fullstendige fixen |
| **Stack-canary** | `-fstack-protector-strong` (gccs standard) | `ret`-et: canaryen sjekkes ved funksjonsavslutningen, så smadringen oppdages og prosessen aborter før `RIP` poppes | En feil i en funksjon *uten* array (ingenting å beskytte); et overløp som holder seg under canaryen; alt som ikke returnerer normalt |
| **NX / W^X** | `-z noexecstack` (standarden) | Shellcode. Payloadens egne instruksjoner kan ikke hentes | ret2win og ret2libc fullstendig. Disse er *grunnen* til at ROP finnes |
| **PIE + ASLR** | `-fPIE` + ASLR=2 (begge standard) | ret2wins hardkodede adresser. Alt flytter seg ved hver kjøring | Alt der angriperen har et leak. ASLR hever prisen på et exploit; det er ikke en fix. Merk at stack, heap og mmap randomiseres, men hoved-binærfilens *innhold* gjør det ikke — det er det ROP-kjeder bruker |
| **Ikke lek** | ingen `printf("%p")` til klienter; initialiser før du skriver ut | Informasjonsleaket som gjør ASLR fra "dyrt" til "gratis" | — |
| **Ikke bruk `printf(user_data)`** | `printf("%s", buf)` i stedet for `printf(buf)` | Format-streng-feil: `%x`-stack-reads, `%n`-vilkårlige skrivninger, som er en *annen* vei til RCE | — |
| **Ikke bruk upålitelige stier** | valider og `openat()` under en fast mappe | Sti-traversal (CWE-22) | — |
| **CET / shadow stack** | `-fcf-protection=full`, kjernens og CPU-ens støtte | `ret`-et selv: shadow stacken husker den *ekte* returadressen og feiler ved mismatch. Fanger ROP-kjeder som bruker maskinvare-`ret` | Angrep som aldri `ret`-er (call-oriented, eller å overskrive en funksjonspekermål med en gadget-kjede som ikke trenger retur) |
| **Sikre språk** | Rust, Go, C# for ny kode | Hele klassen. Bounds-sjekker utføres ved kjøring, ikke håpet på ved review | — |

### Se det selv

```sh
make run            # sårbar daemon
make test           # alle tre teknikkene virker

make test-hardened  # samme kildekode, mottiltak på
```

`test-hardened` bygger `food_hardened` med `-fstack-protector-strong -fPIE -pie
-z noexecstack`, bytter den inn, kjører alle tre igjen og legger så den
sårbare tilbake. Du vil se:

```
### stack segment: 'rw-p' (NOT executable) is what you want to see
--- ret2win   was stopped by the mitigations (as expected)
--- ret2libc  was stopped by the mitigations (as expected)
--- shellcode was stopped by the mitigations (as expected)
```

Og i den hardnede daemonens logg, canaryen som utløses:

```
*** stack smashing detected ***: terminated
```

Les det nøye, for det er den viktigste linjen i hele laboratoriet: **canaryen
fanget ret2win, ikke PIE.** Alle tre teknikkene dør ved canaryen, fordi alle
tre går gjennom det samme `read()` og ødelegger den samme rammen. NX stopper
bare i tillegg shellcodens *kode*; PIE bryter bare i tillegg den hardkodede
adressen. Slå dem på enkeltvis, og du vil oppdage at de fleste enkeltstående
mottiltak etterlater deg utsatt for noe.

---

## Filer

| Fil | Formål |
|---|---|
| `food.c` | den sårbare daemonen. 6 nummererte feil, hver med sin fix i kommentaren |
| `fooc.c` | exploitet. objdump-basert offset-oppdagelse, `/proc`-basert libc-oppdagelse, 4 payload-byggere |
| `shellcode.S` | de 23 shellcode-bytende som assembly, så de kan leses og verifiseres. `fooc` bærer dem inline og trenger ikke dette ved kjøring |
| `Makefile` | bygger, tester og den hardnede sammenligningen |
| `tests/pty_test.c` | driver `fooc` gjennom et pseudo-terminal og sjekker for ekte shell-output |
| `tests/sock_test.c` | uavhengig verifikator over en rå socket, så resultatet ikke avhenger av `fooc` |
| `food.log` | daemonens logg. Beviset ditt på hva som skjedde |

---

## To feil i dette laboratoriet som er verdt å forstå

Dette er ikke målprogrammets feil. Det er feil i exploitet og i dets
test-harness, og begge produserte overbevisende løgner. De er dokumentert i
kilden der de bor; her står de fordi sviktmønstrene er lærerike.

### Stack-justering: krasjet som ikke er en NULL-dereferanse

**Symptom.** Kapringen lander korrekt — `gdb` viser deg i `win()` — og så dør
det aller første `win()` gjør, en `dprintf()`. `SIGSEGV`-handleren rapporterer
`RIP` dypt inne i glibcs formatter og en feiladresse på `(nil)`, noe som ser
nøyaktig ut som en korrupt peker.

**Årsak.** System V AMD64-ABI-en krever 16-byte stack-justering. Et normalt
`ret` gjenoppretter `%rsp` til nøyaktig det det matchende `call` lagret, så
invarianten bevares gratis. Vårt nakne `ret` gjør ikke det: etter det gjelder
`%rsp = buf + rip_off`. Her er `buf` 16-byte justert og `rip_off` er 88, så
callee-en får en stack som er 8 mod 16. glibc er kompilert med SSE2, og
`movaps` **feiler** på et feiljustert operand. På x86 reiser det `#GP`, ikke
`#PF`, så kjernen har ingen feiladresse og rapporterer `si_addr = 0`. Det
NULL-et er fingerpeket: en justeringsfeil forkledd som en NULL-dereferanse.

**Fix.** Én `ret`-gadget *ved offset `rip_off`*, som flytter det ekte målet 8
bytes opp, siden hvert `ret` legger nøyaktig 8 til `%rsp`. Rekkefølgen er
kritisk: en tidligere versjon la `ret`-et *etter* målet og produserte
`[ padding | target | ret ]`, der det avsluttende `ret`-et aldri nås og fixen
stille og rolig ikke gjør noe. Et påfallende `ret` som ser ut som en feil, er
nesten alltid bevisst.

### Én socket, to lesere: byten som forsvant

**Symptom.** Shellcode ble rapportert som fungerende. Så ble pty-harnessen
gjort strengere (slå av `ECHO`, så terminalen sluttet å ekkoe harnessens egen
kommandolinje tilbake til seg), og teknikken begynte å feile. Under alt sammen
mistet hver teknikk nøyaktig én byte fra starten av hver utgangs-chunk:
`uid=1000(hanez)` ble skrevet ut som `id=1000(hanez)`, `PWNED-OK` som
`WNED-OK`, `Linux 7.2.7` som `inux 7.2.7`.

**Årsak.** `fooc` pleide å `dup2()`e socketen inn på sitt eget stdin/stdout
og `execv()`e en *lokal* `/bin/sh`, mens et forket relay-barn også leste den
samme socketen for å flytte utdata til terminalen. Kjernen bryr seg ikke om at
de to samarbeider. En streamsocket har **én** lese-cursor, og hver leser flytter
den, så bytes deles uforutsigbart mellom dem. Den lokale shellen, som er en
interaktiv login-shell, leste nøyaktig én byte og kastet den — hver eneste
gang. `strace -f` viste det umiddelbart:

```
read(0, "u", 1)                              <- den lokale shellen, spiser en byte
read(4, "id=1000(hanez) gid=1000(hanez) g".., 310)   <- relayet, 1 byte for kort
```

**Fix.** Det er ingen shell på denne siden i det hele tatt. Det er nøyaktig én
shell i hele bildet, og den er på offeret, inne i den kaprede prosessen, med
TCP-tilkoblingen som sin stdin/stdout. Denne siden flytter bare bytes. Hvis du
noen gang trenger to forbrukere av en stream, trenger den streamen én eneste
leser som bevisst demultiplekser den.

**Meta-leksjonen.** Det første "fungerende" resultatet var et falskt positivt
produsert av at pty-en ekkoet harnessens egen kommandolinje tilbake til den, og
fixen for det falske positive er det som avslørte den ekte feilen. Tester som
ikke kan feile, er verre enn ingen tester, fordi de forvandler "jeg vet ikke"
til "det virker." En test-harness fortjener samme mistenksomhet som koden den
tester.

---

## Å eksperimentere med det

Ting som er verdt å prøve, omtrent i den rekkefølgen du lærer mest av dem:

1. **Endre `FOOD_BUFSZ` til 128.** Kjør `fooc` igjen. Det burde fortsatt virke
   uten endringer, fordi det leser offsetet ut av disassembly-en. Bryt det så
   for hånd — hardkod 88 — og se det krasje. Legg så til et andre array mellom
   `buf` og de lagrede registrene, og se den automatiske oppdagelsen håndtere
   det.

2. **Legg til `-Wformat-security` og se hva format-streng-stien gjør.** Send
   `%p %p %p %n` og se `food` lekke stacken.

3. **Bruk gdb.** `make debug`, deretter:
   ```gdb
   (gdb) break food.c:393        # det read() som renner over
   (gdb) run -p 2342
   (gdb) info registers rsp rbp
   (gdb) x/24gx $rsp             # legg merke til hvor returadressen ligger
   (gdb) c                        # i et annet terminal: ./fooc -t ret2win
   ```
   `SIGSEGV`-handleren logger `REG_RIP` og `REG_RSP`, så `food.log` forteller
   deg om kapringen landet, selv når barnet dør før du kan koble deg på.

4. **Slett justeringsfixen** i `fooc.c` og se `#GP`-feilen med
   `si_addr = 0`-signaturen. Les så `/proc/sys/kernel/randomize_va_space` og
   tenk over hva ASLR randomiserer, og hva det ikke gjør.

5. **Bryt libc-symboloppløsningen** og se `fooc` tilpasse seg. Hele poenget
   med `/proc/self/maps`-tilnærmingen er at intet offset er hardkodet.

6. **Skriv en fjerde teknikk.** En `ret2csu`-lignende kjede hvis du kan finne
   `__libc_csu_init`, eller en SROP-kjede (`sigreturn`-rammer lar deg
   kontrollere alle registre på én gang). Begge er rent ROP og trenger ikke
   kjørbart minne.

7. **Fix `food.c` ordentlig**, én feil om gangen, og kjør exploitet igjen etter
   hver fix. Rekkefølgen i tabellen øverst i `food.c` er omtrent den riktige
   rekkefølgen å tenke i: begrens først read-et, for ingenting annet betyr noe
   før feilen er borte.

---

## Opprydding

```sh
make stop        # stopper food
make clean       # fjerner byggeprodukter; lar food.log være i fred
pkill -x sh      # bare hvis du har løse shells fra en test som gikk skeis
```

Merk at `pkill -x food` matcher prosess**navnet** nøyaktig. Ikke bruk
`pkill -f ./food` — det mønsteret matcher også shellen du skrev det i, og
dreper din egen sesjon. Det er ikke en hypotese; det skjedde mens dette ble
bygget.