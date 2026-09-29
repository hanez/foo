# SUID-root-RCE-laboratorium — `foosd` (daemon) + `foosc` (exploit)

En ledsager til hovedlaboratoriet (`food` / `fooc`, en vanlig daemon der et
bufferoverløp gir deg en *bruker*-shell). Dette legger til den farligste
én-tegns-endringen i Unix: **setuid-biten**.

> `chmod u+s` forvandler «angriperen kan kjøre kode på denne verten» til
> «angriperen kan kjøre kode som **root** på denne verten».

Den setningen er hele laboratoriet. Alt nedenfor er mekanismen under den, skrevet
ned, slik at du når du skriver din egen programvare, vet nøyaktig hvilke to eller
tre filsystem-attributter og kompilator-flag som avgjør om en
minnesikkerhetsfeil i koden din er en irritasjon eller en root-shell.

Den endelige demoen, når `foosd` er setuid-root, er en **root-shell** som åpnes
over nettverket ved å utføre 32 bytes håndskrevet shellcode.

---

## 1. Hva setuid-biten faktisk gjør

Hver prosess på Linux bærer tre user-ID-er, og setuid-biten tukler med forholdet
mellom dem:

| ID | Navn | Betydning |
|----|------|---------|
| `ruid` | reell user-ID | kontoen som *startet* prosessen |
| `euid` | effektiv user-ID | det kjernen sjekker når den håndhever tilgang |
| (saved) | lagret set-user-ID | en «sporplass» en privilegert prosess kan vende tilbake til senere |

Et vanlig program har `ruid == euid`. Når du kjører en binærfil med
setuid-biten satt, eid av root:

```text
ruid = deg        (f.eks. 1000, «hanez»)
euid = eieren     (f.eks. 0, «root»)
```

Prosessen har derfor **roots autoritet**, selv om brukeren som startet den er
helt vanlig. Hvert sjekkpunkt kjernen utfører — kan denne prosessen lese
`/etc/shadow`? skrive en fil? drepe en annen prosess? — besvares med `euid`,
altså «ja, den er root».

`foosd` er en nettverksdaemon. Den binder en port og `fork()`er deretter et
barn per tilkobling. En fork *arver* euid-en, så hvert barn som håndterer en
tilkobling er også root. Overløpet i `foosd`s `vulnerable_handler()` er derfor
et overløp *inne i en root-prosess*.

**Diagnostiser det selv når daemonen kjører:**

```console
$ ./foosd ...            # se logglinjen den skriver ut ved start
[foosd 1234] startup: ruid=1000 euid=0 -> ROOT process
```

og fra exploitet:

```console
$ ./foosc -t leak
foosc: target euid=0 ruid=1000
```

---

## 2. Laboratoriet ved første øyekast

| Fil | Rolle |
|------|------|
| `foosd.c` | Den bevisst sårbare daemonen (eier feilene). Kjør som *setuid-root*-binærfil for root-shell-demoen. |
| `foosc.c` | Exploitet. Bruker som standard den 32-byte `setreuid + execve`-shellcode-teknikken. |
| `shellcode.S` | Referanse-shellcoden; `make verify` diff'er den mot byte-arrayen i `foosc.c`. |
| `tests/pty_suid_test.c` | Test-harness. Driver `foosc` gjennom et pseudo-terminal og beviser både «en shell kjørte» *og* «den var root» (`uid=0(`). |
| `Makefile` | Bygg, `setuid`/`unsetuid`-hjelpere, testmatrise. |
| `README.md` | Denne filen. |

> **Hvorfor en pty?** Exploitets siste handling er å videresende terminalen din
> til shellen som kjører på offeret. En pipe eller her-doc havner i feil ende av
> den videresendingen; en ekte terminal er påkrevd.

---

## 3. Rask start

```console
$ make                       # bygg alt, som din vanlige bruker
$ make setuid                # én gang, spør om sudo: chown root + chmod u+s
$ make run                   # start foosd på 127.0.0.1:2343
$ make test-suid             # full matrise; shellcode + ret2win-root skal gi root
```

Interaktiv røykprøve:

```console
$ ./foosc -t shellcode
...
foosc: target euid=0 ruid=1000
foosc: shell is on the victim (root if foosd is SUID); relaying
# id
uid=0(root) gid=0(root) groups=0(root)      <-- du er root, på offeret
# exit
```

Når du er ferdig:

```console
$ make stop
$ make unsetuid             # hygiene: etterlat aldri en root-SUID-binærfil
```

---

## 4. *Når skal jeg sette SUID-biten?* — svaret du ba om

Nøyaktig **én gang, etter byggingen, før du starter daemonen for
root-shell-demoene** — og bare på en maskin som er din, egnet til å kastes og
frakoblet nettverket:

```console
$ make            # kompiler foosd, foosc, tester
$ make setuid     # <-- ØYEBLIKKET. sudo chown root:root foosd && sudo chmod u+s foosd
$ make run        # start ETTER at du har satt biten
```

To regler som betyr mer enn det nøyaktige tidspunktet:

1. **Sett den bare når binærfilen er ferdig.** Hvis du bygger om (`make` /
   `make clean`) etter at du har satt biten, treffer du «Permission denied» når
   du skriver root-eide utdatafiler — og hvis du tvinger ombyggingen, gjenskaper
   verktøykjeden filen **uten** `s`-en og angrer stille og rolig oppsettet. Den
   kanoniske rekkefølgen ved enhver ombygging er derfor

   ```console
   $ make unsetuid && make && make setuid
   ```

2. **Fjern den når du er ferdig.** `make unsetuid`. En levende,
   root-eid setuid-binærfil med en utnyttbar feil i treet ditt er ikke et
   læremiddel, det er et root-hull med en kompileringsfeil mellom seg og
   ingenting. På en delt eller produksjonsmaskin: **ikke gjør noe av dette.**
   Daemonen nekter dessuten som standard å binde noe annet enn loopback (se §7).

Hvis du kjører exploitet *uten* noen gang å sette biten, går ingenting i stykker
— payloaden lander fortsatt, og du får fortsatt en shell. Forskjellen er i ett
tall, og exploitet sier det høyt:

```console
foosc: WARNING: the daemon is NOT running with euid 0.
       The payload will still land, but the shell will be
       a plain user shell, not root.
       Fix:  sudo make setuid
```

«Virket, men ikke root»-resultatet er selv en del av laboratoriet. Husk det til
neste avsnitt.

---

## 5. Mekanismen — og vrien som gjør SUID interessant

### 5.1 Overløpet (identisk med `food`)

`foosd`s handler gir et `read()` 512 bytes tillit, mens den rekker den et
64-byte stack-buffer:

```c
char buf[64];
n = read(fd, buf, 512);        /* <- CWE-120: 448 bytes over kanten */
```

På x86-64 vokser stacken nedover. Exploitet skriver 64 bytes søppel for å fylle
`buf`, 8 for å fylle den lagrede rammepekeren og 8 til for å erstatte den
**lagrede returadressen**. Når `vulnerable_handler` utfører `ret`, popper CPU-en
angriperens verdi inn i `RIP` — angriperkontrollert kodeutførelse. Exploitet
finner den nøyaktige avstanden (88 bytes for denne builden) ved å parse
`objdump`-utdata i stedet for å hardkode den, så tallet overlever ombygginger.

### 5.2 Vrien: shellen nekter å være root

Her er det der å tenke «SUID-feil → spawn /bin/sh → root» ville gått galt, og
hvorfor dette laboratoriet har nøyaktig den formen det har.

Når et setuid-root-program kjører, er `ruid` fortsatt den startende brukeren, og
`euid` er root. Hvis programmet — eller angriperen — nå starter en shell:

* `execve("/bin/sh")` endrer **ikke** u-id-ene; den nye prosessen arver
  `(ruid=1000, euid=0)`.
* bash (og dash) **sjekker nøyaktig den tilstanden ved start**. Fra
  bash-manualen: *«If the shell is started with the effective user (group) id
  not equal to the real user (group) id, and the -p option is not supplied, …
  the effective user id is set to the real user id.»*

Så shellen ser på seg selv og *dropper root* — et forsvar
shell-forfatterne bygde nøyaktig mot dette angrepet (den historiske
begrunnelsen var setuid-shell-/setuid-skript-problemet). Resultatet er
«virket, men ikke root»-tilfellene:

| Teknikk | Hva den utfører | Resulterende uid |
|-----------|------------------|---------------|
| `ret2win` | `foosd`s `win()` → `execl("/bin/sh")` | **1000** — shell landet, root nullstilt av bash |
| `ret2libc` | `system("/bin/sh")` → fersk `sh -c '/bin/sh'` | **1000** — samme nullstilling, ett nivå ned |
| `ret2win-root` | `foosd`s `win_root()` → `setreuid(0,0); execl("/bin/sh")` | **0** — ruid ryddet fra C |
| `shellcode` | 32 bytes: `setreuid(0,0); execve("/bin/sh")` | **0** — ruid ryddet fra maskinkode |

De to som når root, skiller seg fra de to som ikke gjør det, med nøyaktig én idé:
**de rydder den *reelle* uid-en, ikke bare den effektive.**

```c
setuid(0)          /* setter euid til 0, men ruid forblir 1000:
                      bash ser fortsatt euid != ruid og nullstiller FORTSATT.  */
setreuid(0, 0)     /* setter BEGGE: ruid = euid = 0.
                      bash ser like uid-er og beholder root.                  */
```

Det er derfor den klassiske `/bin/sh`-shellcoden du finner overalt på nettet,
starter med et uid-ryddende syscall — og grunnen til at shellcoden her er 32
bytes i stedet for 23: de første fem instruksjonene er

```asm
xor    edi, edi      ; ruid = 0
xor    esi, esi      ; euid = 0
push   0x71          ; 113 = __NR_setreuid
pop    rax
syscall
```

### 5.3 Så hva er exploitet, fra ende til annen?

1. `foosc` leser `foosd`s banner over socketen. Det får:
   - `ids=0/1000` — euid/ruid (SUID-selvdiagnosen)
   - `stack=…` og `libc=…` — pekere (ASLR-leaksene)
   - `BUF=…` — den nøyaktige adressen på bufferen den er i ferd med å renne over
2. Fra målbinærfilen (via `objdump`) lærer det `rip_off` og adressene til
   `win()` / `win_root()`.
3. Fra *sin egen* libc (via `/proc/self/maps` + `dlsym` + et minnesøk) måler det
   offsetene for `system`, `read`, `/bin/sh` og et `pop rdi; ret`-gadget —
   ingenting er hardkodet.
4. Det setter sammen payloaden. For `-t shellcode` er det:
   `[32-byte-setreuid+execve-kode][padding til RIP][ret-fix][adresse på buf]`.
5. `foosd`s `read()` renner over; `ret` lander på shellcoden; kjernen utfører
   `setreuid(0,0)` (helt greit: euid 0 er privilegert) og deretter `execve` av
   `/bin/sh`. bash starter med `ruid == euid == 0` og forblir root.
6. `foosc` videresender terminalen din til den root-shellen, til du skriver
   `exit`.

Én bekvemmelighetsdetalj som koster folk mye tid hvis den overses: exploitet
tester hver uid-ryddende adferd **uten** først å trenge setuid-biten. Kjør
`make test` før `make setuid`, så ser du hver teknikk lande en shell mens
`ROOT=MISSING` står; kjør `make test-suid` etter `make setuid`, så dukker
`ROOT=SEEN` opp ved de to teknikkene som rydder den reelle uid-en. Den A/B-en er
hele leksjonen, utført på ti sekunder.

---

## 6. De gamle one-linerne — og hvorfor de fleste av dem er døde

Har du lest om SUID, har du lest om `PATH`-kapring, `LD_PRELOAD` og
setuid-shells. Alle tre er klassiske, og alle tre feiler på et moderne system
mot *dette programmet*. Det er verdt å vite nøyaktig hvorfor, fordi grunnene er
forsvarene du får gratis:

| Angrepsklasse | Gammel påstand | Hvorfor den feiler på en moderne maskin |
|--------------|-----------|------------------------------|
| `LD_PRELOAD` av et ondsinnet bibliotek | «Setuid-programmet laster min `.so` og kjører koden min som root.» | Kjernen merker en setuid-binærfil som **AT_SECURE**; glibc ignorerer deretter `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_DEBUG` og venner. Miljøet behandles som *upålitelig input*. `LD_PRELOAD` mot en setuid-binærfil er en no-op. |
| `PATH`-kapring (`system("ls")` med en forgiftet PATH) | «Pek PATH mot en mappe med min falske `ls`; root-programmet kjører den.» | Et annet ansikt av samme forsvar: en AT_SECURE-prosess får en **sanert `PATH`** (en sikker standard, omtrent `/usr/local/bin:/usr/bin:/bin`) for `system()`/`execvp`, så den forgiftede mappen konsulteres aldri. |
| Setuid-`system()`-kommandoinjeksjon | «Den injiserte kommandoen kjører med euid 0.» | `system()` kjører kommandoen i en fersk `/bin/sh`, og den shellen — §5.2 — nullstiller `euid = ruid` ved start. Den injiserte kommandoen utføres med den *reelle* uid-en. (Det er fortsatt en feil; den eskalerer bare ikke lenger gjennom `/bin/sh`.) |
| Setuid-root-shell på disken (`cp /bin/sh /tmp; chmod u+s`) | «Kjør den, få root.» | Nøyaktig forsvaret ovenfor, og det er grunnen til at moderne distroer ikke leverer noen setuid-root-shell. Selv når du lykkes med å lage én, nekter bash å beholde euid 0 med mindre den startes med `-p`. |

Det som forblir i live, og det er dette laboratoriet: **programmet er *allerede*
root når det kjører.** Du trenger ikke miljøet eller `system()`; du trenger at
programmet utfører *din* kode (via en minnekorrupsjonsfeil) mens det er
privilegert, og at koden din er omhyggelig nok til selv å rette opp
uid-mismatchen — `setreuid(0,0)` — før den overrekker deg en shell.
Minnekorrupsjon + SUID er kombinasjonen som fortsatt ender i `uid=0`, noe som er
nøyaktig hvorfor minnesikre språk, canaries og no-execute-stacker ikke er en
moteavgjørelse.

---

## 7. Sikkerhetsgelenderne som er bygget inn i daemonen

`foosd` er bevisst det *dårligste* stykket programvare i dette repositoriet, så
det bærer også flest gelendere:

1. **Bare loopback, håndhevet.** `foosd` nekter enhver bind-adresse utenom
   loopback, med mindre du gir `-L`. En setuid-root-listener på et ekte
   grensesnitt er en fjern root-tjeneste; avslaget er standarden, så den
   farlige tilstanden må skrives inn bevisst.
2. **Selvdiagnose.** Ved start logger den `ruid`/`euid` og om den kjører som
   root, så konsollen viser den tilstanden exploitet avhenger av.
3. **Loggen når aldri klienten.** Daemonen reserverer en privat
   logg-descriptor før sockets erstatter fd 1, så crash-reporter-utdata og
   interne stier ikke kan leses tilbake over ledningen av angriperen.
4. **Crash-reporter.** En SIGSEGV-handler logger `RIP`/`RSP` — den verdien
   angriperen skrev inn i returadressen — så en vellykket kapring er synlig i
   `foosd.log` i stedet for å være en stille død.
5. **`make unsetuid`.** Fjerning av biten er scriptet, fordi å etterlate den
   satt er feiltilstanden folk faktisk har.

---

## 8. Mottiltak — hva hvert stopper, og hva det *ikke* stopper

Anvendt på `foosd` via `make hardened`, én om gangen eller sammen:

| Mottiltak | Hva det stopper | Hva det *ikke* stopper |
|------------|---------------|-------------------------|
| `-fstack-protector-strong` (canary) | Overløpet: `ret` oppdager en smadret canary og aborter, før angriperens adresse brukes. Stopper her **alle fire** teknikkene — de deler det ene sårbare `read()`-et. | Ingenting ved *designet*: binærfilen er fortsatt setuid-root; en annen feil (format-streng-`%n`, heap-overflow, use-after-free) har ingen canary å utløse. |
| `-fPIE -pie` (ASLR for binærfilen) | Bruk av forutsigbare `win()`/`win_root()`-adresser (ret2win-teknikkene). | Shellcode-teknikken, hvis en stack-adresse fortsatt lekker (`BUF=`-linjen). |
| `-z noexecstack` (NX / W^X) | Shellcoden: CPU-en nekter å hente instruksjoner fra en data-only-side, så et hopp til `buf` er et SIGSEGV. | ROP — å kjøre kode som allerede finnes (`ret2libc`). |
| Alle tre sammen | En vanskelig-å-renne-over, randomisert binærfil med ikke-kjørbar stack. Slik ser en normal hardet build ut. | Setuid-biten. **En hardet SUID-binærfil er fortsatt en SUID-binærfil.** Hvis noen nåbar minnesikkerhetsfeil overlever, er det fortsatt «feil i en root-prosess». |

Konsollbeviset er `make test-hardened`, som bytter den hardnede builden inn og
viser alle teknikkene dø ved canaryen, mens `foosd_hardened.log` fanger
`*** stack smashing detected ***`.

To mottiltak på designnivå som ingen kompilator-flag leverer, og som
hovedlaboratoriet (`food`) også bruker:

- **Minste privilegium.** En daemon for en uprivilegert port (2343 > 1024) har
  intet legitimt behov for root. En korrekt `foosd` ville binde og deretter
  `setgroups`/`setgid`/`setuid` til en uprivilegert konto og *bekrefte at det
  holdt* (den korrekte versjonen står i kilden som `drop_privs()`, aldri kalt —
  ikke-kallingen er laboratoriets feil nr. 3).
- **Begrens read-et.** `n = read(fd, buf, sizeof(buf) - 1)`. Én korrekt linje
  overgår hvert kompilator-flag i tabellen.

---

## 9. Wire-protokollen (så du kan lese daemonen med netcat)

```text
FOOSD 1.0 - deliberately vulnerable SUID service
Type 'quit' to disconnect. Buffer = 64 bytes, read accepts 512.
FOOSD 1.0 ids=0/1000 leak stack=0x7ffd... libc=0x7f...
BUF=0x7ffd...
```

* `ids=euid/ruid` — kunne ikke skrives ut som `euid=`/`ruid=`, fordi
  test-harnessen beviser en shell ved å greppe etter det bokstavelige `uid=`, og
  banneret må ikke inneholde det (en sonde som deler signatur med svaret, er en
  klassisk falsk-positiv-felle; se kommentaren i `foosd.c`). Harnessen krever
  dessuten den strenge `id`-utdataformen — `uid=NNN(...)` — så ingenting
  daemonen eller exploitet skriver ut kan oppfylle sjekken ved en tilfeldighet:
  `foosc`s eget «target euid=… ruid=…» inneholder `uid=` som delstreng, noe som
  en gang fikk en hardnet test til å melde en shell som aldri hadde kjørt.
* `stack=`, `libc=`, `BUF=` — ASLR-leaksene: lar shellcode og ret2libc beregne
  eksakte adresser.

---

## 10. Øvelser

1. **Betrakt ikke-root-nedgraderingen.** Kjør `make test` *før* `make setuid`,
   og deretter igjen etterpå. Forklar `ROOT=SEEN`-endringen med
   ruid/euid-historien i §5.2.
2. **Les krasjet.** Kjør `./foosc -t demo -n` og les deretter `foosd.log`.
   Linjen `RIP=0x4141414141414141` er angriperens padding — beviset på at
   overløpet, ikke uhell, kontrollerer utførelsen.
3. **Legg til canaryen.** `make hardened` og endre selv `test-hardened`-løkken;
   logglinjen `*** stack smashing detected ***` er forsvaret som virker.
4. **Deaktiver leaket.** Kommentér `BUF=`-linjen i `foosd.c` ut, bygg om, og se
   `-t shellcode` gå fra deterministisk til et gjettespill. Den ene linjen er
   grunnen til at ekte ASLR-bypasser er et helt felt.
5. **`-p`-eksperimentet.** Endre i en kopi av `win()` `execl("/bin/sh", "sh",
   NULL)` til `execl("/bin/sh", "sh", "-p", NULL)` og observer root. `-p` er
   den dokumenterte nødutgangen fra shellens vakt — og grunnen til at rådet
   «spawn bare en shell» fra gamle write-ups er ufullstendig.
6. **Hvorfor ikke `setuid(0)`?** Omskriv shellcoden til å kalle `setuid(0)`
   i stedet for `setreuid(0,0)` (syscall 105). Shellen lander fortsatt — og
   faller fortsatt til `uid=1000`. Det er det mest lærerike
   én-linjes-eksperimentet i hele repositoriet.

---

## 11. Sikkerhet og opprydding

- Bare loopback, som standard og etter design; `-L` binder lenger, og bare en
  egnet-til-å-kastes VM bør i det hele tatt vurdere det.
- Dette er et root-shell-laboratorium. Ikke kjør det på en maskin som betyr
  noe, og pek ikke `foosc -h` mot noe du ikke eier.
- Oppryddingsritual: `make stop` og deretter `make unsetuid`, og hvis du vil ha
  treet plettfritt igjen: `sudo make clean`.

```console
$ make stop
$ make unsetuid
```