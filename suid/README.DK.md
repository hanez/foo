# SUID-root-RCE-laboratorium — `foosd` (daemon) + `foosc` (exploit)

En ledsager til det overordnede laboratorium (`food` / `fooc`, en almindelig
daemon, hvor et bufferoverløb giver dig en *bruger*-shell). Dette tilføjer den
farligste en-tegns-ændring i Unix: **setuid-bitten**.

> `chmod u+s` forvandler "angriberen kan køre kode på denne host" til
> "angriberen kan køre kode som **root** på denne host".

Den sætning er hele laboratoriet. Alt herunder er mekanismen under den, skrevet
ned, så du, når du skriver din egen software, præcist ved, hvilke to eller tre
filsystem-attributter og compiler-flag der afgør, om en
hukommelsessikkerhedsfejl i din kode er en gene eller en root-shell.

Den endelige demo, når `foosd` er setuid-root, er en **root-shell**, der åbnes
over netværket ved at udføre 32 bytes håndskrevet shellcode.

---

## 1. Hvad setuid-bitten rent faktisk gør

Hver proces på Linux bærer tre user-ID'er, og setuid-bitten piller ved
forholdet mellem dem:

| ID | Navn | Betydning |
|----|------|---------|
| `ruid` | reelle user-ID | kontoen, der *startede* processen |
| `euid` | effektive user-ID | det, kernen tjekker, når den håndhæver adgang |
| (saved) | gemte set-user-ID | en "slot", en privilegeret proces må vende tilbage til senere |

Et normalt program har `ruid == euid`. Når du udfører en binærfil med
setuid-bitten sat, ejet af root:

```text
ruid = dig        (fx. 1000, "hanez")
euid = ejeren     (fx. 0, "root")
```

Processen har derfor **roots autoritet**, selvom brugeren, der startede den, er
helt almindelig. Hvert tjek, kernen udfører — kan denne proces læse
`/etc/shadow`? skrive en fil? dræbe en anden proces? — besvares med `euid`,
dvs. "ja, den er root".

`foosd` er en netværksdaemon. Den binder en port og `fork()`er derefter et barn
per forbindelse. En fork *arver* euid'en, så hvert barn, der håndterer en
forbindelse, også er root. Overløbet i `foosd`s `vulnerable_handler()` er
derfor et overløb *inde i en root-proces*.

**Diagnosticér det selv, når daemonen kører:**

```console
$ ./foosd ...            # se den loglinje, den printer ved start
[foosd 1234] startup: ruid=1000 euid=0 -> ROOT process
```

og fra exploitet:

```console
$ ./foosc -t leak
foosc: target euid=0 ruid=1000
```

---

## 2. Laboratoriet ved et øjekast

| Fil | Rolle |
|------|------|
| `foosd.c` | Den bevidst sårbare daemon (ejer fejlene). Kør som *setuid-root*-binærfil til root-shell-demoen. |
| `foosc.c` | Exploitet. Bruger som standard den 32-byte `setreuid + execve`-shellcode-teknik. |
| `shellcode.S` | Reference-shellcoden; `make verify` diff'er den mod byte-arrayet i `foosc.c`. |
| `tests/pty_suid_test.c` | Test-harness. Driver `foosc` gennem et pseudo-terminal og beviser både "en shell kørte" *og* "den var root" (`uid=0(`). |
| `Makefile` | Build, `setuid`/`unsetuid`-hjælpere, testmatrix. |
| `README.md` | Denne fil. |

> **Hvorfor en pty?** Exploitets sidste handling er at videresende din terminal
> til shellen, der udfører på offeret. En pipe eller her-doc lander i den
> forkerte ende af den videresendelse; en ægte terminal er påkrævet.

---

## 3. Hurtig start

```console
$ make                       # byg alt, som din normale bruger
$ make setuid                # én gang, spørger om sudo: chown root + chmod u+s
$ make run                   # start foosd på 127.0.0.1:2343
$ make test-suid             # fuld matrix; shellcode + ret2win-root skal give root
```

Interaktiv rygeprøve:

```console
$ ./foosc -t shellcode
...
foosc: target euid=0 ruid=1000
foosc: shell is on the victim (root if foosd is SUID); relaying
# id
uid=0(root) gid=0(root) groups=0(root)      <-- du er root, på offeret
# exit
```

Når du er færdig:

```console
$ make stop
$ make unsetuid             # hygiejne: efterlad aldrig en root-SUID-binærfil
```

---

## 4. *Hvornår skal jeg sætte SUID-bitten?* — svaret, du bad om

Præcis **én gang, efter bygningen, før du starter daemonen til
root-shell-demoerne** — og kun på en maskine, der er din, velegnet til at smide
væk og frakoblet netværket:

```console
$ make            # kompilér foosd, foosc, tests
$ make setuid     # <-- ØJEBLIKKET. sudo chown root:root foosd && sudo chmod u+s foosd
$ make run        # start EFTER at have sat bitten
```

To regler, der betyder mere end det præcise tidspunkt:

1. **Sæt den kun, når binærfilen er færdig.** Hvis du genbygger (`make` /
   `make clean`), efter du har sat bitten, rammer du et "Permission denied",
   når du skriver root-ejede outputfiler — og hvis du tvinger genbygningen,
   genskaber værktøjskæden filen **uden** `s`-en og fortryder stille og roligt
   opsætningen. Den kanoniske rækkefølge ved enhver genbygning er derfor

   ```console
   $ make unsetuid && make && make setuid
   ```

2. **Fjern den, når du er færdig.** `make unsetuid`. En levende,
   root-ejet setuid-binærfil med en udnyttelig fejl i dit træ er ikke et
   læremiddel, det er et root-hul med en kompileringsfejl mellem sig og
   ingenting. På en delt eller produktionsmaskine: **lav ikke noget af
   dette.** Daemonen nægter desuden som standard at binde andet end loopback
   (se §7).

Hvis du kører exploitet *uden* nogensinde at sætte bitten, går intet i stykker
— payloaden lander stadig, og du får stadig en shell. Forskellen er i ét tal,
og exploitet siger det højt:

```console
foosc: WARNING: the daemon is NOT running with euid 0.
       The payload will still land, but the shell will be
       a plain user shell, not root.
       Fix:  sudo make setuid
```

Det "virker, men ikke root"-resultat er selv en del af laboratoriet. Husk det
til næste afsnit.

---

## 5. Mekanismen — og drejningen, der gør SUID interessant

### 5.1 Overløbet (identisk med `food`)

`foosd`s handler giver et `read()` 512 bytes tillid, mens den rækker den et
64-byte stack-buffer:

```c
char buf[64];
n = read(fd, buf, 512);        /* <- CWE-120: 448 bytes over kanten */
```

På x86-64 vokser stacken nedad. Exploitet skriver 64 bytes junk for at fylde
`buf`, 8 for at fylde den gemte framepointer og 8 mere for at erstatte den
**gemte returadresse**. Når `vulnerable_handler` udfører `ret`, popper CPU'en
angriberens værdi ind i `RIP` — angriberkontrolleret kodeudførelse. Exploitet
finder den præcise afstand (88 bytes for denne build) ved at parse
`objdump`-output i stedet for at hardkode det, så tallet overlever genbygninger.

### 5.2 Drejningen: shellen nægter at være root

Her er det, hvor at tænke "SUID-fejl → spawn /bin/sh → root" ville gå galt, og
hvorfor dette laboratorium har præcis den form, det har.

Når et setuid-root-program kører, er dets `ruid` stadig den startende bruger,
og dets `euid` er root. Hvis programmet — eller angriberen — nu starter en
shell:

* `execve("/bin/sh")` ændrer **ikke** uiderne; den nye proces arver
  `(ruid=1000, euid=0)`.
* bash (og dash) **tjekker præcis den tilstand ved start**. Fra bash-manualen:
  *"If the shell is started with the effective user (group) id not equal to
  the real user (group) id, and the -p option is not supplied, … the effective
  user id is set to the real user id."*

Så shellen kigger på sig selv og *dropper root* — et forsvar, som
shell-forfatterne byggede præcis mod dette angreb (den historiske begrundelse
var setuid-shell-/setuid-script-problemet). Resultatet er "virker, men ikke
root"-tilfældene:

| Teknik | Hvad den udfører | Resulterende uid |
|-----------|------------------|---------------|
| `ret2win` | `foosd`s `win()` → `execl("/bin/sh")` | **1000** — shell landede, root nulstillet af bash |
| `ret2libc` | `system("/bin/sh")` → frisk `sh -c '/bin/sh'` | **1000** — samme nulstilling, et niveau nede |
| `ret2win-root` | `foosd`s `win_root()` → `setreuid(0,0); execl("/bin/sh")` | **0** — ruid ryddet fra C |
| `shellcode` | 32 bytes: `setreuid(0,0); execve("/bin/sh")` | **0** — ruid ryddet fra maskinkode |

De to, der når root, adskiller sig fra de to, der ikke gør, med præcis én idé:
**de rydder den *reelle* uid, ikke kun den effektive.**

```c
setuid(0)          /* sætter euid til 0, men ruid forbliver 1000:
                      bash ser stadig euid != ruid og nulstiller STADIG.  */
setreuid(0, 0)     /* sætter BEGGE: ruid = euid = 0.
                      bash ser lige uider og beholder root.              */
```

Det er derfor, den klassiske `/bin/sh`-shellcode, du finder overalt på
internettet, starter med et uid-ryddende syscall — og det er grunden til, at
shellcoden her er 32 bytes i stedet for 23: de første fem instruktioner er

```asm
xor    edi, edi      ; ruid = 0
xor    esi, esi      ; euid = 0
push   0x71          ; 113 = __NR_setreuid
pop    rax
syscall
```

### 5.3 Så hvad er exploitet, ende til ende?

1. `foosc` læser `foosd`s banner over socket'en. Det får:
   - `ids=0/1000` — euid/ruid (SUID-selvdiagnosen)
   - `stack=…` og `libc=…` — pointers (ASLR-leaksene)
   - `BUF=…` — den nøjagtige adresse på det buffer, den er ved at løbe over
2. Fra target-binærfilen (via `objdump`) lærer det `rip_off` og adresserne på
   `win()` / `win_root()`.
3. Fra *sin egen* libc (via `/proc/self/maps` + `dlsym` + et hukommelsesscan)
   måler det offsets for `system`, `read`, `/bin/sh` og et
   `pop rdi; ret`-gadget — intet er hardkodet.
4. Det samler payloaden. For `-t shellcode` er det:
   `[32-byte-setreuid+execve-kode][padding til RIP][ret-fix][adresse på buf]`.
5. `foosd`s `read()` løber over; `ret` lander på shellcoden; kernen udfører
   `setreuid(0,0)` (fint: euid 0 er privilegeret) og derefter `execve` af
   `/bin/sh`. bash starter med `ruid == euid == 0` og forbliver root.
6. `foosc` videresender din terminal til den root-shell, indtil du skriver
   `exit`.

Én bekvemmelighedsdetalje, der koster folk meget tid, hvis den overses:
exploitet tester hver uid-ryddende adfærd **uden** først at have brug for
setuid-bitten. Kør `make test` før `make setuid`, og du vil se hver teknik
lande en shell, mens `ROOT=MISSING` står; kør `make test-suid` efter `make
setuid`, og `ROOT=SEEN` dukker op ved de to teknikker, der rydder den reelle
uid. Det A/B er hele lektionen, udførligt på ti sekunder.

---

## 6. De gamle one-liners — og hvorfor de fleste af dem er døde

Har du læst om SUID, har du læst om `PATH`-kapring, `LD_PRELOAD` og
setuid-shells. Alle tre er klassiske, og alle tre fejler på et moderne system
mod *dette program*. Det er værd at vide præcis hvorfor, fordi grundene er de
forsvar, du får gratis:

| Angrebsklasse | Gamle påstand | Hvorfor den fejler på en moderne maskine |
|--------------|-----------|------------------------------|
| `LD_PRELOAD` af et ondsindet bibliotek | "Setuid-programmet loader min `.so` og kører min kode som root." | Kernen markerer en setuid-binærfil som **AT_SECURE**; glibc ignorerer derefter `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_DEBUG` og venner. Miljøet behandles som *utroverdig input*. `LD_PRELOAD` mod en setuid-binærfil er en no-op. |
| `PATH`-kapring (`system("ls")` med en forgiftet PATH) | "Peg PATH mod et bibliotek med min falske `ls`; root-programmet kører den." | Et andet ansigt af samme forsvar: en AT_SECURE-proces får en **saneret `PATH`** (en sikker standard, nogenlunde `/usr/local/bin:/usr/bin:/bin`) til `system()`/`execvp`, så det forgiftede bibliotek aldrig konsulteres. |
| Setuid-`system()`-kommandoinjektion | "Den injicerede kommando kører med euid 0." | `system()` kører kommandoen i en frisk `/bin/sh`, og den shell — §5.2 — nulstiller `euid = ruid` ved start. Den injicerede kommando udføres med den *reelle* uid. (Det er stadig en fejl; den eskalerer bare ikke længere gennem `/bin/sh`.) |
| Setuid-root-shell på disken (`cp /bin/sh /tmp; chmod u+s`) | "Kør den, få root." | Præcis forsvaret ovenfor, og det er grunden til, at moderne distroer ikke leverer nogen setuid-root-shell. Selv når det lykkes at lave én, nægter bash at beholde euid 0, medmindre den startes med `-p`. |

Hvad der forbliver i live, og det er dette laboratorium: **programmet er
*allerede* root, når det kører.** Du behøver ikke miljøet eller `system()`; du
har brug for, at programmet udfører *din* kode (via en
hukommelseskorruptionsfejl), mens det er privilegeret, og din kode skal være
omhyggelig nok til selv at rette uid-mismatchet — `setreuid(0,0)` — før den
overrækker dig en shell. Hukommelseskorruption + SUID er kombinationen, der
stadig ender i `uid=0`, hvilket er præcis hvorfor hukommelsessikre sprog,
canaries og no-execute-stacks ikke er en modebeslutning.

---

## 7. De sikkerhedsgelændere, der er bygget ind i daemonen

`foosd` er bevidst det *dårligste* stykke software i dette repository, så det
bærer også flest gelændere:

1. **Kun loopback, håndhævet.** `foosd` nægter enhver bind-adresse ud over
   loopback, medmindre du giver `-L`. En setuid-root-listener på en rigtig
   grænseflade er en fjern root-tjeneste; afslaget er standarden, så den
   farlige tilstand skal skrives bevidst ind.
2. **Selvdiagnose.** Ved start logger den `ruid`/`euid` og om den kører som
   root, så konsollen viser den tilstand, exploitet afhænger af.
3. **Loggen når aldrig klienten.** Daemonen reserverer en privat
   log-descriptor, før sockets erstatter fd 1, så crash-reporter-output og
   interne stier ikke kan læses tilbage over ledningen af angriberen.
4. **Crash-reporter.** En SIGSEGV-handler logger `RIP`/`RSP` — den værdi,
   angriberen skrev ind i returadressen — så en vellykket kapring er synlig i
   `foosd.log` i stedet for at være en stille død.
5. **`make unsetuid`.** Fjernelse af bitten er scriptet, fordi at efterlade den
   sat er den fiaskotilstand, folk rent faktisk har.

---

## 8. Modforanstaltninger — hvad hver stopper, og hvad den *ikke* stopper

Anvendt på `foosd` via `make hardened`, én ad gangen eller sammen:

| Modforanstaltning | Hvad den stopper | Hvad den *ikke* stopper |
|------------|---------------|-------------------------|
| `-fstack-protector-strong` (canary) | Overløbet: `ret` opdager en smadret canary og abort'er, før angriberens adresse bruges. Stopper her **alle fire** teknikker — de deler det ene sårbare `read()`. | Intet ved *designet*: binærfilen er stadig setuid-root; en anden fejl (format-string-`%n`, heap-overflow, use-after-free) har ingen canary at udløse. |
| `-fPIE -pie` (ASLR for binærfilen) | Brug af forudsigelige `win()`/`win_root()`-adresser (ret2win-teknikkerne). | Shellcode-teknikken, hvis en stack-adresse stadig lækker (`BUF=`-linjen). |
| `-z noexecstack` (NX / W^X) | Shellcoden: CPU'en nægter at hente instruktioner fra en data-only-side, så et hop til `buf` er et SIGSEGV. | ROP — at køre kode, der allerede findes (`ret2libc`). |
| Alle tre sammen | En svær-at-overløbe, randomiseret binærfil med ikke-eksekverbar stack. Sådan ser en normal hærdet build ud. | Setuid-bitten. **En hærdet SUID-binærfil er stadig en SUID-binærfil.** Hvis nogen nåbar hukommelsessikkerhedsfejl overlever, er det stadig "fejl i en root-proces". |

Konsolbeviset er `make test-hardened`, som bytter den hærdede build ind og viser
alle teknikker dø ved canaryen, mens `foosd_hardened.log` optager
`*** stack smashing detected ***`.

To designniveau-modforanstaltninger, som intet compiler-flag leverer, og som det
overordnede laboratorium (`food`) også bruger:

- **Least privilege.** En daemon til en uprivilegeret port (2343 > 1024) har
  intet legitimt behov for root. En korrekt `foosd` ville binde og derefter
  `setgroups`/`setgid`/`setuid` til en uprivilegeret konto og *bekræfte, at det
  holdt* (den korrekte version står i kilden som `drop_privs()`, aldrig kaldt —
  ikke-kaldelsen er laboratoriets fejl nr. 3).
- **Begræns read'et.** `n = read(fd, buf, sizeof(buf) - 1)`. Én korrekt linje
  overgår hvert compiler-flag i tabellen.

---

## 9. Wire-protokollen (så du kan læse daemonen med netcat)

```text
FOOSD 1.0 - deliberately vulnerable SUID service
Type 'quit' to disconnect. Buffer = 64 bytes, read accepts 512.
FOOSD 1.0 ids=0/1000 leak stack=0x7ffd... libc=0x7f...
BUF=0x7ffd...
```

* `ids=euid/ruid` — kunne ikke printes som `euid=`/`ruid=`, fordi test-harnessen
  beviser en shell ved at greppe efter det bogstavelige `uid=`, og banneret må
  ikke indeholde det (en sonde, der deler signatur med svaret, er en klassisk
  falsk-positiv-fælde; se kommentaren i `foosd.c`). Harnessen kræver desuden
  den strenge `id`-outputform — `uid=NNN(...)` — så intet, daemonen eller
  exploitet printer, kan opfylde tjekket ved et tilfælde: `foosc`s eget
  "target euid=… ruid=…" indeholder `uid=` som delstreng, hvilket engang fik en
  hærdet test til at melde en shell, der aldrig havde kørt.
* `stack=`, `libc=`, `BUF=` — ASLR-leaksene: lader shellcode og ret2libc
  beregne eksakte adresser.

---

## 10. Øvelser

1. **Betragt ikke-root-nedgraderingen.** Kør `make test` *før* `make setuid`,
   og derefter igen bagefter. Forklar `ROOT=SEEN`-ændringen med
   ruid/euid-historien i §5.2.
2. **Læs nedbruddet.** Kør `./foosc -t demo -n` og læs derefter `foosd.log`.
   Linjen `RIP=0x4141414141414141` er angriberens padding — beviset på, at
   overløbet, ikke uheld, kontrollerer udførelsen.
3. **Tilføj canaryen.** `make hardened` og ændr selv `test-hardened`-løkken;
   loglinjen `*** stack smashing detected ***` er forsvaret, der virker.
4. **Deaktiver leaket.** Kommentér `BUF=`-linjen i `foosd.c` ud, genbyg, og se
   `-t shellcode` gå fra deterministisk til et gættespil. Den ene linje er
   grunden til, at ægte ASLR-bypasses er et helt felt.
5. **`-p`-eksperimentet.** Ændr i en kopi af `win()` `execl("/bin/sh", "sh",
   NULL)` til `execl("/bin/sh", "sh", "-p", NULL)` og observer root. `-p` er
   den dokumenterede nødudgang fra shellens vagt — og grunden til, at rådet
   "spawn bare en shell" fra gamle write-ups er ufuldstændigt.
6. **Hvorfor ikke `setuid(0)`?** Omskriv shellcoden til at kalde `setuid(0)`
   i stedet for `setreuid(0,0)` (syscall 105). Shellen lander stadig — og
   falder stadig til `uid=1000`. Det er det mest lærerige en-linjes-eksperiment
   i hele repositoryet.

---

## 11. Sikkerhed og oprydning

- Kun loopback, som standard og efter design; `-L` binder længere, og kun en
  velegnet-til-at-smid-væk-VM bør overhovedet overveje det.
- Dette er et root-shell-laboratorium. Kør det ikke på en maskine, der
  betyder noget, og peg ikke `foosc -h` mod noget, du ikke ejer.
- Oprydningsritual: `make stop` og derefter `make unsetuid`, og hvis du vil
  have træet pletfrit igen: `sudo make clean`.

```console
$ make stop
$ make unsetuid
```