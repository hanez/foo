# `wosuid`-laboratoriet — root-RCE **uten** setuid-bit

```
  foowosd   en bevisst sårbar daemon som er root fordi den ble *STARTET* som
            root  (port 2344, bare loopback som standard)
  foowosc   exploitet: forvandler et stack-overløp til en **root**-shell ved å
            utføre shellcode — de samme 23 bytene som knekte user-level-
            `food`-daemonen i hovedlaboratoriet
```

Det er det tredje laboratoriet i serien. Samme exploit-verktøykjede, samme
stil, én fundamental forskjell:

| Laboratorium | hvordan målprosessen blir root              | `uid=0(root)`-shell? |
|----------|------------------------------------------------|----------------------|
| food/fooc| aldri — det er en vanlig user-daemon       | nei                   |
| foosd/foosc | SUID-biten (`chmod u+s`) — euid 0, ruid 1000 | ja (krever `setreuid` i shellcoden, fordi bash nullstiller euid→ruid) |
| **foowosd/foowosc** | **ingen — root *starter* daemonen** (sudo / systemd `User=root`) | **ja (vanlig `execve`-shellcode)** |

Setuid-biten er et *transportmiddel* for privilegier — ikke privilegiene selv.
En daemon startet av root har reell, effektiv og lagret uid alle lik 0. For
kjernen er det root, punktum; den kan og vil ikke vite om prosessen kom dit via
`+s` på en fil eller via `sudo ./foowosd`. Overløpet i en root-startet daemon er
altså et root-exploit — *«jeg har ingen SUID-binærfiler» er ikke det samme som
«jeg er ikke utnyttbar».*

Det er hele leksjonen i dette laboratoriet. Alt nedenfor er maskineriet.

---

## Rask start (det brukeren ba om)

```
cd wosuid
make                 # bygger daemonen, exploitet og test-harnessen
```

### Det ekte — kjør daemonen som **root**

```
sudo make run-root      # starter foowosd som uid 0 (prosess, ikke filtillstand)
make test-root          # hver teknikk skal nå gi uid=0(root)
```

### Ikke sudo? Den identiske kjernesti via en user-namespace

```
make run-root-ns        # uid 0 i en user-namespace — ingen passord nødvendig
make test-root          # samme dommer; brukes av CI og alle uten sudo
```

### Baseline — daemon som din vanlige bruker (intet root noen steder)

```
make run                # foowosd kjører med dine uid-er
make test               # exploits lander shells, men `root` forventes MISSING
```

### Oppryddingsritual (alltid: dette er et root-shell-laboratorium)

```
make stop
```

`foowosd` er *ikke* setuid, og intet i dette biblioteket gjør noen gang
`chmod +s` — det er poenget. Den farlige tilstanden er **prosessen**, ikke
filen.

---

## Når du blir bedt om å sette SUID-biten

Det blir du **ikke**. Dette laboratoriet har bevisst ingen SUID-bit:

- `foowosd` bygges, eies og har vanlige tillstander som ethvert annet program.
- Det blir root, som ekte daemoner gjør — ved å bli *startet* av root.
- `make run-root` bruker `sudo` til nøyaktig det, og `make run-root-ns` skaffer
  en ekte uid-0-prosess helt uten noe av det.

Suid-biten tilhører *søster*-laboratoriet (`foosd`). Kontrasten mellom de to
er pensum:

1. SUID-laboratoriet: biten gir **euid 0, men ruid 1000** →
   `execve("/bin/sh")` nedgraderes av bashs vakt (`euid != ruid` → reset) →
   shellcoden må først kalle `setreuid(0,0)` (32-byte-payload).
2. Dette laboratoriet: root **starter** prosessen → **ruid == euid == 0** →
   vakten har ingenting å nullstille → den vanlige 23-byte `execve`-shellcoden
   beholder root.

Samme overløp. Samme teknikk. Forskjellig *opprinnelse* av privilegier,
annerledes payload-form. Det er leksjonen i miniatyr.

---

## Protokollen

Uansett hvilken slags klient som kobler til, hilser foowosd på den med:

```
FOOWOSD 1.0 ids=0/0 leak stack=0x7ffd… libc=0x7f…      (banneret + leaks)
BUF=0x7ffd…                                             (bufferadressen)
```

`ids=euid/ruid` er *«er jeg root?»*-sidekanalen. foowosc skriver ut en høy
advarsel når euid ikke er 0 (dvs. du startet daemonen som en vanlig bruker):
payloaden lander fortsatt, men shellen blir en bruker-shell, og å kalle
exploitet «i stykker» ville vært feil — det eskalerer bare ikke.

> Staveform-merknad: `ids=`, ikke `euid=`/`ruid=`. Test-harnessen beviser en
> levende `id` ved å matche den bokstavelige formen `uid=NNN(`, så banneret må
> aldri inneholde en delstreng som selv oppfyller sjekken. (I SUID-laboratoriet
> produserte nøyaktig den fellen et spektakulært falskt positivt.)

---

## Exploit-teknikkene (`foowosc -t …`)

Alle fire exploit-stiene nedenfor virker mot foowosd. Når daemonen er root,
gir **alle som spawner noe, root** — i motsetning til SUID-laboratoriet der
ret2win/ret2libc stille og rolig ble nedgradert til uid 1000 av bashs vakt. Her
er det intet mismatch å vokte mot.

| `-t`          | hva som skjer                                                       | når daemonen er root |
|---------------|---------------------------------------------------------------------|---------------------|
| `shellcode`   | 23-byte-`execve("/bin/sh", NULL, NULL)` kjører på stacken.           | **root-shell** (standard) |
| `ret2win`     | hopp til `win()` → `execl("/bin/sh")`                                | **root-shell** |
| `ret2libc`    | ROP: `pop rdi; ret` → `"/bin/sh"` → `system()`                      | **root-shell** |
| `demo`        | bare søppel-overløp — forvent et SIGSEGV i daemonloggen               | krasj, etter design |
| `leak`        | skriver bare ut leaks, sender ingen payload                            | n/a |

```
./foowosc -t shellcode       # interaktiv; standard-target 127.0.0.1:2344
./foowosc -t shellcode -n    # send og rapporter, ingen interaktiv økt
```

En vellykket interaktiv økt videresender terminalen din til shellen *på
offeret* — det er nøyaktig én shell i bildet, og det er `/bin/sh` som kjører
som root inne i foowosd. Skriv `id` for å se `uid=0(root)`.

### Hvorfor det ikke finnes noen `ret2win-root`-teknikk her

foosc hadde én — den hoppet til et `win_root()` som kalte `setreuid(0,0)` før
exec, fordi en setuid-prosess kjørte med en reell uid som fortsatt sa 1000. En
root-*startet* prosess har den reelle uid-en allerede 0; det er ingenting å
rydde, så den ekstra funksjonen og teknikken ville ikke lært noe. Fjernet.

---

## Hva foowosc gjør, steg for steg

1. **Statisk analyse** — `objdump -d` av `./foowosd`. Finner
   `vulnerable_handler`, `win()`, det `lea -0x50(%rbp)` som adresserer `buf`,
   og det første nakne `ret`. Ut fra forskyvningen beregner det
   `rip_off = 80 + 8 = 88`. Ingenting er hardkodet; det overlever en ombygging.
2. **Selv-introspeksjon** — leser sitt eget `/proc/self/maps` og `dlsym()`er
   `system`/`read` for å lære libc-*offsets*. Targetets libc-base er
   `leaked_read − off_read`, deretter `system = base + off_system`, osv. Denne
   delta-aritmetikken er grunnen til at exploits overlever libc-versjoner.
3. **Koble til** — leser banneret/leaks (`ids=`, `stack=`, `libc=`, `BUF=`).
4. **Bygg payloaden** — for `shellcode`: 23 bytes maskinkode, padding til
   `rip_off`, deretter den lagrede RIP = `buf` (så `ret` hopper inn på koden).
   For `ret2win`/`ret2libc`: adresser beregnet ut fra analysen — ingen
   utførelse av stacken nødvendig.
5. **Justeringsfixen** — et kapret nakent `ret` gir callee-en
   `rsp ≡ 8 (mod 16)`, og glibcs SSE2-kode `movaps`-feiler på en ikke-justert
   stack (crash-reporteren logger `si_addr=(nil)` — fingerpeket). foowosc
   setter inn ett ekstra `ret`-gadget før det ekte målet og gjenoppretter
   invarianten. Silkehansketeknikk i et shellcode-laboratorium, men det er
   forskjellen mellom en payload som «noen ganger virker» og en som alltid
   virker.
6. **Send, deretter videresend** — offerprosessen *er* shellen; denne prosessen
   splisser bare bytes. Ingen lokal shell, ingen annen leser —
   single-read-cursor-feilen (ett spist byte per chunk) er dokumentert i
   `become_shell()`.

---

## Daemonens bevisste feil (alle i `foowosd.c`, alle ekte CWE-klasser)

| # | feil | CWE | notat |
|---|-----|-----|------|
| 1 | `read(fd, buf, 512)` inn i et 64-byte stack-buffer | [CWE-120](https://cwe.mitre.org/data/definitions/120.html) | overløpet: 448 bytes forbi `buf`, lagret RIP ved +88 |
| 2 | bare `snprintf(line, …, "%.*s", …)`; men angriper-`%` i ekko-stien | [CWE-134](https://cwe.mitre.org/data/definitions/134.html) | leaket er her den reelle payloaden; et `%n` i en *root*-prosess ville vært write-what-where som root |
| 3 | barn beholder root mens de håndterer upålitelige inputs | [CWE-271](https://cwe.mitre.org/data/definitions/271.html) | det korrekte `drop_privs()` (setgroups→setgid→setuid, i den rekkefølgen, med verifikasjon) står i filen, kommentert, *bevisst aldri kalt* |
| 4 | `ids=`, `stack=`, `libc=`, `BUF=` avslørt til enhver klient | [CWE-120](https://cwe.mitre.org/data/definitions/120.html) | uten disse leaks kunne ikke shellcode- og ret2libc-teknikkene beregne adresser (ASLR ville beseiret dem) |

Handleren har nøyaktig samme `buf[64]`/`read(512)`-form som de to andre
laboratoriene, så den felles objdump-baserte oppdagelsespipelinen virker
uendret.

---

## Slik inspiserer du daemonen (læringssti)

```
make status            # kjører den? som hvilken uid? filtillstand vises
make run-root          # eller run / run-root-ns
./foowosc -t leak      # se banneret og leaks, send ingenting
./foowosc -t demo      # søppel-overløp -> SIGSEGV, logget med RIP/rsp
./foowosc -t shellcode # den interaktive root-shellen
make test-root         # full matrise, alle teknikkene, --must-root
```

Crash-reporter: Ved SIGSEGV logger daemonen feiladressen, RIP og RSP. Et `ret`
inn i en ikke-kanonisk `0x4141…` feiler ved `ret`-et selv (RIP som `0x4028xx`,
`si_addr=(nil)`) — verdt å vite før du feilleser en logglinje som en
NULL-dereferanse.

---

## Hvorfor shellcoden er 23 bytes, ikke 32

```
31 f6        xor esi, esi            ; argv = NULL
31 d2        xor edx, edx            ; envp = NULL
48 bf 2f62696e2f736800 movabs rdi, "/bin/sh\\0"
57           push rdi
48 89 e7     mov rdi, rsp
6a 3b        push 0x3b               ; 59 = execve
58           pop rax
0f 05        syscall
```

SUID-laboratoriet trenger `setreuid(0,0)` foran dette. Dette laboratoriet ikke,
av den grunnen som gjentas overalt: **ruid er allerede 0**, fordi root startet
prosessen. `make verify` beviser at bytene i `foowosc.c` er byte-for-byte det
`shellcode.S` assemblerer til.

---

## Mottiltak — hva `make hardened` endrer

Hardet build (`-fstack-protector-strong -fPIE -pie -z noexecstack`):

| teknikk | sårbar `foowosd` | hardet `foowosd_hardened` |
|-----------|----------------------|------------------------------|
| `shellcode` | root-shell (kjørbar stack) | SIGSEGV ved canary-sjekken / NX |
| `ret2win` / `ret2libc` | root-shell | canary aborter `ret` — men merk: en *PIE*-build gjør også disse adressene tilfeldige |
| `demo` | SIGSEGV, logget | SIGSEGV, logget |

`make test-hardened` demonstrerer det live. Den viktige observasjonen er ikke
bare at mottiltakene drepte teknikkene — det er at de **ikke** gjorde daemonen
til «ikke-root». En hardet build som fortsatt *startes* som root, er fortsatt en
root-daemon; mottiltaket hever bare lista for angriperen. Minste privilegium
(`drop_privs()`) og minnesikkerhet er to forskjellige feil, og en daemon som
ikke trenger root, bør ikke ha det.

---

## Sikkerhetsgelendere (samme politikk som SUID-laboratoriet)

- **Bare loopback.** foowosd nekter å binde noe annet enn `127.0.0.1` /
  `localhost` / `::1`, med mindre du gir `-L`. En root-daemon på et ekte
  grensesnitt er en *fjern* root-tjeneste. `-L` finnes bare for å vise vakten;
  ikke bruk den på noe som betyr noe.
- **Tilstanden logges høyt.** Ved start skriver den ut `ruid/euid` og om dette
  er en root-prosess, så du alltid vet hvilket exploit-resultat du skal vente.
- **Dommer kommer fra exit-status** i `make test*` (pty-harnessens
  returkode), aldri fra å greppe stdout-en dens — grepbar utdata lyver.
- **pty-en må kjøre cooked + ECHO off**, ellers ekkoer harnessen sin egen
  kommandolinje og forfalsker markøren. Harnessen slår av ECHO og beholder
  ECHONL på.
- **Oppryddingsritual:** `make stop` etter hver økt. Hvis daemonen er
  root-eid, sier `stop` deg å kjøre `sudo pkill -x foowosd`.
- Kjør aldri dette på en vert du bryr deg om. Det finnes for å dele ut
  `uid=0`-shells over loopback-grensesnittet.

---

## Øvelser

1. Kjør `make run` (user-daemon), deretter `./foowosc -t shellcode`. Hvorfor er
   shellen ikke root? (Sjekk `ids=` i banneret — foowosc sier deg det før du i
   det hele tatt kobler til.)
2. `make stop && sudo make run-root && make test-root`. Forklar ut fra
   bannerlinjen hvorfor alle fire teknikkene nå gir `uid=0(root)`.
3. Finn i `foowosd.c` `drop_privs()` og les *hvorfor rekkefølgen* av
   `setgroups → setgid → setuid` betyr noe. Bestem hvor i `main()` den ville
   hørt hjemme, og hva laboratoriets angrepsflate blir når den faktisk kalles.
4. Beregn `rip_off` for hånd ut fra `objdump -d foowosd`: finn `buf`s
   `lea -0xNN(%rbp)` inne i `vulnerable_handler`, deretter `NN + 8`. foowosc
   gjør nøyaktig det; sjekk regnestykket dens mot ditt eget.
5. `make hardened && make test-hardened`. Hvilken teknikk faller for canaryen,
   og hvilken for NX? Hvorfor endrer ikke hærdning hva `make status` rapporterer
   om *prosessen*?
6. Sammenlign de to laboratorienes shellcodes: 23 bytes her, 32 for foosd. Hva
   gjør de ekstra 9 bytene, og hvorfor trengs de bare i SUID-tilfellet?
7. Les `become_shell()`s kommentar om den enkelte lese-cursoren. Gjenskap
   feiltilstanden mentalt: to lesere på én socket betyr at login-shellen spiser
   ett byte per chunk — «uid=1000…» ankommer som «id=1000…». Hvorfor kan en
   relay-prosess aldri ha denne feilen?

---

## Filer

```
foowosd.c                 den sårbare root-daemonen (hver linje kommentert)
foowosc.c                 exploitet (hver linje kommentert)
shellcode.S               referanse-assembly for 23-byte-payloaden
tests/pty_wosuid_test.c   pty-harnessen (markør + streng id-form-sjekk)
Makefile                  build / run / run-root / run-root-ns / test /
                          test-root / verify / hardened / clean …
```

Søster-laboratorier: `../food.c`/`../fooc.c` (user-level-baseline, port 2342)
og `../suid/` (SUID-root-daemon `foosd`/`foosc`, port 2343). Portene er bevisst
forskjellige — du kan kjøre alle tre samtidig og kryssjekke `ids=`-linjene
deres i banneret.
