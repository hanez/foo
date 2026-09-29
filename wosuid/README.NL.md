# Het `wosuid`-lab — root-RCE **zonder** setuid-bit

```
  foowosd   een bewust kwetsbare daemon die root is omdat hij als *GESTART* als
            root  (poort 2344, standaard alleen loopback)
  foowosc   het exploit: verandert een stack-overloop in een **root**-shell door
            shellcode uit te voeren — dezelfde 23 bytes die de user-level-
            `food`-daemon in het hoofdlab kraakten
```

Dit is het derde lab in de serie. Dezelfde exploit-werktuigketen, dezelfde stijl,
één fundamenteel verschil:

| Lab | hoe het doelproces root wordt              | `uid=0(root)`-shell? |
|----------|------------------------------------------------|----------------------|
| food/fooc | nooit — het is een gewone user-daemon       | nee                   |
| foosd/foosc | de SUID-bit (`chmod u+s`) — euid 0, ruid 1000 | ja (vereist `setreuid` in de shellcode, want bash reset euid→ruid) |
| **foowosd/foowosc** | **geen — root *start* de daemon** (sudo / systemd `User=root`) | **ja (gewone `execve`-shellcode)** |

De setuid-bit is een *transportmiddel* voor privileges — niet de privileges
zelf. Een daemon die door root is gestart, heeft reële, effectieve en
opgeslagen uid allemaal 0. Voor de kernel is dat root, punt uit; hij kan en wil
niet weten of het proces daar via `+s` op een bestand of via `sudo ./foowosd`
is gekomen. De overloop in een root-gestarte daemon is dus een root-exploit — *"ik
heb geen SUID-binaries" is niet hetzelfde als "ik ben niet exploiteerbaar".*

Dat is de hele les van dit lab. Al het andere hieronder is het mechanisme.

---

## Snelle start (wat de gebruiker vroeg)

```
cd wosuid
make                 # bouwt de daemon, het exploit en de test-harness
```

### Het echte werk — draai de daemon als **root**

```
sudo make run-root      # start foowosd als uid 0 (proces, geen bestandstoestand)
make test-root          # elke techniek moet nu uid=0(root) geven
```

### Geen sudo? Het identieke kernelpad via een user-namespace

```
make run-root-ns        # uid 0 in een user-namespace — geen wachtwoord nodig
make test-root          # dezelfde oordelen; gebruikt door CI en iedereen zonder sudo
```

### Baseline — daemon als je normale gebruiker (nergens root)

```
make run                # foowosd draait met jouw uids
make test               # exploits landen shells, maar `root` wordt verwacht als MISSING
```

### Opruimritueel (altijd: dit is een root-shell-lab)

```
make stop
```

`foowosd` is *niet* setuid, en niets in deze map doet ooit `chmod +s` — dat is
het punt. De gevaarlijke toestand is **het proces**, niet het bestand.

---

## Wanneer je wordt gezegd de SUID-bit te zetten

Dat zul je **niet** worden. Dit lab heeft bewust geen SUID-bit:

- `foowosd` wordt gebouwd, is eigendom van jou en heeft gewone toestanden als
  elk ander programma.
- Hij wordt root zoals echte daemons dat doen — door *gestart* te worden door
  root.
- `make run-root` gebruikt `sudo` voor precies dat, en `make run-root-ns`
  regelt een echte uid-0-proces zonder ook maar iets daarvan.

De Suid-bit hoort bij het *zuster*-lab (`foosd`). Het contrast tussen de twee
is de leerstof:

1. SUID-lab: de bit geeft **euid 0, maar ruid 1000** → `execve("/bin/sh")`
   wordt gedegradeerd door de wacht van bash (`euid != ruid` → reset) → de
   shellcode moet eerst `setreuid(0,0)` aanroepen (32-byte-payload).
2. Dit lab: root **start** het proces → **ruid == euid == 0** → de wacht heeft
   niets om te resetten → de gewone 23-byte `execve`-shellcode houdt root.

Dezelfde overloop. Dezelfde techniek. Andere *oorsprong* van privileges, andere
payload-vorm. Dat is de les in het klein.

---

## Het protocol

Welke client er ook verbindt, foowosd begroet hem met:

```
FOOWOSD 1.0 ids=0/0 leak stack=0x7ffd… libc=0x7f…      (banner + leaks)
BUF=0x7ffd…                                             (het bufferadres)
```

`ids=euid/ruid` is het *"ben ik root?"*-kanaal. foowosc print een luide
waarschuwing wanneer euid niet 0 is (dus je startte de daemon als gewone
gebruiker): de payload landt nog steeds, maar de shell wordt een
gebruiker-shell, en het exploit "kapot" noemen zou fout zijn — hij escaleert
alleen niet.

> Spellingsnoot: `ids=`, niet `euid=`/`ruid=`. De test-harness bewijst een
> levende `id` door de letterlijke vorm `uid=NNN(` te matchen, dus het banner
> mag nooit een deelstring bevatten die zelf aan de controle voldoet. (In het
> SUID-lab produceerde precies die val een spectaculaire fout-positief.)

---

## De exploit-technieken (`foowosc -t …`)

Alle vier de exploit-paden hieronder werken tegen foowosd. Wanneer de daemon
root is, geeft **alles dat iets spawnt root** — in tegenstelling tot het
SUID-lab, waar ret2win/ret2libc stilletjes door de wacht van bash naar uid 1000
werden gedegradeerd. Hier is er geen mismatch om te bewaken.

| `-t`          | wat er gebeurt                                                       | wanneer de daemon root is |
|---------------|---------------------------------------------------------------------|---------------------|
| `shellcode`   | 23-byte `execve("/bin/sh", NULL, NULL)` draait op de stack.           | **root-shell** (standaard) |
| `ret2win`     | sprong naar `win()` → `execl("/bin/sh")`                                | **root-shell** |
| `ret2libc`    | ROP: `pop rdi; ret` → `"/bin/sh"` → `system()`                      | **root-shell** |
| `demo`        | alleen rommel-overloop — verwacht een SIGSEGV in de daemonlog        | crash, volgens ontwerp |
| `leak`        | print alleen leaks, stuurt geen payload                               | n.v.t. |

```
./foowosc -t shellcode       # interactief; standaardtarget 127.0.0.1:2344
./foowosc -t shellcode -n    # sturen en rapporteren, geen interactieve sessie
```

Een succesvolle interactieve sessie schakelt je terminal door naar de shell *op
het slachtoffer* — er is precies één shell in het beeld, en dat is `/bin/sh`
die als root binnenin foowosd draait. Typ `id` om `uid=0(root)` te zien.

### Waarom er hier geen `ret2win-root`-techniek is

foosc had er één — die sprong naar een `win_root()` die `setreuid(0,0)` aanriep
vóór exec, omdat een setuid-proces draaide met een reële uid die nog 1000 zei.
Een root-*gestart* proces heeft de reële uid al 0; er valt niets op te ruimen,
dus de extra functie en techniek zouden niets leren. Verwijderd.

---

## Wat foowosc doet, stap voor stap

1. **Statische analyse** — `objdump -d` van `./foowosd`. Vindt
   `vulnerable_handler`, `win()`, de `lea -0x50(%rbp)` die `buf` adresseert,
   en de eerste kale `ret`. Uit de verplaatsing berekent het
   `rip_off = 80 + 8 = 88`. Niets is hardcoded; het overleeft een herbouw.
2. **Zelf-introspectie** — leest zijn eigen `/proc/self/maps` en `dlsym()`t
   `system`/`read` om de libc-*offsets* te leren. De libc-base van het
   doelwit is `leaked_read − off_read`, daarna `system = base + off_system`,
   enz. Die delta-rekenkunde is de reden dat exploits libc-versies overleven.
3. **Verbind** — leest het banner/leaks (`ids=`, `stack=`, `libc=`, `BUF=`).
4. **Bouw de payload** — voor `shellcode`: 23 bytes machinecode, padding tot
   `rip_off`, daarna de opgeslagen RIP = `buf` (zodat de `ret` op de code
   springt). Voor `ret2win`/`ret2libc`: adressen berekend uit de analyse —
   geen stackuitvoering nodig.
5. **De uitlijnfix** — een gekaapte kale `ret` geeft de callee
   `rsp ≡ 8 (mod 16)`, en glibc's SSE2-code faalt met `movaps` op een
   niet-uitgelijnde stack (de crash-reporter logt `si_addr=(nil)` — de hint).
   foowosc plaatst één extra `ret`-gadget vóór het echte doelwit en herstelt de
   invariant. Een zijdenhandschoentechniek in een shellcode-lab, maar het is
   het verschil tussen een payload die "soms werkt" en een die altijd werkt.
6. **Stuur, daarna schakel door** — het doelproces *is* de shell; dit proces
   splist alleen bytes. Geen lokale shell, geen andere lezer — de
   single-read-cursor-bug (één opgegeten byte per chunk) is gedocumenteerd in
   `become_shell()`.

---

## De bewuste bugs van de daemon (allemaal in `foowosd.c`, allemaal echte CWE-klassen)

| # | bug | CWE | notitie |
|---|-----|-----|------|
| 1 | `read(fd, buf, 512)` in een 64-byte stack-buffer | [CWE-120](https://cwe.mitre.org/data/definitions/120.html) | de overloop: 448 bytes voorbij `buf`, opgeslagen RIP op +88 |
| 2 | alleen `snprintf(line, …, "%.*s", …)`; maar aanvaller-`%` in het echo-pad | [CWE-134](https://cwe.mitre.org/data/definitions/134.html) | het lek is hier de echte payload; een `%n` in een *root*-proces zou write-what-where als root zijn |
| 3 | kinderen behouden root terwijl ze onbetrouwbare input afhandelen | [CWE-271](https://cwe.mitre.org/data/definitions/271.html) | de correcte `drop_privs()` (setgroups→setgid→setuid, in die volgorde, met verificatie) staat in het bestand, gecommentarieerd, *bewust nooit aangeroepen* |
| 4 | `ids=`, `stack=`, `libc=`, `BUF=` onthuld aan elke client | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | zonder deze leaks konden de shellcode- en ret2libc-technieken geen adressen berekenen (ASLR zou ze verslaan) |

De handler heeft precies dezelfde `buf[64]`/`read(512)`-vorm als de twee andere
labs, dus de gedeelde objdump-gebaseerde herkenningspipeline werkt ongewijzigd.

---

## Zo inspecteer je de daemon (leerpad)

```
make status            # draait hij? als welke uid? bestandstoestand wordt getoond
make run-root          # of run / run-root-ns
./foowosc -t leak      # zie het banner en leaks, stuur niets
./foowosc -t demo      # rommel-overloop -> SIGSEGV, gelogd met RIP/rsp
./foowosc -t shellcode # de interactieve root-shell
make test-root         # volledige matrix, alle technieken, --must-root
```

Crash-reporter: Bij SIGSEGV logt de daemon het foutadres, RIP en RSP. Een `ret`
in een niet-canonieke `0x4141…` faalt bij de `ret` zelf (RIP als `0x4028xx`,
`si_addr=(nil)`) — goed om te weten vóór je een logregel als NULL-dereferentie
verkeerd leest.

---

## Waarom de shellcode 23 bytes is, niet 32

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

Het SUID-lab heeft `setreuid(0,0)` vóór dit nodig. Dit lab niet, om de reden
die overal herhaald wordt: **ruid is al 0**, omdat root het proces startte.
`make verify` bewijst dat de bytes in `foowosc.c` byte-voor-byte zijn wat
`shellcode.S` assembleren tot.

---

## Tegenmaatregelen — wat `make hardened` verandert

Geharde build (`-fstack-protector-strong -fPIE -pie -z noexecstack`):

| techniek | kwetsbare `foowosd` | geharde `foowosd_hardened` |
|-----------|----------------------|------------------------------|
| `shellcode` | root-shell (uitvoerbare stack) | SIGSEGV bij de canary-controle / NX |
| `ret2win` / `ret2libc` | root-shell | canary aborted de `ret` — maar merk: een *PIE*-build maakt deze adressen ook willekeurig |
| `demo` | SIGSEGV, gelogd | SIGSEGV, gelogd |

`make test-hardened` demonstreert het live. De belangrijke observatie is niet
alleen dat de tegenmaatregelen de technieken doodden — het is dat ze de daemon
**niet** "niet-root" maakten. Een geharde build die nog steeds als root
*gestart* wordt, is nog steeds een root-daemon; de tegenmaatregel verhoogt
alleen de lat voor de aanvaller. Minste privilege (`drop_privs()`) en
geheugenveiligheid zijn twee verschillende bugs, en een daemon die geen root
nodig heeft, zou het niet moeten hebben.

---

## Veiligheidsleuningen (zelfde beleid als het SUID-lab)

- **Alleen loopback.** foowosd weigert iets anders dan `127.0.0.1` /
  `localhost` / `::1` te binden, tenzij je `-L` geeft. Een root-daemon op een
  echte interface is een *externe* root-dienst. `-L` bestaat alleen om de
  wacht te tonen; gebruik het niet op iets dat ertoe doet.
- **De toestand wordt luid gelogd.** Bij de start print hij `ruid/euid` en of
  dit een root-proces is, zodat je altijd weet welk exploit-resultaat je moet
  verwachten.
- **Oordelen komen uit exit-status** in `make test*` (de retourcode van de
  pty-harness), nooit uit het greppen van zijn stdout — grepbare output liegt.
- **De pty moet cooked + ECHO off draaien**, anders echoët de harness zijn
  eigen commandoregel en vervalst de markering. De harness zet ECHO uit en
  houdt ECHONL aan.
- **Opruimritueel:** `make stop` na elke sessie. Als de daemon root-bezeten
  is, zegt `stop` je `sudo pkill -x foowosd` te draaien.
- Draai dit nooit op een host waar je om geeft. Het bestaat om `uid=0`-shells
  over de loopback-interface uit te delen.

---

## Oefeningen

1. Draai `make run` (user-daemon), daarna `./foowosc -t shellcode`. Waarom is
   de shell niet root? (Check `ids=` in het banner — foowosc zegt het je vóór
   je überhaupt verbindt.)
2. `make stop && sudo make run-root && make test-root`. Verklaar aan de hand
   van de bannerregel waarom alle vier de technieken nu `uid=0(root)` geven.
3. Vind in `foowosd.c` `drop_privs()` en lees *waarom de volgorde* van
   `setgroups → setgid → setuid` ertoe doet. Bepaal waar in `main()` hij thuis
   zou horen, en wat het aanvalsoppervlak van het lab wordt wanneer hij
   daadwerkelijk wordt aangeroepen.
4. Bereken `rip_off` met de hand uit `objdump -d foowosd`: vind de
   `lea -0xNN(%rbp)` van `buf` binnenin `vulnerable_handler`, daarna `NN + 8`.
   foowosc doet precies dat; controleer zijn rekensom tegen de jouwe.
5. `make hardened && make test-hardened`. Welke techniek valt voor de canary,
   en welke voor NX? Waarom verandert harden niet wat `make status` over *het
   proces* rapporteert?
6. Vergelijk de shellcodes van de twee labs: 23 bytes hier, 32 voor foosd. Wat
   doen de extra 9 bytes, en waarom zijn ze alleen in het SUID-geval nodig?
7. Lees de commentaar van `become_shell()` over de enkele lees-cursor. Maak de
   faaltoestand mentaal na: twee lezers op één socket betekent dat de
   login-shell één byte per chunk eet — "uid=1000…" arriveert als "id=1000…".
   Waarom kan een relay-proces deze bug nooit hebben?

---

## Bestanden

```
foowosd.c                 de kwetsbare root-daemon (elke regel gecommentarieerd)
foowosc.c                 het exploit (elke regel gecommentarieerd)
shellcode.S               referentie-assembly voor de 23-byte-payload
tests/pty_wosuid_test.c   de pty-harness (markering + strikte id-vorm-controle)
Makefile                  build / run / run-root / run-root-ns / test /
                          test-root / verify / hardened / clean …
```

Zuster-labs: `../food.c`/`../fooc.c` (user-level-baseline, poort 2342) en
`../suid/` (SUID-root-daemon `foosd`/`foosc`, poort 2343). De poorten zijn
bewust verschillend — je kunt alle drie tegelijk draaien en hun `ids=`-regels
in het banner kruislings controleren.
