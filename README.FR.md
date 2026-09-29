# food / fooc — un débordement de tampon de pile, des deux côtés

Un laboratoire de sécurité en C99 en deux moitiés :

- **`food.c`** — un démon TCP volontairement vulnérable. Il contient un vrai
  débordement de tampon de pile, digne d'un manuel ([CWE-120](https://cwe.mitre.org/data/definitions/120.html)), plus quelques
  bugs en prime.
- **`fooc.c`** — un exploit contre lui. Il calcule l'offset du débordement en
  désassemblant le programme cible à l'exécution, lit les fuites d'adresses du
  démon et obtient un shell sur la « victime » en écrasant une adresse de
  retour sauvegardée.

Le but n'est pas le shell. Le but est que vous puissiez suivre de bout en bout
comment un bug de sécurité mémoire devient une exécution de code arbitraire —
puis voir exactement quelles contre-mesures arrêtent chaque maillon de cette
chaîne. Chaque ligne des deux programmes est commentée, parce que le mécanisme
est la leçon.

```
                  votre terminal
                         |
                     ./fooc   (exploit)
                         |
                    TCP 127.0.0.1:2342
                         |
                     ./food   (démon vulnérable)
                         |
                 fork() -> vulnerable_handler() -> overflow -> ret -> votre code
```

---

## ⚠️ Lisez ceci d'abord

**`food` est un service réseau volontairement cassé. Il ne se lie qu'à
`127.0.0.1`, et cette valeur par défaut est volontaire — laissez-la.**

- Ne l'exécutez **pas** sur une machine à laquelle vous tenez, ni sur quelque
  chose qui contient des données.
- Ne le liez **pas** à `0.0.0.0` ou à une vraie interface réseau. Il est
  volontairement exploitable à distance.
- Pointer `fooc` vers une machine que vous ne possédez pas ou que vous n'avez
  pas l'autorisation écrite de tester est une infraction informatique dans la
  plupart des juridictions — y compris en vertu de l'UK Computer Misuse Act et
  de l'US Computer Fraud and Abuse Act.
- Il se lie à un port non privilégié (>1024), donc pas besoin de root. Ne
  l'« améliorez » pas en ajoutant des capabilities ou en l'exécutant comme
  service système.
- Chaque connexion est traitée dans un enfant `fork()`, et `food` les reape,
  donc les crashs ne s'accumulent pas. Si vous retrouvez ensuite des dizaines
  de `sh` qui traînent, `pkill -x sh` est le nettoyage.

En cas de doute : ce lab est fait pour une machine virtuelle ou un conteneur,
sur un réseau que vous contrôlez, sur une machine sans rien que vous
regretteriez.

---

## Démarrage rapide

```sh
make            # compile food, fooc et les harnesses de test
make run        # démarre food sur 127.0.0.1:2342, détaché en arrière-plan
make test       # exécute les trois techniques d'exploit
make stop       # arrête le démon
```

Ensuite, à la main :

```sh
./fooc -t leak        # regardez les fuites d'adresses que food divulgue
./fooc -t demo -v     # envoyez du bourrage ; voyez food mourir d'un SIGSEGV
./fooc -t ret2win -i  # sautez vers une fonction qui existe déjà -> shell
```

### Prérequis

| Outil | Pour quoi | Remarques |
|---|---|---|
| `gcc` (ou clang) | compilation | C99. Testé avec gcc 16.2 |
| `objdump` | `fooc` | binutils. `fooc` l'appelle à l'exécution |
| `nasm` | `make verify` | uniquement pour recouper la shellcode ; ignoré s'il manque |
| `gdb` | `make debug` | optionnel |
| Linux, x86-64 | les deux | la payload et la chasse aux gadgets dépendent de l'architecture |

`fooc` a aussi besoin de `-ldl` pour `dlsym()` ; le Makefile s'en charge.

---

## Le bug

Une ligne dans `food.c` est toute la surface d'attaque :

```c
char buf[FOOD_BUFSZ];                  /* 64 octets  */
n = read(fd, buf, FOOD_READMAX);       /* jusqu'à 512 octets depuis le réseau */
```

64 octets de destination, 512 acceptés. L'attaquant écrit 448 octets au-delà
de la fin du tampon, et comme la pile croît vers le bas, « au-delà de la fin »
signifie « dans le cadre au-dessus » — et c'est exactement là que se trouvent
le pointeur de trame sauvegardé et l'**adresse de retour sauvegardée**.

Dans une fonction x86-64 compilée à `-O0` :

```
  adresses hautes
  +------------------------+  rbp + 16 : locales de l'appelant
  |  ...                   |
  +------------------------+  rbp +  8 : ADRESSE DE RETOUR SAUVEGARDÉE   <-- devient RIP
  |  saved rbp (8 bytes)   |
  +------------------------+  rbp      : notre pointeur de trame
  |  line[128]             |
  |  buf[64]               |  <- rsp : ce que read() remplit
  +------------------------+
  adresses basses
```

Quand la fonction retourne, `leave; ret` pousse les 8 octets dans `RIP`, et le
CPU saute là où l'attaquant l'a décidé. Tout le reste dans ce lab est de
l'arithmétique sur où pointer.

Pour cette compilation, les chiffres sont : `buf` fait 64 octets, le `rbp`
sauvegardé fait 8, donc l'adresse de retour est à l'offset **88** du début de
`buf`. `fooc` ne hardcode pas ça — il désassemble `food` et trouve le
`lea -0x50(%rbp)` devant `call read@plt`, donc ça continue de marcher si vous
changez `FOOD_BUFSZ`.

> gcc vous le dit déjà. Compiler `food` affiche :
> `warning: 'read' writing 512 bytes into a region of size 64 overflows the
> destination [-Wstringop-overflow=]`. N'étouffez jamais cet avertissement
> dans du vrai code. C'est de la sécurité gratuite.

---

## Les trois techniques

`fooc -t <technique>`. Elles sont dans l'ordre où un vrai attaquant s'y
prendrait, parce que chacune a besoin de ce que la précédente vous a appris.

### 1. `ret2win` — contrôlez le pointeur d'instruction

```
[ 88 octets de bourrage ][ l'adresse du win() de food ]
                          ^ saved rbp
                                           ^ devient RIP
```

`win()` est une fonction du programme cible qui exec `/bin/sh`. Écraser
l'adresse de retour avec son adresse, c'est tout l'exploit.

**Ce que ça apprend :** vous avez un contrôle arbitraire du pointeur
d'instruction. Pas besoin de fuite non plus, car le binaire est compilé avec
`-no-pie`, donc `win()` est à une adresse fixe pour toujours.

**L'équivalent dans le monde réel** n'est pas « les attaques sont faciles »,
mais « ne livrez pas de portes dérobées non documentées dans des binaires
réseau ». S'il existe une fonction comme `win()` dans votre binaire, un
débordement de tampon la trouvera. C'est littéralement la classe des CVE de
backdoor Juniper ScreenOS.

**Défense :** `-fPIE` (ou ASLR) randomise l'adresse de chargement, donc
l'attaquant doit connaître l'adresse — ce qui signifie en pratique qu'il lui
faut d'abord une fuite. C'est pourquoi `ret2win` échoue contre
`food_hardened`.

### 2. `ret2libc` — appelez n'importe quoi, par son nom

```
[ bourrage ][ pop rdi; ret ][ adresse de "/bin/sh" ][ adresse de system() ]
            ^^^^^^^^^^^^     ^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^
            met rdi          la chaîne à envoyer      la fonction à appeler
```

À l'exécution : `ret` pousse `pop rdi; ret` dans RIP ; ça pousse le pointeur
`"/bin/sh"` dans `RDI` ; son `ret` pousse `system()` dans RIP, pendant que
`RDI` tient toujours la chaîne. `system("/bin/sh")` s'exécute.

Les gadgets (`pop rdi; ret`) ne sont pas dans `food` — cette glibc n'a pas de
`__libc_csu_init` — donc `fooc` les trouve en scannant la mémoire live de la
libc à la recherche de la paire d'octets `5f c3`. Il localise la libc via
`/proc/self/maps`, trouve les offsets de `system` et `"/bin/sh"` avec
`dlsym()` et calcule la base à partir de la fuite que `food` divulgue. Rien
n'est hardcodé, donc ça survit à une mise à jour de la libc.

**Ce que ça apprend :** une fois que vous contrôlez `RIP`, vous pouvez
enchaîner des instructions *existantes*. C'est la programmation orientée
retour (return-oriented programming), et c'est à ça que ressemblent presque
tous les vrais exploits, parce que ça ne nécessite pas de mémoire exécutable
fournie par l'attaquant.

**Défense :** aucun des flags du compilateur ne l'arrête seul. Ça marche
contre un binaire PIE, avec NX, avec canary — tant que l'attaquant a une
fuite. Les défenses sont « n'ayez pas le débordement » et « ne fuytez pas
d'adresses ». Voir le tableau ci-dessous.

### 3. `shellcode` — exécutez votre propre code machine

23 octets, placés au début du tampon, avec `RIP` pointant dessus :

```asm
xor    esi, esi                    ; envp = NULL
xor    edx, edx                    ; argv = NULL
movabs rdi, 0x68732f6e69622f       ; rdi = "/bin/sh\0" en 8 octets bruts
push   rdi                         ; dépose la chaîne sur la pile
mov    rdi, rsp                    ; rdi = &"/bin/sh"
push   0x3b                        ; 59 = __NR_execve
pop    rax
syscall                           ; nous voilà un shell
```

C'est la forme la plus pure du bug : l'attaquant fournit les *instructions*,
pas seulement l'adresse d'instructions qui existent déjà. Aucun offset de
libc nécessaire, donc ça marche en principe contre une cible statiquement
liée, entièrement randomisée.

`make verify` assemble `shellcode.S` et le diff contre le tableau d'octets
intégré dans `fooc.c`, pour que les deux ne puissent pas diverger.

**Défense :** **NX** (aussi appelé W^X, « no execute »). Marquer la pile comme
non exécutable fait que le matériel refuse d'y chercher des instructions, et
le `ret` atterrit sur une page qui ne peut pas tourner. C'est pourquoi
`make food` passe `-z execstack` : une pile Linux normale est `rw-p`, pas
`rwx`, et la technique meurt d'un SIGSEGV à `RIP = l'adresse de la payload`.
La leçon la plus importante du lab est que chacun de ces octets ne fonctionne
que parce qu'on a dit au compilateur de rendre la pile exécutable. Ce flag est
activé pour le bien de personne.

### Aussi inclus

| Mode | Ce qu'il fait |
|---|---|
| `-t leak` | se connecte, affiche les fuites, n'envoie rien |
| `-t demo` | envoie `rip_off + 8` octets de `0x41`, donc `RIP` devient `0x4141...` et le démon meurt. Prouve le bug sans aucune connaissance d'adresse |
| `-t sled` | un ret-sled, conservé volontairement comme exemple **échec**. Sans fuite, vous brute-foreeriez ASLR en remplissant le tampon avec l'adresse d'un `ret`. Impossible ici : `food` accepte 512 octets, donc le sled a ~53 emplacements contre ~28 bits d'entropie. Implémenté pour que vous puissiez le voir échouer et confirmer que le mécanisme est vraiment « le CPU suit une chaîne de rets » |

---

## Le tableau des contre-mesures

C'est la partie à retenir. Chaque ligne est une vraie défense, et la colonne
de droite montre ce qu'elle fait réellement à la chaîne des événements.

| Contre-mesure | Comment l'activer | Ce qu'elle arrête | Ce qu'elle *n'arrête pas* |
|---|---|---|---|
| **Limitez read** | `n = read(fd, buf, sizeof buf - 1);` | **Tout.** Le bug n'existe pas, donc rien en aval n'a d'importance | Rien — c'est le seul correctif complet |
| **Canary de pile** | `-fstack-protector-strong` (par défaut chez gcc) | Le `ret` : la canary est vérifiée à la sortie de la fonction, la corruption est donc détectée et le processus abort avant que `RIP` soit poussé | Un bug dans une fonction *sans* tableau (rien à protéger) ; un débordement qui reste sous la canary ; tout ce qui ne retourne pas normalement |
| **NX / W^X** | `-z noexecstack` (la valeur par défaut) | La shellcode. Les instructions de la payload ne peuvent pas être cherchées | ret2win et ret2libc complètement. C'est *la raison* pour laquelle ROP existe |
| **PIE + ASLR** | `-fPIE` + ASLR=2 (tous deux par défaut) | Les adresses hardcodées de ret2win. Tout bouge à chaque exécution | Tout ce où l'attaquant a une fuite. ASLR augmente le prix d'un exploit ; ce n'est pas un correctif. Notez que la pile, le tas et mmap sont randomisés, mais pas le *contenu* du binaire principal — c'est ce que les chaînes ROP utilisent |
| **Ne fuytez rien** | aucun `printf("%p")` vers les clients ; initialisez avant d'afficher | La fuite d'information qui rend ASLR « gratuit » au lieu de « cher » | — |
| **N'utilisez pas `printf(user_data)`** | `printf("%s", buf)` au lieu de `printf(buf)` | Les bugs de chaîne de format : lectures de pile `%x`, écritures arbitraires `%n` — une *autre* voie vers RCE | — |
| **N'utilisez pas de chemins non fiables** | validez et `openat()` sous un répertoire fixe | Traversal de chemin ([CWE-22](https://cwe.mitre.org/data/definitions/22.html)) | — |
| **CET / shadow stack** | `-fcf-protection=full`, support noyau et CPU | Le `ret` lui-même : la shadow stack mémorise la *vraie* adresse de retour et fault en cas de mismatch. Attrape les chaînes ROP qui utilisent le `ret` matériel | Les attaques qui ne `ret` jamais (call-oriented, ou écraser la cible d'un pointeur de fonction avec une chaîne de gadgets qui n'a pas besoin de retour) |
| **Langages sûrs** | Rust, Go, C# pour le nouveau code | Toute la classe. Les vérifications de bornes sont imposées à l'exécution, pas espérées à la revue | — |

### Voyez par vous-même

```sh
make run            # démon vulnérable
make test           # les trois techniques fonctionnent

make test-hardened  # même code source, contre-mesures activées
```

`test-hardened` compile `food_hardened` avec `-fstack-protector-strong -fPIE
-pie -z noexecstack`, l'échange, rejoue les trois techniques puis remet la
version vulnérable en place. Vous verrez :

```
### stack segment: 'rw-p' (NOT executable) is what you want to see
--- ret2win   was stopped by the mitigations (as expected)
--- ret2libc  was stopped by the mitigations (as expected)
--- shellcode was stopped by the mitigations (as expected)
```

Et dans le log du démon durci, la canary qui se déclenche :

```
*** stack smashing detected ***: terminated
```

Lisez bien, car c'est la ligne la plus importante de tout le lab : **la canary
a attrapé ret2win, pas PIE.** Les trois techniques meurent à la canary, parce
que les trois passent par le même `read()` et écrasent le même cadre. NX
n'arrête en plus que le *code* de la shellcode ; PIE ne casse en plus que
l'adresse hardcodée. Activez-les une par une, et vous découvrirez que la
plupart des contre-mesures isolées vous laissent exposé à quelque chose.

---

## Fichiers

| Fichier | Rôle |
|---|---|
| `food.c` | le démon vulnérable. 6 bugs numérotés, chacun avec son correctif en commentaire |
| `fooc.c` | l'exploit. Reconnaissance d'offset par objdump, reconnaissance de la libc via `/proc`, 4 constructeurs de payload |
| `shellcode.S` | les 23 octets de shellcode en assembly, pour être lisibles et vérifiables. `fooc` les embarque en ligne et n'en a pas besoin à l'exécution |
| `Makefile` | compile, teste et la comparaison durcie |
| `tests/pty_test.c` | conduit `fooc` à travers un pseudo-terminal et vérifie une vraie sortie de shell |
| `tests/sock_test.c` | vérificateur indépendant sur une socket brute, pour que le résultat ne dépende pas de `fooc` |
| `food.log` | le log du démon. Votre preuve de ce qui s'est passé |

---

## Deux bugs de ce lab qui valent la peine d'être compris

Ce ne sont pas les bugs du programme cible. Ce sont des bugs de l'exploit et
de sa harnesse de test, et les deux ont produit des mensonges convaincants.
Ils sont documentés dans la source où ils vivent ; ils sont ici parce que les
schémas d'échec sont instructifs.

### Alignement de pile : le crash qui n'est pas une déréférence NULL

**Symptôme.** L'overtake atterrit correctement — `gdb` vous montre dans
`win()` — et puis la toute première chose que fait `win()`, un `dprintf()`,
meurt. Le handler SIGSEGV rapporte `RIP` profond dans le formatter de glibc
et une adresse d'erreur de `(nil)`, ce qui ressemble exactement à un pointeur
corrompu.

**Cause.** L'ABI System V AMD64 exige un alignement de pile de 16 octets. Un
`ret` normal restaure `%rsp` exactement comme le `call` correspondant l'avait
stocké, donc l'invariant est préservé gratuitement. Notre `ret` nu ne le fait
pas : après lui, `%rsp = buf + rip_off`. Ici, `buf` est aligné sur 16 octets
et `rip_off` vaut 88, donc le callee reçoit une pile à 8 mod 16. glibc est
compilé avec SSE2, et `movaps` **fault** sur un opérande mal aligné. Sur
x86, ça soulève `#GP`, pas `#PF`, donc le noyau n'a pas d'adresse d'erreur et
rapporte `si_addr = 0`. Ce NULL est l'indice : une erreur d'alignement
déguisée en déréférence NULL.

**Correctif.** Un gadget `ret` *à l'offset `rip_off`*, qui décale la vraie
cible de 8 octets, parce que chaque `ret` ajoute exactement 8 à `%rsp`.
L'ordre est critique : une version précédente collait le `ret` *après* la
cible et produisait `[ padding | target | ret ]`, où le `ret` final n'est
jamais atteint et le correctif ne fait silencieusement rien. Un `ret` égaré
qui ressemble à un bug est presque toujours intentionnel.

### Une socket, deux lecteurs : l'octet disparu

**Symptôme.** La shellcode était rapportée comme fonctionnant. Puis la harness
pty a été durcie (désactivation de `ECHO`, pour que le terminal arrête de
s'échoir sa propre ligne de commande), et la technique a commencé à échouer.
Plus profondément, chaque technique perdait exactement un octet au début de
chaque morceau de sortie : `uid=1000(hanez)` était affiché comme
`id=1000(hanez)`, `PWNED-OK` comme `WNED-OK`, `Linux 7.2.7` comme
`inux 7.2.7`.

**Cause.** `fooc` faisait un `dup2()` de la socket sur son propre stdin/stdout
et un `execv()` d'un `/bin/sh` *local*, pendant qu'un enfant relay forké
lisait aussi la même socket pour déplacer la sortie vers le terminal. Le
noyau se moque que les deux coopèrent. Une socket stream a **une** curseur de
lecture, et chaque lecteur la déplace, donc les octets sont répartis entre eux
de façon imprévisible. Le shell local — un shell de connexion interactif —
lisait exactement un octet et le jetait, à chaque fois. `strace -f` l'a montré
immédiatement :

```
read(0, "u", 1)                              <- le shell local, mange un octet
read(4, "id=1000(hanez) gid=1000(hanez) g".., 310)   <- le relay, 1 octet de trop court
```

**Correctif.** Il n'y a aucun shell de ce côté-ci, point. Il y a exactement un
shell dans tout le tableau, et il est sur la victime, dans le processus
détourné, avec la connexion TCP comme stdin/stdout. Ce côté ne fait que
déplacer des octets. Si vous avez un jour besoin de deux consommateurs d'un
flux, ce flux a besoin d'un lecteur unique qui le démultiplexe délibérément.

**La meta-leçon.** Le premier résultat « fonctionnel » était un faux positif,
produit par le fait que le pty s'échoit sa propre ligne de commande, et le
correctif de ce faux positif est ce qui a révélé le vrai bug. Des tests qui ne
peuvent pas échouer sont pires que pas de tests, parce qu'ils transforment « je
ne sais pas » en « ça marche ». Une harnesse de test mérite la même suspicion
que le code qu'elle teste.

---

## Bidouiller dessus

Des choses qui valent le coup d'essayer, à peu près dans l'ordre où vous en
apprenez le plus :

1. **Changez `FOOD_BUFSZ` en 128.** Relancez `fooc`. Ça devrait continuer de
   marcher sans modification, parce qu'il lit l'offset dans le désassemblage.
   Cassez-le ensuite à la main — hardcodez 88 — et voyez-le crasher. Ajoutez
   puis un deuxième tableau entre `buf` et les registres sauvegardés, et voyez
   la reconnaissance automatique s'en charger.

2. **Ajoutez `-Wformat-security` et voyez ce que fait le chemin de chaîne de
   format.** Envoyez `%p %p %p %n` et voyez `food` fuyter la pile.

3. **Utilisez gdb.** `make debug`, puis :
   ```gdb
   (gdb) break food.c:393        # le read() qui déborde
   (gdb) run -p 2342
   (gdb) info registers rsp rbp
   (gdb) x/24gx $rsp             # remarquez où se trouve l'adresse de retour
   (gdb) c                        # dans un autre terminal : ./fooc -t ret2win
   ```
   Le handler SIGSEGV journalise `REG_RIP` et `REG_RSP`, donc `food.log` vous
   dit si l'overtake a atterri, même quand l'enfant meurt avant que vous
   puissiez vous attacher.

4. **Supprimez le correctif d'alignement** dans `fooc.c` et voyez l'erreur
   `#GP` avec la signature `si_addr = 0`. Lisez ensuite
   `/proc/sys/kernel/randomize_va_space` et réfléchissez à ce qu'ASLR
   randomise, et à ce qu'il ne randomise pas.

5. **Cassez la résolution de symboles de la libc** et voyez `fooc`
   s'adapter. Tout l'intérêt de l'approche `/proc/self/maps` est qu'aucun
   offset n'est hardcodé.

6. **Écrivez une quatrième technique.** Une chaîne de type `ret2csu` si vous
   trouvez `__libc_csu_init`, ou une chaîne SROP (les cadres `sigreturn`
   vous laissent contrôler tous les registres d'un coup). Les deux sont du ROP
   pur et n'ont besoin d'aucune mémoire exécutable.

7. **Corrigez `food.c` proprement**, un bug à la fois, et relancez l'exploit
   après chaque correctif. L'ordre du tableau en haut de `food.c` est à peu
   près le bon ordre de pensée : limitez d'abord le read, car rien d'autre
   n'importe tant que le bug n'est pas parti.

---

## Nettoyage

```sh
make stop        # arrête food
make clean       # supprime les produits de compilation ; laisse food.log tranquille
pkill -x sh      # seulement si vous avez des shells qui traînent d'un test raté
```

Notez : `pkill -x food` matche le **nom** du processus exactement. N'utilisez
pas `pkill -f ./food` — ce motif matche aussi le shell dans lequel vous le
tapez et tue votre propre session. Ce n'est pas une hypothèse ; c'est arrivé
pendant la construction de ce lab.
