# Lab RCE racine par SUID — `foosd` (démon) + `foosc` (exploit)

Un compagnon du laboratoire principal (`food` / `fooc`, un démon ordinaire où
un débordement de tampon vous donne un shell *utilisateur*). Celui-ci ajoute le
changement d'un seul caractère le plus dangereux d'Unix : **le bit setuid**.

> `chmod u+s` transforme « l'attaquant peut exécuter du code sur cette machine »
> en « l'attaquant peut exécuter du code en tant que **root** sur cette
> machine ».

Cette phrase, c'est tout le laboratoire. Tout ce qui suit est le mécanisme
qu'il y a dessous, écrit noir sur blanc, pour que lorsque vous écrivez votre
propre logiciel, vous sachiez précisément quels deux ou trois attributs de
système de fichiers et flags de compilateur décident si un bug de sécurité
mémoire dans votre code est une nuisance ou un shell root.

La démo finale, quand `foosd` est setuid-root, est un **shell root** ouvert sur
le réseau en exécutant 32 octets de shellcode écrite à la main.

---

## 1. Ce que fait réellement le bit setuid

Chaque processus Linux porte trois user-ID, et le bit setuid touche à la
relation entre eux :

| ID | Nom | Signification |
|----|------|---------|
| `ruid` | user-ID réel | le compte qui a *démarré* le processus |
| `euid` | user-ID effectif | ce que le noyau vérifie quand il applique les accès |
| (saved) | set-user-ID sauvegardé | un « créneau » auquel un processus privilégié peut revenir plus tard |

Un programme normal a `ruid == euid`. Quand vous exécutez un binaire avec le
bit setuid posé, appartenant à root :

```text
ruid = vous      (ex. 1000, « hanez »)
euid = le propriétaire (ex. 0, « root »)
```

Le processus a donc **l'autorité de root**, même si l'utilisateur qui l'a
lancé est parfaitement ordinaire. Chaque contrôle que le noyau effectue — ce
processus peut-il lire `/etc/shadow` ? écrire un fichier ? tuer un autre
processus ? — est tranché avec `euid`, donc « oui, il est root ».

`foosd` est un démon réseau. Il lie un port puis `fork()` un enfant par
connexion. Un fork *hérite* de l'euid, donc chaque enfant qui traite une
connexion est aussi root. Le débordement dans `vulnerable_handler()` de
`foosd` est donc un débordement *à l'intérieur d'un processus root*.

**Diagnostiquez-le vous-même quand le démon tourne :**

```console
$ ./foosd ...            # voyez la ligne de log qu'il affiche au démarrage
[foosd 1234] startup: ruid=1000 euid=0 -> ROOT process
```

et depuis l'exploit :

```console
$ ./foosc -t leak
foosc: target euid=0 ruid=1000
```

---

## 2. Le lab en un coup d'œil

| Fichier | Rôle |
|------|------|
| `foosd.c` | Le démon volontairement vulnérable (propriétaire des bugs). Exécutez-le en *binaire setuid-root* pour la démo du shell root. |
| `foosc.c` | L'exploit. Utilise par défaut la technique de shellcode `setreuid + execve` de 32 octets. |
| `shellcode.S` | La shellcode de référence ; `make verify` la diff contre le tableau d'octets dans `foosc.c`. |
| `tests/pty_suid_test.c` | Harnesse de test. Conduit `foosc` à travers un pseudo-terminal et prouve à la fois « un shell a tourné » *et* « il était root » (`uid=0(`). |
| `Makefile` | Compilation, helpers `setuid`/`unsetuid`, matrice de test. |
| `README.md` | Ce fichier. |

> **Pourquoi un pty ?** La dernière action de l'exploit est de relayer votre
> terminal vers le shell qui tourne sur la victime. Un pipe ou un here-doc
> arrive du mauvais côté du relais ; un vrai terminal est requis.

---

## 3. Démarrage rapide

```console
$ make                       # compilez tout, en tant que votre utilisateur normal
$ make setuid                # une fois, demande sudo : chown root + chmod u+s
$ make run                   # démarre foosd sur 127.0.0.1:2343
$ make test-suid             # matrice complète ; shellcode + ret2win-root doivent donner root
```

Test de fumée interactif :

```console
$ ./foosc -t shellcode
...
foosc: target euid=0 ruid=1000
foosc: shell is on the victim (root if foosd is SUID); relaying
# id
uid=0(root) gid=0(root) groups=0(root)      <-- vous êtes root, sur la victime
# exit
```

Quand vous avez fini :

```console
$ make stop
$ make unsetuid             # hygiène : ne laissez jamais un binaire root SUID traîner
```

---

## 4. *Quand dois-je poser le bit SUID ?* — la réponse que vous avez demandée

Exactement **une fois, après la compilation, avant de démarrer le démon pour
les démos de shell root** — et uniquement sur une machine qui est à vous,
bonne à jeter et déconnectée du réseau :

```console
$ make            # compilez foosd, foosc, les tests
$ make setuid     # <-- L'INSTANT. sudo chown root:root foosd && sudo chmod u+s foosd
$ make run        # démarrez APRÈS avoir posé le bit
```

Deux règles plus importantes que le moment précis :

1. **Posez-le seulement quand le binaire est fini.** Si vous recompilez
   (`make` / `make clean`) après avoir posé le bit, vous tombez sur un
   « Permission denied » en écrivant les fichiers de sortie appartenant à root
   — et si vous forcez la recompilation, la chaîne d'outils recrée le fichier
   **sans** le `s` et défait silencieusement la configuration. L'ordre
   canonique à chaque recompilation est donc

   ```console
   $ make unsetuid && make && make setuid
   ```

2. **Enlevez-le quand vous avez fini.** `make unsetuid`. Un binaire setuid
   vivant, appartenant à root, avec un bug exploitable dans votre arborescence,
   ce n'est pas un outil pédagogique, c'est un trou root avec une erreur de
   compilation entre lui et rien. Sur une machine partagée ou de production :
   **ne faites rien de tout cela.** Le démon refuse d'ailleurs par défaut de se
   lier ailleurs qu'en loopback (voir §7).

Si vous exécutez l'exploit *sans* jamais poser le bit, rien ne casse — la
payload atterrit toujours, et vous obtenez toujours un shell. La différence
tient en un seul chiffre, et l'exploit le dit à voix haute :

```console
foosc: WARNING: the daemon is NOT running with euid 0.
       The payload will still land, but the shell will be
       a plain user shell, not root.
       Fix:  sudo make setuid
```

Le résultat « ça marche, mais pas root » fait lui-même partie du lab. Gardez-le
en tête pour la section suivante.

---

## 5. Le mécanisme — et la pirouette qui rend SUID intéressant

### 5.1 Le débordement (identique à `food`)

Le handler de `foosd` donne à un `read()` 512 octets de confiance en lui
tendant un tampon de pile de 64 octets :

```c
char buf[64];
n = read(fd, buf, 512);        /* <- CWE-120 : 448 octets par-dessus le bord */
```

Sur x86-64, la pile croît vers le bas. L'exploit écrit 64 octets de bourrage
pour remplir `buf`, 8 pour remplir le pointeur de trame sauvegardé et 8 de
plus pour remplacer l'**adresse de retour sauvegardée**. Quand
`vulnerable_handler` exécute `ret`, le CPU pousse la valeur de l'attaquant
dans `RIP` — une exécution de code contrôlée par l'attaquant. L'exploit trouve
la distance exacte (88 octets pour cette compilation) en analysant la sortie
de `objdump` au lieu de la hardcoder, donc le chiffre survit aux
recompilations.

### 5.2 La pirouette : le shell refuse d'être root

Voici où penser « bug SUID → spawn /bin/sh → root » irait de travers, et
pourquoi ce lab a exactement la forme qu'il a.

Quand un programme setuid-root tourne, son `ruid` est toujours l'utilisateur
qui l'a lancé, et son `euid` est root. Si le programme — ou l'attaquant — lance
maintenant un shell :

* `execve("/bin/sh")` ne change **pas** les uids ; le nouveau processus hérite
  de `(ruid=1000, euid=0)`.
* bash (et dash) **vérifie exactement cet état au démarrage**. D'après le
  manuel de bash : *« If the shell is started with the effective user (group)
  id not equal to the real user (group) id, and the -p option is not supplied,
  … the effective user id is set to the real user id. »*

Donc le shell se regarde et *lâche root* — une défense que les auteurs de
shell ont construite précisément contre cette attaque (la justification
historique était le problème des shell setuid / scripts setuid). Le résultat,
ce sont les cas « ça marche, mais pas root » :

| Technique | Ce qu'elle exécute | uid résultant |
|-----------|------------------|---------------|
| `ret2win` | `win()` de `foosd` → `execl("/bin/sh")` | **1000** — shell atterri, root réinitialisé par bash |
| `ret2libc` | `system("/bin/sh")` → `sh -c '/bin/sh'` tout frais | **1000** — même réinitialisation, un niveau plus bas |
| `ret2win-root` | `win_root()` de `foosd` → `setreuid(0,0); execl("/bin/sh")` | **0** — ruid nettoyé depuis le C |
| `shellcode` | 32 octets : `setreuid(0,0); execve("/bin/sh")` | **0** — ruid nettoyé depuis le code machine |

Celles qui atteignent root diffèrent de celles qui ne l'atteignent pas par
exactement une idée : **elles nettoient l'uid *réel*, pas seulement
l'effectif.**

```c
setuid(0)          /* met euid à 0, mais ruid reste 1000 :
                      bash voit toujours euid != ruid et réinitialise QUAND MÊME. */
setreuid(0, 0)     /* met LES DEUX : ruid = euid = 0.
                      bash voit des uids égaux et garde root. */
```

C'est pourquoi la shellcode `/bin/sh` classique que vous trouvez partout sur
Internet commence par un syscall de nettoyage d'uid — et c'est pourquoi la
shellcode fait ici 32 octets au lieu de 23 : les cinq premières instructions
sont

```asm
xor    edi, edi      ; ruid = 0
xor    esi, esi      ; euid = 0
push   0x71          ; 113 = __NR_setreuid
pop    rax
syscall
```

### 5.3 Alors, c'est quoi l'exploit, de bout en bout ?

1. `foosc` lit le banner de `foosd` sur la socket. Il obtient :
   - `ids=0/1000` — euid/ruid (l'autodiagnostic SUID)
   - `stack=…` et `libc=…` — des pointeurs (les fuites ASLR)
   - `BUF=…` — l'adresse exacte du tampon qu'il s'apprête à faire déborder
2. Depuis le binaire cible (via `objdump`), il apprend `rip_off` et les
   adresses de `win()` / `win_root()`.
3. Depuis *sa propre* libc (via `/proc/self/maps` + `dlsym` + un scan mémoire),
   il mesure les offsets de `system`, `read`, `/bin/sh` et un gadget
   `pop rdi; ret` — rien n'est hardcodé.
4. Il assemble la payload. Pour `-t shellcode`, c'est :
   `[code setreuid+execve de 32 octets][bourrage jusqu'à RIP][ret-fix][adresse de buf]`.
5. Le `read()` de `foosd` déborde ; le `ret` atterrit sur la shellcode ; le
   noyau exécute `setreuid(0,0)` (pas de souci : euid 0 est privilégié) puis
   `execve` de `/bin/sh`. bash démarre avec `ruid == euid == 0` et reste root.
6. `foosc` relaie votre terminal vers ce shell root, jusqu'à ce que vous
   tapiez `exit`.

Un détail de commodité qui coûte cher à beaucoup de gens s'il est manqué :
l'exploit teste chaque comportement de nettoyage d'uid **sans** avoir besoin du
bit setuid au préalable. Lancez `make test` avant `make setuid`, et vous verrez
chaque technique atterrir un shell avec `ROOT=MISSING` ; lancez `make test-suid`
après `make setuid`, et `ROOT=SEEN` apparaît pour les deux techniques qui
nettolent l'uid réel. Ce A/B est toute la leçon, jouée en dix secondes.

---

## 6. Les vieux one-liners — et pourquoi la plupart sont morts

Si vous avez lu sur SUID, vous avez lu sur les détournements de `PATH`, sur
`LD_PRELOAD` et sur les shells setuid. Les trois sont classiques, et les trois
échouent sur un système moderne contre *ce programme*. Ça vaut le coup de
savoir exactement pourquoi, parce que les raisons sont les défenses que vous
avez gratuitement :

| Classe d'attaque | Vieille affirmation | Pourquoi elle échoue sur une machine moderne |
|--------------|-----------|------------------------------|
| `LD_PRELOAD` d'une bibliothèque malveillante | « Le programme setuid charge mon `.so` et exécute mon code en tant que root. » | Le noyau marque un binaire setuid comme **AT_SECURE** ; glibc ignore alors `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_DEBUG` et compagnie. L'environnement est traité comme *entrée non fiable*. `LD_PRELOAD` contre un binaire setuid est un no-op. |
| Détournement de `PATH` (`system("ls")` avec un PATH empoisonné) | « Pointez PATH vers un répertoire avec mon faux `ls` ; le programme root l'exécutera. » | Un autre visage de la même défense : un processus AT_SECURE reçoit un **PATH assaini** (une valeur sûre par défaut, grossièrement `/usr/local/bin:/usr/bin:/bin`) pour `system()`/`execvp`, donc le répertoire empoisonné n'est jamais consulté. |
| Injection de commande `system()` setuid | « La commande injectée s'exécute avec euid 0. » | `system()` exécute la commande dans un `/bin/sh` tout frais, et ce shell — §5.2 — réinitialise `euid = ruid` au démarrage. La commande injectée s'exécute avec l'uid *réel*. (C'est toujours un bug ; ça n'escalade juste plus via `/bin/sh`.) |
| Shell root setuid sur disque (`cp /bin/sh /tmp; chmod u+s`) | « Exécute-le, obtiens root. » | Exactement la défense ci-dessus, et c'est pourquoi les distros modernes ne livrent aucun shell root setuid. Même si vous réussissez à en fabriquer un, bash refuse de garder euid 0 sauf s'il est lancé avec `-p`. |

Ce qui reste vivant, et c'est ce lab : **le programme est *déjà* root quand il
tourne.** Vous n'avez besoin ni de l'environnement ni de `system()` ; vous avez
besoin que le programme exécute *votre* code (via un bug de corruption
mémoire) pendant qu'il est privilégié, et que votre code soit assez soigneux
pour corriger lui-même le mismatch d'uid — `setreuid(0,0)` — avant de vous
tendre un shell. Corruption mémoire + SUID est la combinaison qui finit encore
en `uid=0`, et c'est exactement pourquoi les langages sûrs en mémoire, les
canaries et les piles no-execute ne sont pas une décision de mode.

---

## 7. Les garde-fous intégrés au démon

`foosd` est volontairement le *pire* morceau de logiciel de ce dépôt, alors il
porte aussi le plus de garde-fous :

1. **Loopback seulement, imposé.** `foosd` refuse toute adresse de bind hors
   loopback, sauf si vous passez `-L`. Un listener setuid-root sur une vraie
   interface est un service root distant ; le refus est la valeur par défaut,
   pour que l'état dangereux doive être tapé délibérément.
2. **Autodiagnostic.** Au démarrage, il journalise `ruid`/`euid` et s'il
   tourne en root, pour que la console montre l'état dont dépend l'exploit.
3. **Le log n'atteint jamais le client.** Le démon réserve un descripteur de
   log privé avant que les sockets ne remplacent fd 1, pour que la sortie du
   crash-reporter et les chemins internes ne puissent pas être relus sur le
   fil par l'attaquant.
4. **Crash-reporter.** Un handler SIGSEGV journalise `RIP`/`RSP` — la valeur
   que l'attaquant a écrite dans l'adresse de retour — pour qu'une prise de
   contrôle réussie soit visible dans `foosd.log` au lieu d'être une mort
   silencieuse.
5. **`make unsetuid`.** Retirer le bit est scripté, parce que le laisser posé
   est le mode d'échec que les gens ont réellement.

---

## 8. Contre-mesures — ce que chacune arrête et ce qu'elle *n'arrête pas*

Appliquées à `foosd` via `make hardened`, une par une ou ensemble :

| Contre-mesure | Ce qu'elle arrête | Ce qu'elle *n'arrête pas* |
|------------|---------------|-------------------------|
| `-fstack-protector-strong` (canary) | Le débordement : `ret` détecte une canary écrasée et abort avant que l'adresse de l'attaquant soit utilisée. Arrête ici **les quatre** techniques — elles partagent le même `read()` vulnérable. | Rien par *conception* : le binaire est toujours setuid-root ; un autre bug (format-string-`%n`, heap-overflow, use-after-free) n'a pas de canary à déclencher. |
| `-fPIE -pie` (ASLR pour le binaire) | L'utilisation d'adresses `win()`/`win_root()` prévisibles (les techniques ret2win). | La technique shellcode, si une adresse de pile fuite encore (ligne `BUF=`). |
| `-z noexecstack` (NX / W^X) | La shellcode : le CPU refuse de chercher des instructions sur une page data-only, donc un saut vers `buf` est un SIGSEGV. | ROP — exécuter du code qui existe déjà (`ret2libc`). |
| Les trois ensemble | Un binaire difficile à déborder, randomisé, avec une pile non exécutable. Voilà à quoi ressemble une build durcie normale. | Le bit setuid. **Un binaire SUID durci reste un binaire SUID.** S'il survit un bug mémoire atteignable, c'est toujours « bug dans un processus root ». |

La preuve console, c'est `make test-hardened`, qui échange la build durcie et
montre les techniques mourir à la canary, pendant que `foosd_hardened.log`
capture `*** stack smashing detected ***`.

Deux contre-mesures de niveau conception, qu'aucun flag de compilateur ne
fournit, et que le lab principal (`food`) utilise aussi :

- **Moindre privilège.** Un démon pour un port non privilégié (2343 > 1024)
  n'a aucun besoin légitime de root. Un `foosd` correct lierait puis ferait
  `setgroups`/`setgid`/`setuid` vers un compte non privilégié et *confirmerait
  que ça a tenu* (la version correcte est dans la source sous le nom de
  `drop_privs()`, jamais appelée — le non-appel est le bug n° 3 du lab).
- **Limitez le read.** `n = read(fd, buf, sizeof(buf) - 1)`. Une ligne correcte
  surpasse tous les flags de compilateur du tableau.

---

## 9. Le protocole filaire (pour que vous puissiez lire le démon avec netcat)

```text
FOOSD 1.0 - deliberately vulnerable SUID service
Type 'quit' to disconnect. Buffer = 64 bytes, read accepts 512.
FOOSD 1.0 ids=0/1000 leak stack=0x7ffd... libc=0x7f...
BUF=0x7ffd...
```

* `ids=euid/ruid` — ne pouvait pas être affiché comme `euid=`/`ruid=`, parce
  que la harnesse de test prouve un shell en grepant le `uid=` littéral, et le
  banner ne doit pas le contenir (une sonde qui partage la signature de la
  réponse est un piège classique de faux positif ; voir le commentaire dans
  `foosd.c`). La harnesse exige en outre la forme stricte de sortie `id` —
  `uid=NNN(...)` — pour que rien de ce que le démon ou l'exploit affiche ne
  puisse satisfaire le contrôle par accident : le propre « target euid=… ruid=… »
  de `foosc` contient `uid=` comme sous-chaîne, ce qui a un jour fait
  rapporter à un test durci un shell qui n'avait jamais tourné.
* `stack=`, `libc=`, `BUF=` — les fuites ASLR : elles permettent à la
  shellcode et à ret2libc de calculer des adresses exactes.

---

## 10. Exercices

1. **Considérez la descente non-root.** Lancez `make test` *avant* `make
   setuid`, puis encore après. Expliquez le passage à `ROOT=SEEN` avec
   l'histoire ruid/euid de la §5.2.
2. **Lisez le crash.** Lancez `./foosc -t demo -n` puis lisez `foosd.log`.
   La ligne `RIP=0x4141414141414141` est le bourrage de l'attaquant — la
   preuve que c'est le débordement, pas le hasard, qui contrôle l'exécution.
3. **Ajoutez la canary.** `make hardened` et modifiez vous-même la boucle
   `test-hardened` ; la ligne de log `*** stack smashing detected ***` est la
   défense qui fonctionne.
4. **Désactivez la fuite.** Commentez la ligne `BUF=` dans `foosd.c`, recompilez
   et voyez `-t shellcode` passer de déterministe à jeu de devinettes. Cette
   seule ligne est la raison pour laquelle les vrais bypass d'ASLR sont tout un
   domaine.
5. **L'expérience `-p`.** Dans une copie de `win()`, changez `execl("/bin/sh",
   "sh", NULL)` en `execl("/bin/sh", "sh", "-p", NULL)` et observez root. `-p`
   est la sortie de secours documentée du gardien du shell — et la raison pour
   laquelle le conseil « spawn juste un shell » des vieux write-ups est
   incomplet.
6. **Pourquoi pas `setuid(0)` ?** Réécrivez la shellcode pour appeler
   `setuid(0)` au lieu de `setreuid(0,0)` (syscall 105). Le shell atterrit
   quand même — et retombe quand même à `uid=1000`. C'est l'expérience d'une
   seule ligne la plus instructive de tout le dépôt.

---

## 11. Sécurité et nettoyage

- Loopback uniquement, par défaut et par conception ; `-L` lie plus loin, et
  seule une VM bonne à jeter devrait même l'envisager.
- C'est un lab de shell root. Ne le faites pas tourner sur une machine qui
  compte, et ne pointez pas `foosc -h` vers quelque chose que vous ne possédez
  pas.
- Rituel de nettoyage : `make stop` puis `make unsetuid`, et si vous voulez
  l'arborescence impeccable à nouveau : `sudo make clean`.

```console
$ make stop
$ make unsetuid
```