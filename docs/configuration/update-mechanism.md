# Update mechanism — comment fonctionne `UPDATE_COLLECTOR`

À partir de **v3.0.23**, le collecteur se met à jour en **exec en place** sur Unix (Linux/macOS) au lieu du fork-watcher historique. Cette page explique pourquoi, le nouveau layout binaire et la procédure de migration depuis v3.0.22 et antérieures.

> Pour la commande SaaS elle-même (payload, codes d'erreur) : pas encore documentée séparément dans `public/docs/` — voir [`docs/API.md`](../API.md) pour la référence REST en attendant.

---

## TL;DR

- **Nouveau layout (Unix)** : binaire réel sous `/var/lib/etc-collector/bin/etc-collector`, symlink `/usr/local/bin/etc-collector` pour le PATH
- **Update Unix** : `syscall.Exec()` remplace l'image du process — même PID, systemd ne voit pas d'exit, pas de boucle
- **Update Windows** : pattern fork-watcher inchangé (Windows ne peut pas remplacer un .exe en cours)
- **Migration depuis v3.0.22** : `sudo etc-collector install --upgrade` (idempotent)

---

## Pourquoi ce changement (le bug v3.0.22 et antérieures)

Sur Linux, l'unit systemd shippé applique :
- `ProtectSystem=strict` + `ReadWritePaths=/etc/etc-collector /var/lib/etc-collector`
- `KillMode=control-group` (défaut) — quand le main PID exit, **systemd kill tous les enfants du cgroup**

Le pattern v3.0.22 :

1. Daemon télécharge + extrait nouveau binaire dans `/var/lib/etc-collector/update-staging/`
2. Daemon fork un **watcher** détaché (process enfant)
3. Daemon exit pour libérer le binaire
4. Watcher attend l'exit, fait `rename(/usr/local/bin/etc-collector, .bak)` puis copie le nouveau

**Deux problèmes** :
- À l'étape 3, `KillMode=control-group` tue le watcher en même temps que le daemon
- Même si le watcher survivait (via `systemd-run --scope`), `/usr/local/bin` n'est pas dans `ReadWritePaths` → `EROFS`

Conséquence observée sur dock-04 : le binaire ne change jamais, systemd relance le daemon (Restart=always), le SaaS repush UPDATE_COLLECTOR, **boucle infinie** (compteur de restart=226).

---

## La nouvelle architecture (v3.0.23+)

### Layout binaire

```
/var/lib/etc-collector/                 ← ReadWritePaths (writable)
├── bin/
│   ├── etc-collector                   ← REAL binary (writable, executable)
│   └── etc-collector.bak               ← Backup créé à chaque update (rollback)
├── credentials.json
└── update-staging/                     ← Téléchargements temporaires

/usr/local/bin/etc-collector            ← Symlink → /var/lib/etc-collector/bin/etc-collector
                                          (juste pour le PATH des admins)
```

`os.Executable()` retourne le chemin réel (résout le symlink), donc le daemon sait qu'il tourne depuis `/var/lib/etc-collector/bin/`.

L'unit systemd a `ExecStart=/var/lib/etc-collector/bin/etc-collector daemon ...` — pas de symlink à résoudre côté systemd, pas de surprise.

### Flow d'update Unix

```
[daemon v3.0.23 reçoit UPDATE_COLLECTOR vers v3.0.24]

1. Download + checksum + extract → /var/lib/etc-collector/update-staging/etc-collector
2. SUBMIT SUCCESS au SaaS (synchrone, attend HTTP 200)
   ─ CRITIQUE : après syscall.Exec on n'a plus de socket
3. Cleanup PID file + write clean-shutdown marker
4. rename(/var/lib/.../bin/etc-collector, /var/lib/.../bin/etc-collector.bak)
   ─ Marche même si le binaire est en cours d'exécution (inode magic Linux)
5. rename(staging/etc-collector, /var/lib/.../bin/etc-collector)
6. chmod 0755
7. syscall.Exec(/var/lib/.../bin/etc-collector, os.Args, os.Environ())
   ─ Le kernel remplace l'image du process. PID identique.
   ─ systemd ne voit AUCUN événement exit. Pas de Restart=always trigger.
   ─ Pas d'incrémentation du restart counter.
8. Le nouveau binaire démarre, lit credentials.json, repolle le SaaS.
```

Si `syscall.Exec` échoue (binaire corrompu, EPERM…), le daemon **rollback automatiquement** le `.bak` et exit avec code 1. systemd redémarre alors la version précédente.

### Flow d'update Windows

Inchangé vs v3.0.22 — Windows ne peut pas renommer un `.exe` en cours d'exécution dans le même process. Le watcher détaché reste nécessaire :

1. Download + checksum + extract dans staging
2. Fork watcher (`etc-collector update watch ...`)
3. Submit SUCCESS au SaaS
4. Daemon exit → SCM marque STOPPED
5. Watcher attend, rename, copie, démarre le service

Windows n'a pas le bug systemd, ce flow marche.

---

## Migration depuis v3.0.22 ou antérieures

### Sur un collecteur existant

Le binaire actuel est probablement à `/usr/local/bin/etc-collector` (fichier réel). Pour migrer :

```bash
# SSH sur le collecteur, puis :
sudo /usr/local/bin/etc-collector install --upgrade
```

La commande `install --upgrade` est **idempotente** :
1. Détecte si `/usr/local/bin/etc-collector` est un fichier réel ou un symlink
2. Si fichier réel → le déplace vers `/var/lib/etc-collector/bin/etc-collector`, crée le symlink, réécrit le unit systemd, `daemon-reload` + `restart`
3. Si déjà un symlink correct → no-op (juste un message "already correct")

Sortie attendue :

```
Migrating ETC Collector to v3.0.23+ layout...
  Real binary target:  /var/lib/etc-collector/bin/etc-collector
  Symlink:             /usr/local/bin/etc-collector
  Detected legacy install at /usr/local/bin/etc-collector, migrating...
  [OK] Binary moved + symlink created
  [OK] Service unit rewritten
  [OK] Service restarted with new layout

Migration complete. Future UPDATE_COLLECTOR commands will use in-place exec.
```

### Vérifications post-migration

```bash
# Le binaire est maintenant un symlink
ls -la /usr/local/bin/etc-collector
# → lrwxrwxrwx ... /usr/local/bin/etc-collector -> /var/lib/etc-collector/bin/etc-collector

# Le unit systemd pointe vers le vrai chemin
grep ExecStart /etc/systemd/system/etcsec-collector.service
# → ExecStart=/var/lib/etc-collector/bin/etc-collector daemon --config-dir /etc/etc-collector

# Le service tourne, restart counter = 0
systemctl status etcsec-collector

# Le binaire répond
etc-collector --version
# → etc-collector version 3.0.23 (pro)
```

### Avertissement automatique au boot

Si le daemon démarre depuis `/usr/local/bin/etc-collector` (fichier réel, layout legacy), il logue un WARN au boot :

```
WARN  Legacy install layout detected — UPDATE_COLLECTOR will likely fail
      under systemd hardening. Run 'sudo etc-collector install --upgrade'
      to migrate the binary to the writable layout.
```

Le daemon continue de tourner — le warning n'est pas fatal. Mais tant que la migration n'est pas faite, **UPDATE_COLLECTOR boucleront** comme en v3.0.22.

---

## Migration depuis une ancienne version

Pour les nouveaux deploys (collecteur jamais installé) :
```bash
read -rsp 'Enrollment token: ' TOKEN && echo
sudo ETCSEC_ENROLL_TOKEN="$TOKEN" ./etc-collector install --saas-url https://api.etcsec.com
unset TOKEN
```
L'installeur place le binaire au bon layout d'office. Le jeton passe par
l'environnement plutôt que par la ligne de commande, où il serait visible dans
`ps` et conservé dans l'historique du shell.

---

## Diagnostic en cas d'échec

### Symptôme : le restart counter monte

```bash
systemctl status etcsec-collector | grep Restart
# Restart=always   ← OK
# ... (Restart counter: 226)   ← BUG — voir layout legacy
```

→ Probable layout legacy non migré. Faire `install --upgrade`.

### Symptôme : `journalctl` montre "syscall.Exec" failed

```
ERROR In-place swap failed, exiting so systemd restarts the old version  error="syscall.Exec: ..."
```

→ Binaire corrompu (checksum OK mais ELF cassé) ou permissions wrong. Le rollback automatique a remis le `.bak` en place. Vérifier :

```bash
file /var/lib/etc-collector/bin/etc-collector       # ELF 64-bit ?
ls -la /var/lib/etc-collector/bin/etc-collector*    # mode 0755 ?
```

### Symptôme : le SaaS marque la commande `success` mais le binaire ne change pas

→ Probablement encore en v3.0.22 layout. Le SUBMIT SUCCESS partait avant le swap, donc le SaaS croyait que ça avait marché. **C'est exactement le bug que v3.0.23 fixe** — la nouvelle version submit success après le swap, juste avant `syscall.Exec` (et seulement si le swap a réussi).

### Logs utiles

```bash
# Logs daemon
journalctl -u etcsec-collector -n 200 --no-pager

# Logs du watcher (Windows uniquement, ou Unix legacy si jamais)
cat /var/lib/etc-collector/bin/update.log  # Unix v3.0.23+
cat 'C:\Program Files\ETCSec\update.log'   # Windows
```

---

## Désinstallation

`etc-collector uninstall` v3.0.23+ retire :
- Le binaire réel sous `/var/lib/etc-collector/bin/`
- Le symlink `/usr/local/bin/etc-collector`
- Le `.bak` éventuel
- Le unit systemd
- (Avec `--purge`) `/etc/etc-collector` et `/var/lib/etc-collector`

Pas de résidu.

---

## Upgrade manuel via la CLI (v3.1.15+)

À partir de **v3.1.15**, `etc-collector upgrade` permet de remplacer le binaire **sans passer par le SaaS**. Contrairement à `UPDATE_COLLECTOR` (qui s'auto-modifie depuis le daemon en cours), la CLI tourne **out-of-process** : un binaire indépendant fait le swap, donc ça marche même quand la version installée est cassée.

> ⚠️ **`get.etcsec.com` ne sert rien aujourd'hui (2026-09-02).** Testé en direct sur
> v3.2.0 : `etc-collector upgrade --check` échoue avec
> `[UPGRADE_NETWORK_UNREACHABLE]` (le manifest par défaut,
> `https://get.etcsec.com/downloads/manifest.json`, répond 404), et
> `/install.sh` répond 403. La procédure de secours ci-dessous, telle
> qu'écrite, échoue donc **dès sa première commande** (`curl` sur
> `get.etcsec.com` → 404). Le **mécanisme d'upgrade lui-même n'est pas en
> cause** — validé en pointant `--manifest-url`/`--download-url` vers un
> manifeste au bon schéma servi depuis de vrais checksums v3.2.0. Ce qui est
> cassé, c'est uniquement l'hébergement `get.etcsec.com` (domaine mort) — un
> arbitrage est en cours côté Fondateur pour décider s'il est réactivé ou
> remplacé par les assets GitHub Releases ; **non tranché ici**. En
> attendant, utilisez `--manifest-url`/`--download-url` (ou téléchargez
> depuis [GitHub Releases](https://github.com/etcsec-com/etc-collector-com/releases)
> et pointez `--target`) plutôt que les valeurs par défaut.

### Cas d'usage typiques

```bash
# Upgrade vers la dernière version publiée (nécessite get.etcsec.com — voir avertissement ci-dessus)
sudo etc-collector upgrade

# Cibler une version précise (idem)
sudo etc-collector upgrade --version 3.1.15

# Vérifier sans rien changer (idem — échoue tant que get.etcsec.com est mort)
etc-collector upgrade --check

# Restaurer la version précédente (depuis <target>.bak) — ne dépend pas du réseau
sudo etc-collector upgrade --rollback

# Dry-run : afficher ce qui se passerait sans modifier (idem, dépend du manifest)
sudo etc-collector upgrade --dry-run --version 3.1.15
```

### Quand un host est bloqué (release cassée)

Si un host tourne une version où `UPDATE_COLLECTOR` est cassé (ex : v3.1.12 et le bug d'in-place swap), aucun ordre SaaS ne peut le sauver — c'est précisément le code cassé qui devrait faire le swap. Procédure de récupération — **en remplaçant l'URL `get.etcsec.com` ci-dessous par un binaire obtenu via [GitHub Releases](https://github.com/etcsec-com/etc-collector-com/releases/latest)**, tant que l'arbitrage d'hébergement n'est pas tranché :

```bash
# 1. Récupérer un binaire frais sur le host — get.etcsec.com est mort (404),
#    substituer l'URL de l'asset GitHub Releases correspondant :
curl -fsSL https://github.com/etcsec-com/etc-collector-com/releases/download/v3.1.15/etc-collector-3.1.15-linux-amd64.tar.gz \
  | tar xz -C /tmp

# 2. Lancer la CLI upgrade depuis ce binaire frais, en ciblant le binaire cassé
sudo /tmp/etc-collector upgrade \
  --target /var/lib/etc-collector/bin/etc-collector
```

Le binaire `/tmp/etc-collector` ne touche jamais à lui-même : il télécharge la version cible (ou utilise `--download-url`), vérifie le checksum SHA-256, stoppe `etcsec-collector`, sauvegarde l'ancien binaire en `.bak`, fait le swap atomique, redémarre le service, fait un health-check, et auto-rollback si le service ne démarre pas.

### Codes d'erreur structurés

Comme pour `LDAP_*` en v3.1.12, chaque échec d'upgrade retourne un **code stable** + une remédiation actionnable. La SaaS UI peut router sur le code sans parser de texte libre.

| Code | Quand | Que faire |
|---|---|---|
| `UPGRADE_DISK_INSUFFICIENT` | < 200 MB libres sur le FS du binaire | `rm /var/lib/etc-collector/bin/*.bak-*` ou `journalctl --vacuum-size=500M` |
| `UPGRADE_TMP_INSUFFICIENT` | < 100 MB libres sur `/tmp` | `find /tmp -type f -mtime +7 -delete` |
| `UPGRADE_PERMISSION_DENIED` | Pas writable sur la cible | Re-lancer avec `sudo` |
| `UPGRADE_NETWORK_UNREACHABLE` | Manifest ou download URL inaccessible | Vérifier réseau / `HTTPS_PROXY` |
| `UPGRADE_VERSION_NOT_FOUND` | La version demandée n'est pas dans le manifest | Liste affichée dans le message ; ou `--version latest` |
| `UPGRADE_CHECKSUM_MISMATCH` | SHA-256 calculé ≠ attendu | Re-télécharger ; si persistant, ticket sécurité |
| `UPGRADE_BINARY_INVALID` | Le binaire téléchargé n'exécute pas `--version` | Vérifier OS/arch ; re-télécharger |
| `UPGRADE_BACKUP_FAILED` | `cp <target> <target>.bak` a échoué | Libérer de l'espace puis re-lancer |
| `UPGRADE_REPLACE_FAILED` | Rename atomique a échoué | Vérifier permissions |
| `UPGRADE_SERVICE_STOP_FAILED` | systemctl stop / SCM stop a planté | Stopper manuellement, re-lancer avec `--no-restart` |
| `UPGRADE_HEALTHCHECK_FAILED` | Service ne devient pas actif après start | Auto-rollback effectué ; `journalctl -u etcsec-collector -n 50` |
| `UPGRADE_ROLLBACK_NOT_AVAILABLE` | `--rollback` mais pas de `.bak` | Re-installer manuellement avec `--version <X>` |
| `UPGRADE_LOCK_HELD` | Une autre opération upgrade est en cours | Attendre, ou supprimer le lock si stale |
| `UPGRADE_ALREADY_AT_VERSION` | current == target | (success, exit 0) |

### Cross-platform

`etc-collector upgrade` marche identiquement sur Linux (systemd), macOS (launchd) et Windows (SCM). La différence avec le `UPDATE_COLLECTOR` SaaS (qui utilise un fork-watcher sur Windows pour contourner le file lock) : la CLI étant out-of-process, elle peut simplement `Stop-Service` → swap → `Start-Service` partout — pas de dance de watcher.

---

## Dedup persisté des commandes (v3.1.15+)

Avant **v3.1.15**, le daemon dédupliquait les commandes SaaS via une `map[string]time.Time` en mémoire. Conséquence : un crash + restart vidait la map, et le daemon re-exécutait la même commande à chaque boot — boucle infinie de crash si la commande elle-même est ce qui crashe.

À partir de v3.1.15 :

- L'état de dédup est persisté dans `/var/lib/etc-collector/state/executed-commands.json`
- Une commande est **réservée AVANT exec**, pas après — un crash mid-exec laisse quand même un marqueur, donc le restart suivant skip la commande
- Cleanup automatique des entrées > 6h (le SaaS a une TTL plus courte côté queue, donc 6h laisse de la marge)

Format on-disk (lisible humainement pour le diagnostic) :

```json
{
  "executed": [
    {
      "id": "fad5e2e8-95b3-45a0-916d-b5628569004c",
      "type": "UPDATE_COLLECTOR",
      "started_at": "2026-04-27T18:45:18Z",
      "completed_at": "2026-04-27T18:45:23Z",
      "status": "done"
    }
  ]
}
```

En cas de besoin, supprimer le fichier réinitialise la dédup (la prochaine commande sera exécutée).
