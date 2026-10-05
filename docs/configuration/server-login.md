# Se connecter au serveur / GUI du collecteur

Le mode `server` (autonome) et le mode `daemon` (SaaS) exposent tous les deux la même admin GUI et la même API REST sur le port `8443`. Les deux sont protégés par le **même mécanisme de login** : un jeton d'accès GUI (`gui-token`), pas un compte utilisateur/mot de passe. Ce document explique où trouver ce jeton, comment s'en servir, et les règles TLS qui s'appliquent dès que le serveur écoute au-delà de `127.0.0.1`.

> Pour démarrer le serveur lui-même : [standalone.md](../modes/standalone.md) (mode autonome) ou [saas-daemon.md](../modes/saas-daemon.md#local-gui-in-daemon-mode) (mode daemon, GUI optionnelle).

---

## 1. D'où vient le jeton

Le jeton n'est **jamais** un mot de passe choisi par l'admin - il est généré aléatoirement (32 octets, préfixé `etcsec_gt_`) au premier démarrage qui en a besoin, puis stocké **uniquement sous forme de hash SHA-256** sur disque (`gui-token.hash`). Le texte en clair n'est affiché qu'**une seule fois**, à sa création, via l'un de ces trois déclencheurs :

| Déclencheur | Où apparaît le jeton en clair |
|---|---|
| `etc-collector server` (premier démarrage, foreground ou service) | stdout (visible dans le terminal, ou capturé par `journalctl` sous systemd) **et** le fichier `<config-dir>/gui-token.firstrun` (0600) |
| `sudo etc-collector server enable` (mode daemon) | Affiché directement dans la sortie de la commande, à la fin de l'assistant |
| `etc-collector gui-token reset` | Affiché directement dans la sortie de la commande |

`<config-dir>` est le répertoire contenant `config.yaml` (par défaut `/etc/etc-collector/`, ou `--config-dir`/`ETCSEC_CONFIG_DIR`).

> **Précision (rejoué le 2026-09-08)** : le flag `--config-dir` n'existe que sur `server` et
> `daemon` (`etc-collector server --help` le liste, `etc-collector gui-token reset --help` non -
> confirmé en direct : `--config-dir` y échoue avec `unknown flag`). Pour pointer `gui-token reset`
> (ou toute autre sous-commande hors `server`/`daemon`) vers un répertoire non standard, utilisez la
> variable d'environnement `ETCSEC_CONFIG_DIR` - celle-là fonctionne partout, confirmée en direct.

> **Contexte headless (service Windows, pas de console attachée)** : le jeton n'est visible nulle part ailleurs que dans `gui-token.firstrun` - lisez ce fichier une fois, notez le jeton en lieu sûr, puis supprimez-le (il n'est pas nécessaire au fonctionnement du collecteur). Le jeton n'apparaît **jamais** dans `collector.log` - c'est volontaire : ce fichier est aussi accessible à distance via la commande SaaS `GET_LOGS`, donc l'y écrire reviendrait à l'exposer à quiconque a accès au canal cloud du collecteur.

Si aucun jeton n'existe encore (nouvelle installation), il est généré automatiquement au premier démarrage du serveur - vous n'avez rien à faire de spécial pour l'obtenir la première fois, juste à lire la sortie de la commande.

---

## 2. Se connecter depuis le navigateur

1. Ouvrez l'URL affichée au démarrage (voir §3 pour `http://` vs `https://`) :
   ```
   http://127.0.0.1:8443
   ```
2. L'écran de login demande le **jeton d'accès** (pas un couple identifiant/mot de passe) - collez la valeur `etcsec_gt_...` récupérée au §1.
3. Le navigateur vérifie le jeton via `POST /api/v1/auth/gui-token/verify`, puis le conserve dans le `localStorage` du navigateur (`etc-gui-token`) - il est renvoyé sur chaque appel API suivant via l'en-tête `X-GUI-Token`. Rien n'est stocké côté serveur au-delà du hash déjà présent sur disque.
4. Se déconnecter (bouton logout de la GUI) efface simplement cette entrée `localStorage` - le jeton reste valide côté serveur tant qu'il n'a pas été réinitialisé (§5).

---

## 3. `--host` et TLS - ce qui est obligatoire

| Configuration | Comportement |
|---|---|
| `--host 127.0.0.1` (défaut) | `http://` suffit - trafic local uniquement, jamais sur le réseau |
| `--host 0.0.0.0` (ou toute IP non-loopback) | **TLS devient obligatoire.** Si `server.tlsCertFile`/`tlsKeyFile` ne sont pas configurés, un certificat auto-signé "bootstrap" est généré automatiquement et la GUI bascule en `https://` (le navigateur affichera un avertissement - normal, ce n'est pas un cert signé par une autorité publique) |
| `--allow-insecure-http` + host non-loopback | Force `http://` en clair malgré l'exposition réseau. Chaque requête servie ainsi est journalisée en warning - **le jeton circule alors sans chiffrement**, à réserver aux réseaux de confiance déjà isolés (VPN, réseau d'audit dédié) |

Confirmé en conditions réelles (conteneur jetable, v3.2.0, 2026-09-02) : `etc-collector server --host 0.0.0.0 --port 8443` journalise `Admin server is bound to a non-loopback interface with no certificate configured - generated a bootstrap self-signed one` ; `curl http://127.0.0.1:8443/health` répond alors `400 Client sent an HTTP request to an HTTPS server`, tandis que `curl -k https://127.0.0.1:8443/health` répond `200 {"status":"ok",...}`.

En mode daemon, l'équivalent est `--gui-host`/`--gui-allow-insecure-http` - mêmes règles, voir [saas-daemon.md](../modes/saas-daemon.md#enable-the-gui).

---

## 4. Générer un jeton API pour l'automatisation (CI/CD, SIEM)

Le jeton GUI ouvre la session dans le navigateur, mais pour un script/pipeline, échangez-le contre un **JWT** à durée de vie choisie via `POST /api/v1/auth/token` :

```bash
curl -X POST http://localhost:8443/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -H "X-GUI-Token: etcsec_gt_..." \
  -d '{"service":"ci","duration":"1h"}'
```

Réponse :
```json
{"token": "eyJhbGciOi...", "expiresAt": "2026-09-08T15:00:00Z"}
```

Utilisez ensuite ce jeton en `Authorization: Bearer <token>` sur `/api/v1/*` :

```bash
TOKEN=$(curl -s -X POST http://localhost:8443/api/v1/auth/token \
  -H "X-GUI-Token: $GUI_TOKEN" \
  -d '{"service":"ci","duration":"1h"}' | jq -r .token)

curl -s -X POST http://localhost:8443/api/v1/audit/ad \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"includeDetails":false}' > audit-results.json
```

Seuls deux champs sont acceptés dans le corps de la requête : `service` (libre, pour vos logs) et `duration` (`"1h"`, `"24h"`, `"30d"`, ...). Si vous omettez `duration`, la durée retenue est `auth.tokenLifetime` (config.yaml) quand elle est configurée, sinon `24h` par défaut - voir les subtilités de cette valeur selon le mode d'exécution dans [README.md](README.md#full-configuration-reference). Un champ `maxUses` a existé côté GUI mais n'a jamais été appliqué côté serveur - un JWT émis ici reste valable pour un nombre illimité d'appels jusqu'à son expiration, quelle que soit la valeur que vous passeriez.

---

## 5. Perdu le jeton / le réinitialiser

```bash
etc-collector gui-token reset
```

Affiche un nouveau jeton **une seule fois** et remplace le hash stocké sur disque immédiatement.

- **Mode `daemon`** : le hash est rechargé depuis le disque à chaque requête - le nouveau jeton est actif immédiatement, aucun redémarrage nécessaire.
- **Mode `server` (autonome) et service Windows** : le hash n'est chargé qu'au démarrage - **redémarrage du service requis** pour que le nouveau jeton prenne effet (`sudo systemctl restart etcsec-collector` sur Linux, ou l'équivalent Windows).

---

## 6. Erreurs de login courantes

Sur l'écran de login lui-même, un mauvais jeton ne renvoie jamais d'erreur HTTP visible - juste le message **"Invalid access token"** dans l'interface. Les codes ci-dessous apparaissent quand un jeton est présenté directement à un endpoint protégé (§4, scripts d'automatisation, ou la GUI après une session déjà ouverte) :

| Réponse API | Cause | Fix |
|---|---|---|
| `401 gui_token_not_configured` | Aucun jeton n'existe encore sur ce serveur (ne devrait pas arriver en pratique - un jeton est généré au premier démarrage) | `etc-collector gui-token reset` |
| `401 gui_token_required` | En-tête `X-GUI-Token` absent de la requête | Vérifiez que le script envoie bien l'en-tête (ou relogin si le `localStorage` du navigateur a été vidé) |
| `401 gui_token_invalid` | Jeton présent mais ne correspond pas au hash stocké | Jeton mal copié, ou réinitialisé depuis (§5) - récupérez la valeur actuelle |
| "Invalid access token" sur l'écran de login | Jeton copié avec un espace/retour à la ligne en trop, ou déjà réinitialisé | Recopiez sans espace de fin - le jeton fait exactement 74 caractères (`etcsec_gt_` + 64 caractères hexadécimaux) |

---

## Voir aussi

- [standalone.md](../modes/standalone.md) - démarrer le serveur en mode autonome, cas d'usage
- [saas-daemon.md](../modes/saas-daemon.md#local-gui-in-daemon-mode) - activer/désactiver la GUI locale en mode daemon (`server enable`/`disable`)
- [environment-variables.md](environment-variables.md) - `auth.tokenLifetime` et les variables liées
- [API.md](../API.md) - référence complète de l'API REST
