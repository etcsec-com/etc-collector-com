# Consentement de collecte - refuser une capacité

Le collecteur est agentless et bas-privilège par défaut : il lit l'annuaire par LDAP et
les fichiers de stratégie de groupe sur le partage `SYSVOL` (`ldap` et `sysvol`), deux
accès que n'importe quel utilisateur de domaine authentifié possède déjà. Au-delà de
cette base, certains contrôles ont besoin de plus - par exemple lire le registre d'un
contrôleur de domaine (`remote_registry`) - et cette collecte-là n'est jamais faite
sans un consentement explicite de l'opérateur.

Ce document couvre le chemin inverse : **refuser** une capacité, y compris une capacité
de base comme `sysvol`.

---

## Les trois entrées

| Entrée | Où | Portée |
|---|---|---|
| `audit.refusedCapabilities` | `config.yaml` | Écrit une fois, s'applique à tous les audits suivants |
| `audit.grantedCapabilities` | `config.yaml` | Escalades au-delà de la base agentless - pas de flag CLI équivalent |
| `--refuse-capability` | flag CLI, répétable | S'ajoute aux refus du fichier pour ce run ; ne lève jamais un refus déjà écrit |

Capacités connues : `sysvol` (lecture SYSVOL, base) et `remote_registry` (lecture du
registre d'un hôte distant, escalade). `ldap` n'est pas refusable - le refuser ne
laisserait rien à auditer (`internal/audit/capability.go`).

```yaml
audit:
  refusedCapabilities:
    - sysvol
  grantedCapabilities:
    - remote_registry
```

Testé : ce fragment est accepté tel quel par `etc-collector audit ad --config
config.yaml` (l'exécution échoue ensuite sur la connexion LDAP si le DC n'est pas
joignable, ce qui prouve que le fichier a bien été lu et parsé, pas rejeté).

```bash
etc-collector audit ad ... --refuse-capability sysvol
```

```
$ etc-collector audit ad --help
...
      --refuse-capability strings  Refuse a collection capability for this run,
                                    e.g. --refuse-capability sysvol. Adds to
                                    audit.refusedCapabilities from the config
                                    file and never lifts it. [...]
                                    Refusable: sysvol, remote_registry.
```

`--refuse-capability` est un flag persistant sur `audit` : il est disponible sur
`audit ad` et toutes les autres sous-commandes `audit`.

---

## Ce que "refuser" veut dire

### 1. Un refus arrête la COLLECTE, pas seulement l'analyse

Le partage n'est pas lu - il n'est même pas ouvert. Mesuré sur un contrôleur de domaine
réel : `--refuse-capability sysvol` ne produit aucune connexion SMB vers le DC. C'est la
différence entre « le collecteur ignore la donnée après l'avoir lue » et « le collecteur
ne va pas la chercher », et c'est celle-là qui permet à l'opérateur de vérifier
lui-même ce qui a quitté son réseau.

### 2. Le refus l'emporte toujours

Sur la base agentless (`sysvol`), et sur toute autorisation accordée ailleurs (un refus
peut retirer une capacité que `grantedCapabilities` venait d'accorder). L'ordre des
entrées dans les deux listes ne change rien : le moteur construit d'abord la base +
les accords, puis retire les refus en dernier
(`newConsentGateWithDenials`, `internal/audit/capability.go`). Aucune configuration
ultérieure ne peut donc réactiver par accident ce qui a été exclu.

### 3. Un résultat absent se lit NON ÉVALUÉ, jamais comme conforme

Un refus produit un avertissement explicite dans le rapport plutôt qu'un résultat plus
petit et silencieux :

```json
{
  "code": "CAPABILITY_REFUSED_SYSVOL",
  "message": "SYSVOL collection was refused in the configuration - no Group Policy file was read. Any detector whose verdict depends on Group Policy content has nothing to work from in this audit: read its result as UNKNOWN, not as clean."
}
```

Cet avertissement apparaît **que le fournisseur SYSVOL soit configuré ou non** - le
refus n'a pas besoin d'un provider câblé pour être signalé. Un contrôle dont le
verdict dépend du contenu SYSVOL n'a rien à analyser dans cet audit : traitez son
résultat comme NON ÉVALUÉ, jamais comme une conformité constatée.

---

## Limite actuelle

Le refus arrête la collecte, comme décrit ci-dessus. Il n'exclut **pas encore** les
détecteurs concernés de la sélection : la table qui déclarerait « ce détecteur dépend
de cette capacité » (`detectorCapability` dans `internal/audit/capability.go`) est
vide aujourd'hui. Ces détecteurs tournent donc quand même, sur une donnée absente, et
l'avertissement ci-dessus est aujourd'hui la seule garantie que ce fait ne passe pas
inaperçu - la documentation ne promet rien de plus.

`remote_registry` suit la même mécanique de consentement (refusable, accordable), mais
aucune collecte de registre distant n'existe encore dans le code à ce jour : le
refuser ou l'accorder n'a donc pas d'effet observable pour l'instant.

---

## Pas de variable d'environnement

`audit.refusedCapabilities` et `audit.grantedCapabilities` n'ont pas d'équivalent en
variable d'environnement, contrairement aux clés `audit.scope.*` (voir
[environment-variables.md](environment-variables.md)). Seuls le fichier `config.yaml`
et, pour le refus, le flag `--refuse-capability`, permettent de les régler.

---

## Voir aussi

- [permissions.md](permissions.md) - ce que la base agentless (`ldap` + `sysvol`) lit par défaut
- [audit-scope.md](audit-scope.md) - quels détecteurs tournent (indépendant du consentement de collecte)
