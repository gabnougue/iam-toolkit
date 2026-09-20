# Audit IAM Active Directory — rapport d'exemple

> Ce rapport a été produit contre un domaine de laboratoire reproductible
> (`lab.local`), peuplé par `lab/seed-test-users.ps1`. Il ne contient aucune
> donnée client. Il illustre le format et la démarche d'un audit mené avec
> l'IAM Toolkit.

## 1. Synthèse

L'audit a porté sur le domaine `lab.local` : 31 comptes utilisateurs et 13 groupes
d'administration, interrogés en lecture seule par trois scripts PowerShell dont les
résultats ont ensuite été croisés.

Quatre écarts ont été retenus, dont un critique. Quatre comptes privilégiés — trois
comptes applicatifs et un compte d'administration historique — cumulent des droits
d'administration du domaine, un mot de passe qui n'expire jamais, et aucune
authentification depuis leur création. Le compte d'administration intégré, qui détient
l'ensemble des privilèges de la forêt, n'est pas dormant. Un rôle de direction porte un
privilège d'administration de l'annuaire sans besoin opérationnel. Enfin, cinq comptes
sans privilège ont également un mot de passe à durée illimitée.

Le risque principal tient en une phrase : la compromission d'un seul des quatre comptes
du premier finding suffit à donner le contrôle de l'ensemble du domaine. Deux d'entre
eux y parviennent par une voie indirecte — l'appartenance à `Backup Operators` permet de
lire la base de l'annuaire et d'en extraire la clé de signature des tickets Kerberos.
Ces quatre comptes sont donc à traiter en premier, avant toute autre remédiation.

## 2. Périmètre et méthode

**Domaine audité** : `lab.local`, forêt à domaine unique, un contrôleur de domaine,
niveau fonctionnel Windows Server 2016.

**Objets dans le périmètre** : 31 comptes utilisateurs répartis dans 6 unités
d'organisation, 13 groupes d'administration interrogés.

**Date d'exécution** : 12 septembre 2026.

**Outils** : trois scripts PowerShell de l'IAM Toolkit.

| Script | Ce qu'il interroge |
|---|---|
| `Get-InactiveUsers.ps1` | Comptes activés sans authentification récente ou jamais authentifiés |
| `Get-PrivilegedUsers.ps1` | Membres directs et imbriqués des groupes d'administration |
| `Get-PasswordNeverExpires.ps1` | Comptes portant le drapeau `DONT_EXPIRE_PASSWORD` |

Aucun de ces scripts ne modifie l'annuaire : ils lisent des attributs LDAP et
produisent des fichiers CSV.

Les trois rapports sont ensuite croisés sur le `SamAccountName`. Ce croisement
est le cœur de la démarche : un compte qui apparaît dans un seul rapport est
un écart de configuration, un compte qui apparaît dans plusieurs est un chemin
de compromission. C'est lui qui détermine la sévérité et l'ordre de priorité
des remédiations.

## 3. Synthèse des findings

| ID | Intitulé | Sévérité | Comptes |
|---|---|---|---|
| F-01 | Comptes privilégiés à mot de passe permanent, jamais authentifiés | Critique | 4 |
| F-02 | Compte d'administration intégré non dormant | Élevé | 1 |
| F-03 | Privilège d'administration d'annuaire sur un rôle métier | Moyen | 1 |
| F-04 | Mot de passe permanent sur des comptes non privilégiés | Faible | 5 |

## 4. Findings détaillés

### F-01 — Comptes privilégiés à mot de passe permanent, jamais authentifiés (Critique)

Quatre comptes apparaissent simultanément dans `privileged-users.csv` et
`password-never-expires.csv` : ils sont membres d'un groupe d'administration du
domaine et portent le drapeau `PasswordNeverExpires`. Le rapport
`inactive-users.csv` indique qu'aucun des quatre ne s'est authentifié depuis sa
création. Trois suivent une convention de nommage indiquant un usage applicatif
(`svc-*`), le quatrième est un compte d'administration historique.

| SamAccountName | Groupe | PasswordNeverExpires | Dernière authentification |
|---|---|---|---|
| `svc-backup` | Domain Admins | oui | jamais |
| `svc-legacy` | Domain Admins | oui | jamais |
| `svc-sql` | Backup Operators | oui | jamais |
| `sysadmin-legacy` | Backup Operators | oui | jamais |

Un compte applicatif conserve son secret dans un fichier de configuration, un
service ou une tâche planifiée. Ce secret est donc lisible par toute personne
ayant accès à ce support. Lui accorder des droits d'administration du domaine
revient à mettre l'annuaire à portée de ce support. Le drapeau
`PasswordNeverExpires` fige ce secret : celui qui a été posé à la création reste
valide indéfiniment, et la liste des personnes l'ayant connu n'est pas
reconstituable.

Deux de ces comptes sont membres de `Backup Operators`. Ce groupe confère le
privilège de sauvegarde sur les contrôleurs de domaine, lequel contourne les
listes de contrôle d'accès par conception. Il permet donc de lire `NTDS.dit`, la
base de l'annuaire, et d'en extraire le condensat du compte `krbtgt` — la clé qui
signe tous les tickets Kerberos du domaine. Quiconque la détient peut forger des
tickets valides pour n'importe quel utilisateur. `Backup Operators` équivaut donc
à `Domain Admins`, sous une forme moins visible.

L'absence totale d'authentification aggrave le constat plutôt qu'elle ne
l'atténue : aucun usage légitime n'est constaté, et une utilisation illégitime ne
serait remarquée par personne.

**Remédiation.** Déterminer d'abord si chacun de ces comptes sert encore ; ceux
dont l'usage n'est pas justifié sont à désactiver, ce qui ne coûte rien. Pour les
autres, migrer vers un compte de service géré par le domaine (gMSA) lorsque
l'application le permet : le mot de passe est alors généré, détenu et renouvelé
par Active Directory, sans intervention humaine. À défaut, remplacer
l'appartenance au groupe d'administration par la délégation la plus restreinte
qui permette le fonctionnement, retirer le drapeau `PasswordNeverExpires`, et
confier la rotation à un coffre-fort à secrets.

**Effort estimé** : de quelques heures pour une désactivation à plusieurs jours
par compte lorsqu'une dépendance applicative doit être identifiée et testée.

### F-02 — Compte d'administration intégré non dormant (Élevé)

Le compte `labadmin` est membre des cinq groupes d'administration de la forêt et
présente une authentification enregistrée.

| SamAccountName | Groupes |
|---|---|
| `labadmin` | Administrators, Domain Admins, Enterprise Admins, Schema Admins, Group Policy Creator Owners |

Un compte d'administration intégré doit rester dormant. Il constitue le moyen de
reprise en main de dernier recours, celui qui permet de rétablir l'accès quand
tout le reste a échoué, et son usage courant en annule la fonction. Toute
authentification sur ce compte signale qu'il est entré dans le périmètre
opérationnel.

Deux garanties disparaissent alors. La traçabilité individuelle d'abord :
plusieurs administrateurs partageant ce compte produisent des journaux
indiscernables, et aucune action ne peut être attribuée en cas d'incident. La
séparation des usages ensuite : la même session sert aux tâches courantes et aux
opérations les plus sensibles de la forêt, de sorte qu'une compromission de
poste de travail devient une compromission de forêt.

**Remédiation.** Créer un compte d'administration nommé pour chaque
administrateur et y transférer les appartenances aux groupes privilégiés. Traiter
ensuite le compte intégré comme un compte de reprise d'urgence : mot de passe
long, scellé, aucune utilisation courante, et alerte déclenchée à chaque
authentification — une règle de détection d'une ligne dans le SIEM suffit.

**Effort estimé** : quelques jours, proportionnel au nombre d'administrateurs à
équiper.

**Note.** Ce constat ne provient pas du jeu de données de test : il a été
découvert dans l'état réel du domaine.

### F-03 — Privilège d'administration d'annuaire sur un rôle métier (Moyen)

Le compte `aceo` — nom complet « Alex CEO », situé dans l'unité d'organisation
`Management` — est membre direct du groupe `Account Operators`.

| SamAccountName | Nom | OU | Groupe | Appartenance |
|---|---|---|---|---|
| `aceo` | Alex CEO | Management | Account Operators | Directe |

Le signal ici n'est pas le groupe lui-même, qui serait légitime pour un opérateur
du service informatique, mais l'écart entre un rôle métier et un droit
d'administration de l'annuaire.

`Account Operators` permet de créer des comptes et de modifier l'appartenance des
groupes non protégés. Ce n'est pas `Domain Admins`, d'où une sévérité moyenne,
mais cela suffit à ouvrir un chemin d'élévation : créer un compte, l'ajouter à un
groupe non protégé disposant d'une délégation ailleurs dans l'annuaire, puis
exploiter cette délégation. La plupart des annuaires anciens comportent de telles
délégations, accordées puis oubliées.

**Remédiation.** Révoquer l'appartenance, puis identifier la demande qui a conduit
à l'accorder et y répondre par une délégation ciblée sur le périmètre strictement
nécessaire. Sans ce second temps, le droit sera réaccordé par la même voie.

**Effort estimé** : quelques heures.

### F-04 — Mot de passe permanent sur des comptes non privilégiés (Faible)

Cinq comptes sans appartenance à un groupe d'administration portent le drapeau
`PasswordNeverExpires`.

| SamAccountName | OU | AdminCount |
|---|---|---|
| `alopez` | HR | — |
| `ccfo` | Management | — |
| `pkim` | Finance | — |
| `rmills` | IT | — |
| `svc-monitor` | Service Accounts | — |

Le défaut technique est le même qu'en F-01, sans le privilège : le secret a une
durée de vie illimitée et reste exploitable indéfiniment s'il fuit. Le risque est
borné par ce que chaque compte peut atteindre, d'où la sévérité faible.

`svc-monitor` mérite une mention à part : c'est un compte applicatif, donc le
raisonnement de F-01 s'y applique pour ce qui est du stockage du secret. Seule
l'absence de privilège en limite la portée.

**Remédiation.** Retirer le drapeau et documenter les rares cas où il serait
réellement justifié.

**Effort estimé** : quelques heures.

## 5. Limites de l'audit

**L'inactivité n'est pas mesurable sur ce périmètre.** Les 28 comptes activés
remontent tous comme jamais authentifiés, et tous ont été créés le même jour. Un
critère qui correspond à la totalité du périmètre ne discrimine rien : ce n'est
pas le signe d'un parc dormant, mais celui d'une donnée d'annuaire non
exploitable ici. L'inactivité réelle doit être établie à partir des événements
d'authentification collectés par le SIEM, et non des attributs d'annuaire. Ce
constat explique pourquoi aucun finding de ce rapport ne repose sur l'inactivité
seule.

**Les chemins d'attaque Kerberos ne sont pas couverts.** Délégations non
contraintes, délégation contrainte avec transition de protocole, délégation basée
sur les ressources et comptes exposant un SPN sont hors du périmètre de
l'outillage actuel. Cette couverture est prévue dans une itération ultérieure.

**Le domaine ne comporte qu'un contrôleur.** Aucun écart de réplication n'est donc
observable, et le mode `-AccurateMode` de `Get-InactiveUsers.ps1` n'apporte rien
sur ce périmètre.

**Les âges de mot de passe ne sont pas représentatifs.** L'attribut `pwdLastSet`
n'accepte que deux valeurs en écriture et ne peut pas être antidaté : la colonne
`PasswordAge` reflète la date de création du laboratoire, non un vieillissement
réel. Le raisonnement des findings porte sur le drapeau
`PasswordNeverExpires` lui-même, pas sur l'âge observé.

## Annexe A — Commandes exécutées

```powershell
.\scripts\powershell\Get-InactiveUsers.ps1 -IncludeNewlyCreated -OutputPath .\outputs\sample-results\inactive-users.csv
.\scripts\powershell\Get-PrivilegedUsers.ps1 -OutputPath .\outputs\sample-results\privileged-users.csv
.\scripts\powershell\Get-PasswordNeverExpires.ps1 -OutputPath .\outputs\sample-results\password-never-expires.csv
```

## Annexe B — Données brutes

Les trois fichiers CSV complets sont disponibles dans
[`outputs/sample-results/`](../outputs/sample-results/).