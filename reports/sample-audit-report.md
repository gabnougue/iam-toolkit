# Audit IAM Active Directory — rapport d'exemple

> Ce rapport a été produit contre un domaine de laboratoire reproductible
> (`lab.local`), peuplé par `lab/seed-test-users.ps1`. Il ne contient aucune
> donnée client. Il illustre le format et la démarche d'un audit mené avec
> l'IAM Toolkit.

## 1. Synthèse

L'audit a porté sur le domaine `lab.local` : 35 comptes utilisateurs, dont 32
activés, et 13 groupes d'administration, interrogés en lecture seule par quatre
scripts PowerShell dont les résultats ont ensuite été croisés.

Cinq écarts ont été retenus, dont un critique. Quatre comptes privilégiés — trois
comptes applicatifs et un compte d'administration historique — cumulent des droits
d'administration du domaine, un mot de passe qui n'expire jamais, et aucune
authentification depuis leur création. L'un d'eux, `svc-backup`, est en outre exposé
au Kerberoasting : n'importe quel utilisateur du domaine peut obtenir un ticket
chiffré avec son mot de passe et le casser hors ligne. Le compte d'administration
intégré, qui détient l'ensemble des privilèges de la forêt, n'est pas dormant. Un rôle
de direction porte un privilège d'administration de l'annuaire sans besoin
opérationnel. Quatre comptes de service sans privilège sont exposés au même
Kerberoasting, trois d'entre eux avec un chiffrement faible ou non configuré. Enfin,
cinq comptes sans privilège ont un mot de passe à durée illimitée.

Le risque principal tient en une phrase : la compromission d'un seul des quatre comptes
du premier finding suffit à donner le contrôle de l'ensemble du domaine. Deux d'entre
eux y parviennent par une voie indirecte — l'appartenance à `Backup Operators` permet de
lire la base de l'annuaire et d'en extraire la clé de signature des tickets Kerberos.
Pour `svc-backup`, la compromission n'exige même pas d'accès préalable particulier : un
compte ordinaire du domaine suffit pour lancer l'attaque, et la demande de ticket se
confond avec le trafic Kerberos légitime. Ces quatre comptes sont donc à traiter en
premier, `svc-backup` en tête, avant toute autre remédiation.

## 2. Périmètre et méthode

**Domaine audité** : `lab.local`, forêt à domaine unique, un contrôleur de domaine,
niveau fonctionnel Windows Server 2016.

**Objets dans le périmètre** : 35 comptes utilisateurs, dont 32 activés, répartis
dans 6 unités d'organisation ; 13 groupes d'administration interrogés.

**Date d'exécution** : 27 novembre 2026.

**Outils** : quatre scripts PowerShell de l'IAM Toolkit.

| Script | Ce qu'il interroge |
|---|---|
| `Get-InactiveUsers.ps1` | Comptes activés sans authentification récente ou jamais authentifiés |
| `Get-PrivilegedUsers.ps1` | Membres directs et imbriqués des groupes d'administration |
| `Get-PasswordNeverExpires.ps1` | Comptes portant le drapeau `DONT_EXPIRE_PASSWORD` |
| `Get-KerberoastableAccounts.ps1` | Comptes utilisateurs portant un SPN, avec les types de chiffrement Kerberos qu'ils acceptent |

Aucun de ces scripts ne modifie l'annuaire : ils lisent des attributs LDAP et
produisent des fichiers CSV. L'exposition au Kerberoasting est déduite de la
configuration des comptes. Elle a été complétée par un contrôle défensif, sans
cassage : des tickets de service ont été demandés avec le client Windows standard,
et leur type de chiffrement a été lu (voir section 5).

Les quatre rapports sont ensuite croisés sur le `SamAccountName`. Ce croisement
est le cœur de la démarche : un compte qui apparaît dans un seul rapport est
un écart de configuration, un compte qui apparaît dans plusieurs est un chemin
de compromission. C'est lui qui détermine la sévérité et l'ordre de priorité
des remédiations.

## 3. Synthèse des findings

| ID | Intitulé | Sévérité | Comptes |
|---|---|---|---|
| F-01 | Comptes privilégiés à mot de passe permanent, jamais authentifiés — dont un exposé au Kerberoasting en RC4 | Critique | 4 |
| F-02 | Compte d'administration intégré non dormant | Élevé | 1 |
| F-03 | Privilège d'administration d'annuaire sur un rôle métier | Moyen | 1 |
| F-04 | Comptes de service non privilégiés exposés au Kerberoasting | Moyen | 4 (dont 1 Faible) |
| F-05 | Mot de passe permanent sur des comptes non privilégiés | Faible | 5 |

## 4. Findings détaillés

### F-01 — Comptes privilégiés à mot de passe permanent, jamais authentifiés (Critique)

Quatre comptes apparaissent simultanément dans `privileged-users.csv` et
`password-never-expires.csv` : ils sont membres d'un groupe d'administration du
domaine et portent le drapeau `PasswordNeverExpires`. Le rapport
`inactive-users.csv` indique qu'aucun des quatre ne s'est authentifié depuis sa
création. Trois suivent une convention de nommage indiquant un usage applicatif
(`svc-*`), le quatrième est un compte d'administration historique.

| SamAccountName | Groupe | PasswordNeverExpires | Dernière authentification | SPN (chiffrement) |
|---|---|---|---|---|
| `svc-backup` | Domain Admins | oui | jamais | `MSSQLSvc/bkp-sql01.lab.local:1433` (RC4 seul) |
| `svc-legacy` | Domain Admins | oui | jamais | — |
| `svc-sql` | Backup Operators | oui | jamais | — |
| `sysadmin-legacy` | Backup Operators | oui | jamais | — |

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

`svc-backup` est le seul compte du domaine présent dans les quatre rapports : il
porte en plus un nom de principal de service (SPN) et n'accepte que le chiffrement
RC4.

```csv
"Severity","SamAccountName","DisplayName","ServicePrincipalName","EncryptionType","SupportedEncryptionTypesRaw","PasswordAge","PasswordLastSet","AdminCount","Enabled","OU","DistinguishedName"
"Critical","svc-backup","svc-backup","MSSQLSvc/bkp-sql01.lab.local:1433","RC4","4","0","2026-11-27 12:08:02","1","True","OU=Service Accounts,DC=lab,DC=local","CN=svc-backup,OU=Service Accounts,DC=lab,DC=local"
```

Un SPN permet à n'importe quel utilisateur authentifié du domaine de demander au
contrôleur un ticket de service pour ce compte. C'est le fonctionnement normal de
Kerberos, aucun privilège n'est requis. Une partie de ce ticket est chiffrée avec une
clé dérivée du mot de passe du compte. L'attaquant l'emporte et teste des mots de
passe candidats hors ligne, à son rythme : plus aucune interaction avec l'annuaire,
donc ni verrouillage de compte ni échec d'authentification à détecter. En RC4, cette
clé est un simple condensat MD4 du mot de passe, sans sel ni itérations, ce qui permet
de tester des milliards de candidats par seconde sur une carte graphique. Côté
contrôleur, la demande de ticket ne déclenche rien : pour un compte qui n'accepte que
RC4, un ticket RC4 est la norme, et chaque accès légitime au service en produit un
identique.

La chaîne est donc complète : un compte ordinaire du domaine, un ticket demandé, un
mot de passe cassé hors ligne — et l'attaquant détient un membre de `Domain Admins`
dont le mot de passe, figé par `PasswordNeverExpires`, ne changera jamais.

**Remédiation.** Déterminer d'abord si chacun de ces comptes sert encore ; ceux
dont l'usage n'est pas justifié sont à désactiver, ce qui ne coûte rien. Pour les
autres, migrer vers un compte de service géré par le domaine (gMSA) lorsque
l'application le permet : le mot de passe est alors généré, détenu et renouvelé
par Active Directory, sans intervention humaine. À défaut, remplacer
l'appartenance au groupe d'administration par la délégation la plus restreinte
qui permette le fonctionnement, retirer le drapeau `PasswordNeverExpires`, et
confier la rotation à un coffre-fort à secrets.

Pour `svc-backup`, sans attendre ces arbitrages : retirer le SPN s'il ne correspond
plus à un service en exploitation. S'il est utilisé, restreindre le compte à AES
(`msDS-SupportedEncryptionTypes = 0x18`), puis réinitialiser son mot de passe avec
une valeur aléatoire d'au moins 25 caractères, ce qui génère ses clés AES. Cette
bascule rend aussi l'attaque détectable : une fois le compte passé en AES, ses
tickets légitimes sont chiffrés en AES, et une demande de ticket RC4 à son nom
devient une anomalie. Une alerte sur l'événement 4769 portant le type de chiffrement
`0x17` (RC4) pour ce compte n'a de sens qu'après la bascule : avant, elle se
déclencherait sur chaque accès légitime.

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

### F-04 — Comptes de service non privilégiés exposés au Kerberoasting (Moyen)

Quatre comptes de service sans appartenance à un groupe d'administration portent un
SPN. Ils sont exposés au même mécanisme que `svc-backup` (voir F-01) : n'importe quel
utilisateur du domaine peut demander leur ticket de service et tenter de casser leur
mot de passe hors ligne.

| SamAccountName | SPN | Chiffrement accepté | Sévérité |
|---|---|---|---|
| `svc-default` | `HTTP/legacy-app.lab.local` | non configuré (attribut absent) | Moyen |
| `svc-mixed` | `MSSQLSvc/app-sql01.lab.local:1433` | RC4 et AES (`0x1C`) | Moyen |
| `svc-web` | `HTTP/intranet.lab.local` | RC4 seul (`0x04`) | Moyen |
| `svc-modern` | `HTTP/portal.lab.local` | AES seul (`0x18`) | Faible |

```csv
"Severity","SamAccountName","DisplayName","ServicePrincipalName","EncryptionType","SupportedEncryptionTypesRaw","PasswordAge","PasswordLastSet","AdminCount","Enabled","OU","DistinguishedName"
"Medium","svc-default","svc-default","HTTP/legacy-app.lab.local","NotConfigured",,"0","2026-11-27 12:08:03",,"True","OU=Service Accounts,DC=lab,DC=local","CN=svc-default,OU=Service Accounts,DC=lab,DC=local"
"Medium","svc-mixed","svc-mixed","MSSQLSvc/app-sql01.lab.local:1433","RC4+AES","28","0","2026-11-27 12:08:03",,"True","OU=Service Accounts,DC=lab,DC=local","CN=svc-mixed,OU=Service Accounts,DC=lab,DC=local"
"Medium","svc-web","svc-web","HTTP/intranet.lab.local","RC4","4","0","2026-11-27 12:08:03",,"True","OU=Service Accounts,DC=lab,DC=local","CN=svc-web,OU=Service Accounts,DC=lab,DC=local"
"Low","svc-modern","svc-modern","HTTP/portal.lab.local","AES","24","0","2026-11-27 12:08:03",,"True","OU=Service Accounts,DC=lab,DC=local","CN=svc-modern,OU=Service Accounts,DC=lab,DC=local"
```

Le chiffrement accepté fixe le coût de l'attaque :

- **`svc-web`** n'accepte que RC4 : c'est le cas le plus rapide à casser, décrit en
  F-01.
- **`svc-default`** n'a pas l'attribut renseigné. Le contrôleur applique alors sa
  valeur par défaut, qui dépend de sa configuration (`DefaultDomainSupportedEncTypes`)
  et de son niveau de correctifs. C'est le cas le plus fréquent en production. Sur le
  contrôleur du laboratoire, à jour de ses correctifs, un client standard a reçu un
  ticket AES256. Le compte reste classé comme exposé à RC4 : ce résultat vaut pour ce
  contrôleur, pas pour ceux d'un autre domaine (voir section 5).
- **`svc-mixed`** accepte RC4 et AES : AES a été ajouté, RC4 n'a jamais été retiré, la
  marque d'une migration inachevée. Un client standard a reçu un ticket AES256. Mais
  le compte déclare toujours RC4, et un attaquant peut demander un ticket en RC4
  seulement. Ce cas n'a pas été testé ; le classement en Moyen considère qu'il obtient
  ce ticket (voir section 5).
- **`svc-modern`** n'accepte qu'AES. Le ticket reste obtenable, mais la clé est dérivée
  du mot de passe par 4 096 itérations salées, ce qui ralentit le cassage de plusieurs
  ordres de grandeur. Seul un mot de passe faible tombe encore, d'où la sévérité
  faible.

Sans privilège, un mot de passe cassé donne accès à ce que le service atteint,
typiquement les données de son application, d'où la sévérité moyenne. Cette
évaluation suppose que les droits du compte se limitent à son application. Or
l'attribut `adminCount`, sur lequel repose le classement, ne voit ni un droit
d'administrateur local sur le serveur applicatif, ni une délégation sur une unité
d'organisation. Ces droits sont à vérifier compte par compte avant de clore le
finding.

**Remédiation.** Par ordre de préférence :

1. Retirer le SPN s'il ne sert plus. Les SPN de services décommissionnés sont
   fréquents, et leur retrait supprime l'exposition sans autre effet.
2. Migrer le service vers un gMSA : le mot de passe aléatoire de 120 caractères,
   renouvelé automatiquement, rend l'attaque sans objet.
3. À défaut, restreindre le compte à AES (`msDS-SupportedEncryptionTypes = 0x18`),
   puis réinitialiser le mot de passe avec une valeur aléatoire longue (25 caractères
   au moins) pour générer les clés AES. Tester l'application avant la bascule : un
   client ancien qui ne parle que RC4 ne pourra plus s'authentifier.

Pour `svc-modern`, déjà en AES seul, seule la robustesse du mot de passe reste à
établir : à défaut de gMSA, le réinitialiser avec une valeur aléatoire longue.

**Effort estimé** : quelques heures par compte pour le retrait d'un SPN ou la
bascule AES, davantage lorsqu'une dépendance applicative doit être testée.

### F-05 — Mot de passe permanent sur des comptes non privilégiés (Faible)

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

**L'inactivité n'est pas mesurable sur ce périmètre.** Les 32 comptes activés
remontent tous comme jamais authentifiés, et tous ont été créés le même jour. Un
critère qui correspond à la totalité du périmètre ne discrimine rien : ce n'est
pas le signe d'un parc dormant, mais celui d'une donnée d'annuaire non
exploitable ici. L'inactivité réelle doit être établie à partir des événements
d'authentification collectés par le SIEM, et non des attributs d'annuaire. Ce
constat explique pourquoi aucun finding de ce rapport ne repose sur l'inactivité
seule.

**Les délégations Kerberos ne sont pas couvertes.** Délégations non contraintes,
délégation contrainte avec transition de protocole et délégation basée sur les
ressources sont hors du périmètre de l'outillage actuel. Cette couverture est prévue
dans une itération ultérieure.

**L'exposition RC4 de `svc-mixed` et `svc-default` n'est que partiellement
mesurée.** Des tickets de service ont été demandés pour les cinq comptes avec un
client Windows standard (`klist get`), et leur type de chiffrement a été recoupé avec
les événements 4769 du contrôleur. `svc-backup` et `svc-web` reçoivent un ticket RC4
(`0x17`). `svc-mixed`, `svc-default` et `svc-modern` reçoivent un ticket AES256
(`0x12`). Deux cas restent non testés. D'abord, un client qui ne demande que RC4 :
c'est ce que ferait un attaquant contre `svc-mixed`, qui déclare toujours RC4.
Ensuite, d'autres contrôleurs : le traitement de `svc-default` dépend de la
configuration et du niveau de correctifs de chaque contrôleur, et un seul a été
observé. Le classement prudent des deux comptes est donc conservé.

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
.\scripts\powershell\Get-KerberoastableAccounts.ps1 -OutputPath .\outputs\sample-results\kerberoastable-accounts.csv
```

## Annexe B — Données brutes

Les quatre fichiers CSV complets sont disponibles dans
[`outputs/sample-results/`](../outputs/sample-results/).