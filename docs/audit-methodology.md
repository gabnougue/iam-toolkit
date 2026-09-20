# Méthodologie d'audit IAM

## Objet

Ce document décrit la démarche suivie pour auditer la gestion des identités et
des accès dans un environnement Active Directory : le déroulé des opérations, les
règles de jugement appliquées aux résultats, et ce qui relève explicitement du
hors-périmètre.

Il est indépendant de tout audit particulier. Le rapport d'exemple
[`reports/sample-audit-report.md`](../reports/sample-audit-report.md) en montre
l'application sur un domaine de laboratoire.

## Objectifs

L'audit vise à identifier les écarts de configuration et les chemins de
compromission dans l'annuaire : comptes dormants ou jamais utilisés, privilèges
excessifs ou mal placés, secrets à durée de vie illimitée, appartenances
imbriquées qui masquent un droit d'administration. Chaque constat est assorti
d'une remédiation et d'un ordre de grandeur d'effort, de façon que le
destinataire puisse arbitrer.

## Déroulé

1. **Cadrage** — périmètre de l'annuaire, comptes exclus et raison de
   l'exclusion, compte de lecture utilisé, fenêtre d'exécution.
2. **Collecte** — exécution des scripts de détection en lecture seule. Aucune
   modification de l'annuaire n'est effectuée à aucun moment.
3. **Croisement** — jointure des rapports sur l'identifiant de compte.
4. **Qualification** — application des règles de jugement ci-dessous, puis
   classement par sévérité.
5. **Rédaction** — findings avec constat, mécanisme de risque, remédiation et
   effort ; limites explicitées ; synthèse destinée à un lecteur non technique.

## Règles de jugement

Ces règles sont ce qui distingue un audit d'une extraction de données. Elles
s'appliquent au moment de la qualification.

**Valider l'outillage avant de croire ses résultats.** Un outil d'audit se valide
contre un annuaire réel, pas en relisant son code. Sur la version initiale de
l'IAM Toolkit, quatre chemins de code jamais exécutés ont été testés et trois se
sont révélés défectueux — dont un qui produisait un faux positif sur le compte le
plus privilégié du domaine. Un script qui ne remonte rien peut aussi bien
signifier qu'il n'y a rien à trouver que qu'il est cassé ; seule l'exécution
contre un jeu de données dont on connaît le contenu attendu permet de trancher.

**Juger la donnée avant de juger le finding.** Quand un critère correspond à la
totalité du périmètre, il ne discrimine plus rien. La bonne réaction est de
chercher pourquoi plutôt que de conclure : une colonne d'inactivité qui remonte
tous les comptes ne signale pas un parc dormant, mais une donnée d'annuaire non
exploitable sur ce périmètre — qu'il faut alors aller chercher ailleurs, par
exemple dans les événements d'authentification collectés par le SIEM.

**Un rapport donne un écart, plusieurs donnent un chemin.** Un compte qui
apparaît dans un seul rapport est un écart de configuration. Le même compte
présent dans deux ou trois rapports est un chemin de compromission : les
contrôles ont échoué successivement sur la même identité. La différence n'est pas
d'intensité mais de nature, et c'est elle qui commande la sévérité.

**Le signal se lit au regard de ce qu'on attend du compte.** Un compte de service
doit s'authentifier, c'est sa raison d'être : son silence signale un service mort
ou un compte oublié. Un compte d'administration de secours ne doit pas
s'authentifier, c'est sa définition : toute authentification signale qu'il est
entré dans le périmètre opérationnel. Le même signal produit donc deux findings
opposés selon la nature du compte.

**Nommer le mécanisme, pas seulement la gravité.** Écrire qu'un finding est
critique n'apprend rien au lecteur. Ce qui l'informe, c'est la chaîne qui mène du
constat à la compromission — par exemple : appartenance à `Backup Operators`,
donc privilège de sauvegarde sur les contrôleurs de domaine, donc lecture de
`NTDS.dit`, donc extraction du condensat `krbtgt`, donc forge de tickets Kerberos
arbitraires.

## Les limites font partie du livrable

Ce que l'audit ne couvre pas s'écrit dans le rapport au même titre que les
findings. Un lecteur qui ignore le périmètre réel conclura qu'un domaine est sain
alors qu'une partie n'a simplement pas été regardée.

Trois catégories de limites sont à déclarer systématiquement : les zones hors du
périmètre de l'outillage, les données non exploitables sur l'environnement audité
et la manière d'aller les chercher, et les contraintes propres à l'environnement
qui empêchent de valider certains contrôles.