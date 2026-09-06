FINDING 1 — CRITIQUE
Comptes de service avec privilèges d'administration du domaine et mot de passe
n'expirant jamais.
svc-backup, svc-legacy (Domain Admins) | svc-sql, sysadmin-legacy (Backup Operators)
Risque : un compte non humain peut compromettre le domaine ; le mot de passe ne
tourne jamais ; aucun des quatre ne s'est authentifié depuis sa création, donc
personne ne sait à quoi ils servent ni ne surveille leur usage. Backup Operators
donne accès à NTDS.dit, donc au hash krbtgt, donc au domaine entier.
Remédiation : gMSA si le produit le supporte, sinon délégation restreinte +
rotation via coffre-fort. Désactiver ceux dont l'usage n'est pas justifié.
Effort : 1 à 3 jours par compte selon la dépendance applicative.

FINDING 2 — ÉLEVÉ
Compte d'administration intégré utilisé en session de travail courante.
labadmin — membre de Administrators, Domain Admins, Enterprise Admins,
Schema Admins, Group Policy Creator Owners. Authentification le jour de l'audit.
Risque : détient l'intégralité des privilèges de la forêt, aucune traçabilité
individuelle, aucune séparation entre usage courant et opérations sensibles.
Une compromission de la session compromet la forêt.
Remédiation : comptes nommés par administrateur, élévation ponctuelle, compte
intégré laissé dormant et supervisé.
Effort : quelques jours, dépend du nombre d'administrateurs.
Note : finding non provoqué par le jeu de données, découvert dans l'état réel
du domaine.

FINDING 3 — MOYEN
Privilège d'administration d'annuaire porté par un rôle métier.
aceo — membre direct d'Account Operators.
Risque : Account Operators permet de créer des comptes et de modifier des groupes
non protégés, ce qui ouvre des chemins d'élévation indirects. Un dirigeant n'a
aucun besoin opérationnel de ce droit.
Remédiation : révoquer, traiter le besoin d'origine par une délégation ciblée.
Effort : quelques heures.

FINDING 4 — FAIBLE
Mot de passe n'expirant jamais sur des comptes non privilégiés.
alopez, ccfo, pkim, rmills, svc-monitor
Risque : credentials à durée de vie illimitée, exposition accrue en cas de fuite.
Sévérité limitée par l'absence de privilège.
Remédiation : retirer le flag, documenter les rares cas justifiés.

CONSTAT MÉTHODOLOGIQUE — pas un finding
28 comptes actifs sur 28 remontent comme jamais authentifiés, tous créés le même
jour. Un critère qui matche 100 % du périmètre ne discrimine rien : ce n'est pas
un parc dormant, c'est une donnée d'annuaire non exploitable sur ce périmètre.
L'inactivité réelle doit être mesurée sur les événements d'authentification
collectés côté SIEM, pas sur les attributs d'annuaire.