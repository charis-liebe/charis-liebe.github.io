---
title: Anonymous Azure Services Enumeration
date: 2026-08-06 00:00:00 +0000
categories: [OFFENSIVE AZURE, RECONNAISSANCE]
tags: [Azure, recon, offensive]
---

# Anonymous Azure Services Enumeration

## Azure Enumeration

Il existe plusieurs façons d'énumérer un environnement Azure :

- **En étant authentifié** (avec des identifiants valides)
- **De manière anonyme** (sans aucune authentification)

C'est cette seconde approche qu'on va explorer ici.

---

## Anonymous Azure Storage

Un souci récurrent sur Azure ? Des comptes de stockage exposés publiquement.  
Oui, comme les fameux buckets S3 chez AWS, mais en version Microsoft.

Chaque **"Storage Account"** se voit attribuer un sous-domaine unique sur `core.windows.net`.

> **Exemple :** je crée le compte `confidentiel-projet`, il devient accessible sur `confidentiel-projet.core.windows.net`.  
> Le problème ? Si tu laisses l'accès ouvert, n'importe qui peut aller farfouiller dedans.

Et croyez-moi, ça arrive plus souvent qu'on ne le pense.

---

## Les Blobs

Dans ce billet, on va surtout parler des **Blobs** – même si les autres types de données mériteraient qu'on s'y attarde aussi.

Pour faire simple, un Blob chez Azure, c'est du stockage de données **non structurées**. Souvent, on les voit servir des fichiers publics (images, CSS, ce genre de trucs). Mais là où ça devient chaud, c'est qu'on en trouve aussi remplis de trucs **sensibles** :

- Fichiers de configuration
- Backups de bases de données
- Identifiants / mots de passe

Bref, le genre de dossier qu'on aimerait bien garder fermé à clé.
Et pour vous donner une idée de l'ampleur : **Google indexe à lui seul environ 1,2 million de PDF** sur le sous-domaine `blob.core.windows.net`.  Oui, vous avez bien lu. 1,2 million.
Autant dire que la surface d'attaque, elle est bien réelle.
`site:blob.core.windows.net`


## Permissions
Bon, parlons des permissions, parce que c'est là que tout se joue.
Les blobs, ils sont rangés dans des "Containers". Pour faire simple, pensez à des dossiers sur votre ordinateur. Rien de sorcier.
Mais voilà où ça devient intéressant : chaque container a une politique d'accès. Et cette politique, elle décide d'un truc crucial : qui peut voir vos fichiers ?

    Est-ce que seul vous pouvez y accéder ?

    Est-ce que n'importe qui sur Internet peut les lire ?

    Est-ce qu'on peut même lister tout le contenu du dossier ?
Et devinez quoi ? Si vous choisissez l'option trop permissive (et croyez-moi, ça arrive plus souvent qu'on ne le pense), vos données deviennent accessibles à tout le monde. Sans mot de passe, sans connexion, sans rien.
En gros : un container mal configuré, c'est comme laisser la porte de votre appartement grande ouverte avec une pancarte "Entrez, tout est gratuit".Et c'est là que les choses deviennent vraiment dangereuses, parce qu'on trouve parfois des trucs bien sensibles dans ces blobs – mais ça, on en reparle plus tard.

## Automatisation : un outil qui fait le boulot à notre place

Face au nombre croissant d'environnements Azure qu'on croise dans nos audits, on s'est vite dit qu'il fallait **automatiser** la recherche de blobs exposés publiquement. Parce que faire ça à la main ? Non merci. 😅
Heureusement, l'équipe chez NetSPI avait déjà pensé à tout. Ils ont sorti un outil en PowerShell – parce que bon, on est chez Microsoft – mais honnêtement, le script pourrait être réécrit dans d'autres langages sans trop de difficultés.

> 📦 **Le code est dispo ici :**  
> [NetSPI/MicroBurst sur GitHub](https://github.com/NetSPI/MicroBurst)

---

### Comment ça marche, concrètement ?

L'outil fait trois choses principales :
**1. Il chasse les comptes de stockage valides**  
Il commence par faire des requêtes DNS sur le sous-domaine `blob.core.windows.net`. En gros, il teste des noms de comptes potentiels pour voir s'ils existent.

**2. Il bruteforce les noms de containers**  
Une fois qu'il a trouvé un compte de stockage, il tente d'énumérer les containers en utilisant les API REST d'Azure Blob Service. Il essaie des noms comme `dev`, `test`, `qa` – bref, tout ce qui ressemble à un nom de dossier qu'un admin aurait laissé traîner.

**3. Il utilise Bing API (optionnel)**  
Parce que Google a déjà indexé des millions de fichiers, l'outil peut aussi interroger Bing pour trouver des containers déjà exposés publiquement. Une petite recherche bien sentie, et hop.

### Et une fois qu'il trouve un container ?
Il utilise à nouveau les API Azure pour vérifier si le container est en mode **"Container"** (celui qui permet de lister tous les fichiers). Si c'est le cas, bingo – on peut tout récupérer.

### D'où vient cette idée ?
Le concept, ainsi qu'une partie de la liste de permutations, est directement inspiré d'un outil similaire pour AWS S3 : **inSp3ctor**. Mais comme on est sur Azure, l'équipe a adapté le tout pour que ça colle à l'écosystème Microsoft.
**En résumé :** un outil qui fait le sale boulot à notre place, pour qu'on puisse se concentrer sur ce qui est vraiment intéressant – les données que les gens laissent trainer. Et franchement, vu le nombre de comptes exposés qu'on trouve… il tourne souvent. 

## Utilisation du script
Le script s'appelle **`Invoke-EnumerateAzureBlobs`** – et il est plutôt simple à prendre en main.
Il accepte **cinq paramètres**, que je vous détaille :
---

| Paramètre | Description |
|-----------|-------------|
| `-Base` | Le nom de base sur lequel vous voulez appliquer les permutations. Exemple : `netspi` |
| `-Permutations` | Le fichier contenant les mots à ajouter au nom de base pour trouver des comptes de stockage (ex : `dev`, `test`, `qa`). Ça donne des trucs comme `netspidev`, `testnetspi`, etc. |
| `-Folders` | Le fichier contenant les noms de dossiers potentiels à bruteforcer (ex : `files`, `docs`, `backup`). |
| `-BingAPIKey` | (Optionnel) La clé API Bing pour trouver des fichiers déjà indexés publiquement. |
| `-OutputFile` | Le fichier où écrire les résultats. |

---

### Exemple d'utilisation

```
Invoke-EnumerateAzureBlobs -Base "contoso" -Permutations .\perms.txt -Folders .\folders.txt -OutputFile .\results.txt
```                    

## Ressources additionnels 
<https://learn.microsoft.com/en-us/previous-versions/azure/cloud-services/cloud-services-choose-me>
<https://www.netspi.com/blog/technical-blog/cloud-penetration-testing/anonymously-enumerating-azure-file-resources/>
<https://www.blackhillsinfosec.com/red-teaming-microsoft-part-1-active-directory-leaks-via-azure/>
                                                     