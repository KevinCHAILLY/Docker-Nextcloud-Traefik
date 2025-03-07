# Déploiement de Nextcloud avec Docker Compose et Traefik v3

Ce dépôt contient les fichiers nécessaires pour déployer Nextcloud à l'aide de Docker Compose, avec Traefik v3 comme reverse proxy et Let's Encrypt pour la génération automatique de certificats SSL.

## Caractéristiques

- **Noms uniques** : Tous les conteneurs, volumes et réseaux sont nommés de façon unique en utilisant le nom de domaine, ce qui permet de déployer plusieurs instances sur le même serveur
- **Traefik v3** : Utilisation de la dernière version de Traefik avec toutes ses fonctionnalités
- **SSL automatique** : Génération et renouvellement automatiques des certificats SSL via Let's Encrypt
- **Sécurité renforcée** : Configuration des en-têtes de sécurité et middlewares pour protéger votre instance Nextcloud
- **Interface graphique de configuration** : Un script Python pour configurer facilement le fichier .env via une interface graphique

## Prérequis

- Docker
- Docker Compose
- Un nom de domaine pointant vers votre serveur
- Les ports 80 et 443 ouverts sur votre serveur
- Python 3.x (pour l'outil de configuration graphique)

## Structure des fichiers

- `docker-compose.yml` : Configuration des services Docker (Nextcloud, MariaDB, Redis, Traefik)
- `.env` : Variables d'environnement pour la configuration
- `traefik/` : Répertoire contenant les fichiers de configuration de Traefik
  - `traefik.yml` : Configuration principale de Traefik
  - `acme.json` : Fichier pour stocker les certificats SSL (généré automatiquement)
- `configure_env.py` : Script Python pour configurer le fichier .env via une interface graphique

## Installation

### Méthode 1 : Utilisation de l'interface graphique (recommandée)

1. Clonez ce dépôt ou téléchargez les fichiers
2. Exécutez le script Python pour configurer le fichier .env :

```bash
python configure_env.py
```

3. Remplissez les champs dans l'interface graphique et cliquez sur "Enregistrer"
4. Lancez les conteneurs avec la commande :

```bash
docker-compose up -d
```

### Méthode 2 : Configuration manuelle

1. Clonez ce dépôt ou téléchargez les fichiers
2. Modifiez le fichier `.env` pour personnaliser votre configuration :
   - Changez les mots de passe par défaut (`MYSQL_ROOT_PASSWORD` et `MYSQL_PASSWORD`)
   - Configurez vos noms de domaine (`NEXTCLOUD_HOST` et `TRAEFIK_DASHBOARD_HOST`)
   - Configurez l'authentification pour le dashboard Traefik (`TRAEFIK_DASHBOARD_AUTH`)
   - Indiquez votre adresse email pour Let's Encrypt (`TRAEFIK_ACME_EMAIL`)
   - Ajustez le niveau de logs si nécessaire (`TRAEFIK_LOG_LEVEL`)

3. Générez un mot de passe pour le dashboard Traefik :
   ```bash
   docker run --rm httpd:alpine htpasswd -nbB admin "votre_mot_de_passe" | sed -e s/\\$/\\$\\$/g
   ```
   Copiez le résultat dans la variable `TRAEFIK_DASHBOARD_AUTH` du fichier `.env`

4. Assurez-vous que le fichier `traefik/acme.json` a les bonnes permissions :
   ```bash
   chmod 600 traefik/acme.json
   ```

5. Lancez les conteneurs avec la commande :
   ```bash
   docker-compose up -d
   ```

## Utilisation de l'interface graphique de configuration

L'interface graphique de configuration vous permet de :

- Configurer facilement tous les paramètres nécessaires
- Générer automatiquement des mots de passe sécurisés
- Charger un fichier .env existant pour le modifier
- Créer automatiquement le fichier acme.json avec les bonnes permissions

Pour l'utiliser, exécutez simplement :

```bash
python configure_env.py
```

## Premier accès à Nextcloud

Accédez à Nextcloud via votre navigateur à l'adresse : `https://votre-domaine-nextcloud`

Suivez l'assistant d'installation de Nextcloud :
- Créez un compte administrateur
- Pour la base de données, utilisez les paramètres suivants :
  - Type de base de données : MySQL/MariaDB
  - Hôte de base de données : `db-votre-domaine-nextcloud`
  - Nom de la base de données : `nextcloud` (ou la valeur de `MYSQL_DATABASE` dans `.env`)
  - Utilisateur de la base de données : `nextcloud` (ou la valeur de `MYSQL_USER` dans `.env`)
  - Mot de passe de la base de données : la valeur de `MYSQL_PASSWORD` dans `.env`

## Volumes persistants

Cette configuration utilise des volumes Docker pour stocker les données de manière persistante, avec des noms uniques basés sur le nom de domaine :
- `nextcloud_votre-domaine-nextcloud` : Contient les fichiers de l'application Nextcloud
- `db_votre-domaine-nextcloud` : Contient les données de la base de données MariaDB

## Déploiement de plusieurs instances

Grâce à l'utilisation de noms uniques basés sur le nom de domaine, vous pouvez déployer plusieurs instances de Nextcloud sur le même serveur :

1. Créez un répertoire séparé pour chaque instance
2. Copiez les fichiers de configuration dans chaque répertoire
3. Modifiez le fichier `.env` dans chaque répertoire pour définir un nom de domaine différent (ou utilisez l'interface graphique)
4. Lancez chaque instance avec `docker-compose up -d` dans son répertoire respectif

## Sécurité

Cette configuration inclut déjà :
1. HTTPS avec Let's Encrypt pour les certificats SSL
2. Redirection automatique de HTTP vers HTTPS
3. En-têtes de sécurité pour Nextcloud configurés selon les meilleures pratiques
4. Authentification pour le dashboard Traefik
5. Middlewares de sécurité globaux définis dans le fichier de configuration Traefik

Assurez-vous de :
1. Changer les mots de passe par défaut dans le fichier `.env`
2. Limiter l'accès au serveur avec un pare-feu
3. Maintenir régulièrement à jour tous les services

## Fonctionnalités de Traefik v3

Cette configuration tire parti des nouvelles fonctionnalités de Traefik v3 :
- Middlewares globaux définis dans le fichier de configuration
- Support amélioré pour les certificats SSL
- Métriques Prometheus intégrés
- Tracing pour le débogage

## Maintenance

### Mise à jour de Nextcloud et des autres services

Pour mettre à jour tous les services, exécutez :

```bash
docker-compose pull
docker-compose up -d
```

### Renouvellement des certificats SSL

Les certificats Let's Encrypt sont automatiquement renouvelés par Traefik.

### Sauvegarde

Pour sauvegarder vos données, vous pouvez :
1. Sauvegarder les volumes Docker (qui ont des noms uniques basés sur le nom de domaine)
2. Exporter la base de données avec :

```bash
docker-compose exec db sh -c 'exec mysqldump --all-databases -uroot -p"$MYSQL_ROOT_PASSWORD"' > backup.sql
```

### Accès au dashboard Traefik

Le dashboard Traefik est accessible à l'adresse `https://votre-domaine-traefik` avec les identifiants configurés dans le fichier `.env`. 