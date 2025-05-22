Jogabonitooo

Site de commande d'articles sportifs, créé par Bastides Yoan
Fonctionnalités :

    Connexion / inscription

    Possibilité pour l'utilisateur d’écrire un avis sur le site

    Le message est affiché, puis 4 messages aléatoires (s'ils existent) l’accompagnent

    Ajout au panier des différents articles, avec choix de la taille

    Possibilité de retirer un ou plusieurs articles du panier, ou même de le vider complètement

    Vérification des informations de livraison, et ajout dans la base de données de l'adresse de l'utilisateur, ainsi que des articles constituant sa commande

    Page d'administration, où l’administrateur peut retirer un utilisateur du site


Fonctionnalités prévues au départ mais non implémentées :

    Le panier de chaque utilisateur est stocké en localStorage grâce à son identifiant. Au départ, il était prévu qu’il soit chargé et affiché depuis la base de données

    Les produits sont de simples images ; ils ne sont pas chargés depuis la base de données. Il n’y a pas de suivi des stocks non plus


Difficultés rencontrées :

    Problème lors du déploiement : impossible de déployer avec SQLite, il a donc fallu passer à PostgreSQL

    Problème de configuration du serveur Nginx, avec des ports d’écoute incorrects, ce qui empêchait le bon fonctionnement de Let's Encrypt


Déploiement :

Site déployé sur le serveur Polytech :

    Front : https://jogabonitooo-front.cluster-ig3.igpolytech.fr/

    Back : https://jogabonitoo-back.cluster-ig3.igpolytech.fr/