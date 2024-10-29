# Projet de Cryptographie Asymétrique : Attaques sur RSA et DSA

## Description

Ce projet explore les failles de sécurité dans les systèmes de signature numérique RSA et DSA en utilisant des techniques d'injection de fautes et de fuite d'aléatoire. Il se divise en deux parties principales :

  + Injection de fautes sur la signature RSA pour tester la résistance de l'algorithme face aux erreurs introduites intentionnellement.
  + Fuite d'aléatoire sur DSA pour démontrer comment l'exposition de certaines valeurs aléatoires peut compromettre la clé secrète.

## Membres de l'équipe.

 + Nouhaila Jabbar
 + Rim Sadiqi
    
## Structure du Projet

  * main.cpp : Ce fichier implémente la signature RSA en utilisant le Théorème des Restes Chinois (CRT) pour optimiser les calculs. Il simule une attaque par injection de                   faute (Bellcore) en introduisant une erreur dans le calcul de la signature, permettant ainsi de récupérer les facteurs premiers de la clé publique. Cette                       technique révèle ainsi la clé privée.
    
  * main_DSA.cpp : Ce fichier implémente l’algorithme de signature DSA et simule une attaque basée sur la fuite de l’aléa k utilisé pour signer. En exposant cette valeur,                       l’attaque permet de remonter jusqu'à la clé privée, illustrant la vulnérabilité de DSA en cas de fuite de l'aléatoire.

