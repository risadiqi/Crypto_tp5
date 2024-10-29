#include <stdio.h>
#include <iostream>
#include <gmp.h>
#include <time.h>

#define BITSTRENGTH 14 // Taille du module (n) en bits
#define PRIMESIZE (BITSTRENGTH / 2) // Taille des nombres premiers p et q

/* Déclaration des variables globales */
mpz_t d, e, n; // Variables pour les clés privée (d), publique (e) et le module (n)
mpz_t M, C;    // Variables pour le message original (M) et le message chiffré (C)

// Fonction d'exponentiation rapide modulaire pour calculer g^k mod p
void Expo_By_Squaring(mpz_t result, mpz_t g, const mpz_t k_orig, mpz_t p) {
    mpz_t k;
    mpz_init_set(k, k_orig); // Crée une copie locale de k pour éviter de modifier l'original

    // Si k est négatif, on inverse g et rend k positif
    if(mpz_sgn(k) < 0) {
        mpz_invert(g, g, p);
        mpz_neg(k, k);
    }
    // Si k est nul, on définit le résultat comme 1 (car g^0 = 1)
    else if(mpz_sgn(k) == 0) {
        mpz_set_ui(result, 1);
    }
    // Sinon, on effectue l'exponentiation par élévation au carré pour optimiser le calcul
    else {
        mpz_t y;
        mpz_init_set_ui(y, 1); // Initialisation de y avec la valeur 1

        // Boucle de calcul rapide jusqu'à ce que k soit réduit à 1
        while(mpz_cmp_ui(k, 1) > 0) {
            // Si k est pair, on élève g au carré
            if(mpz_even_p(k) != 0) {
                mpz_mul(g, g, g);
                mpz_mod(g, g, p);        // Calcul g = g^2 mod p
                mpz_divexact_ui(k, k, 2); // Division de k par 2
            } else {
                // Si k est impair, on multiplie y par g et réduit k de 1
                mpz_mul(y, g, y);
                mpz_mul(g, g, g);
                mpz_sub_ui(k, k, 1);
                mpz_divexact_ui(k, k, 2); // Division de k par 2
            }
        }
        mpz_mul(result, g, y); // Calcul final pour result = g * y mod p
        mpz_mod(result, result, p);
        mpz_clear(y); // Libération de la mémoire pour y
    }
    mpz_clear(k); // Libération de la mémoire pour k
}

// Fonction pour calculer le GCD de deux nombres en utilisant l'algorithme d'Euclide
void gcd_euclidian(mpz_t res, mpz_t a, mpz_t b) {
    // Si b est 0, le GCD est a
    if (mpz_cmp_ui(b, 0) == 0)
        mpz_set(res, a);
    else {
        mpz_t m;
        mpz_init(m);
        mpz_mod(m, a, b); // m = a mod b
        gcd_euclidian(res, b, m); // Appel récursif
        mpz_clear(m); // Libération de la mémoire pour m
    }
}

// Fonction pour simuler une injection de faute en modifiant la valeur de sigma1
void inject_faute(mpz_t faulty_sigma1, mpz_t sigma1) {
    mpz_add_ui(faulty_sigma1, sigma1, 1); // Ajoute 1 à sigma1 pour simuler une erreur
}

// Implémentation de RSA avec le Théorème des Restes Chinois (CRT)
void RSA_CTR(mpz_t result, mpz_t p, mpz_t q, mpz_t d, mpz_t M, int faulty = 1) {
    // Initialisation des variables pour les calculs de CRT
    mpz_t A, B, n, i, sigma1, sigma2, temp1, temp2, Mp, Mq;

    mpz_init(A); mpz_init(B); mpz_init(sigma1); mpz_init(sigma2);
    mpz_init(temp1); mpz_init(temp2); mpz_init(n); mpz_init(Mp); mpz_init(Mq); mpz_init(i);

    // Calcul du module n = p * q
    mpz_mul(n, p, q);

    // Calcul des coefficients A et B pour CRT
    mpz_invert(B, p, q);  // B = p^(-1) mod q
    mpz_invert(A, q, p);  // A = q^(-1) mod p
    mpz_mul(A, q, A);     // A = q * (q^(-1) mod p)
    mpz_mul(B, p, B);     // B = p * (p^(-1) mod q)

    // Calcul des résidus de M mod p et M mod q
    mpz_mod(Mp, M, p);
    mpz_mod(Mq, M, q);

    // Calcul des signatures partielles sigma1 et sigma2
    Expo_By_Squaring(sigma1, Mp, d, p); // sigma1 = M^d mod p
    Expo_By_Squaring(sigma2, Mq, d, q); // sigma2 = M^d mod q

    // Injection de faute si indiqué
    if (faulty == 0) {
        inject_faute(sigma1, sigma1); // Injecte une erreur dans sigma1 pour simuler l'attaque
    }

    // Calcul de la signature complète en combinant les deux parties
    mpz_mul(temp1, A, sigma1); // temp1 = A * sigma1
    mpz_mul(temp2, B, sigma2); // temp2 = B * sigma2
    mpz_add(result, temp1, temp2); // result = temp1 + temp2

    // Libération de la mémoire allouée
    mpz_clear(A); mpz_clear(B); mpz_clear(Mp); mpz_clear(Mq);
    mpz_clear(sigma1); mpz_clear(sigma2); mpz_clear(temp1); mpz_clear(temp2); mpz_clear(n); mpz_clear(i);
}

// Fonction pour effectuer une attaque de Bellcore en retrouvant les facteurs premiers p et q
void Bellcore_attack(mpz_t real_sigma, mpz_t faulty_sigma, mpz_t p_found, mpz_t q_found) {
    mpz_t sub, q, p;
    mpz_init(sub); mpz_init(q); mpz_init(p);

    // Calcul de la différence entre la signature réelle et la signature avec faute
    mpz_sub(sub, real_sigma, faulty_sigma);

    // Calcul du GCD de sub et n pour trouver q
    mpz_gcd(q, sub, n); // q est le GCD
    mpz_tdiv_q(p, n, q); // p = n / q

    mpz_set(p_found, p); // Stocke p dans p_found
    mpz_set(q_found, q); // Stocke q dans q_found

    // Libération de la mémoire allouée
    mpz_clear(sub); mpz_clear(p); mpz_clear(q);
}

// Fonction principale
int main() {
    // Initialisation des grands entiers GMP pour les clés et les messages
    mpz_init(d); mpz_init(e); mpz_init(n); mpz_init(M); mpz_init(C);

    // Initialisation des variables pour générer des nombres premiers
    mpz_t p, q, randp, randq;
    mpz_init(randp); mpz_init(randq); mpz_init(p); mpz_init(q);

    // Initialisation du générateur de nombres aléatoires
    gmp_randstate_t r;
    gmp_randinit_default(r);
    gmp_randseed_ui(r, time(NULL)); // Seed avec le temps actuel

    // Génération des nombres premiers aléatoires p et q
    mpz_urandomb(randp, r, PRIMESIZE); // Génère un nombre aléatoire de taille PRIMESIZE
    mpz_urandomb(randq, r, PRIMESIZE);
    mpz_nextprime(p, randp); // Trouve le prochain nombre premier à partir de randp
    mpz_nextprime(q, randq);

    // Calcul du module n = p * q
    mpz_mul(n, p, q);

    // Calcul de phi(n) = (p-1)(q-1)
    mpz_t p_minus_1, q_minus_1, x;
    mpz_init(p_minus_1); mpz_init(q_minus_1); mpz_init(x);
    mpz_sub_ui(p_minus_1, p, 1); // p-1
    mpz_sub_ui(q_minus_1, q, 1); // q-1
    mpz_mul(x, p_minus_1, q_minus_1); // phi(n)

    // Génération de e tel que GCD(e, phi(n)) = 1
    mpz_t rop;
    mpz_init(rop);
    do {
        gmp_randstate_t ra;
        gmp_randinit_default(ra);
        gmp_randseed_ui(ra, time(NULL)); // Seed avec le temps actuel
        mpz_urandomb(e, ra, PRIMESIZE); // Génère e
        gcd_euclidian(rop, e, x); // Vérifie que e et phi(n) sont premiers entre eux
    } while (mpz_cmp_ui(rop, 1) != 0); // Si GCD(e, phi(n)) != 1, on régénère e

    // Calcul de d tel que e * d ≡ 1 (mod phi(n)), c’est la clé privée
    mpz_invert(d, e, x);

    // Génération d'un message aléatoire M tel que M < n
    gmp_randstate_t rs;
    gmp_randinit_default(rs);
    gmp_randseed_ui(rs, time(NULL));
    mpz_urandomb(M, rs, BITSTRENGTH - 1); // Message aléatoire de taille BITSTRENGTH
    while (mpz_cmp(M, n) >= 0) { // Assure que M < n
        mpz_urandomb(M, rs, BITSTRENGTH - 1);
    }

    // Calcul de la signature RSA CRT
    mpz_t result;
    mpz_init(result);
    RSA_CTR(result, p, q, d, M);

    // Vérification de la signature en déchiffrant
    mpz_t M_decrypted;
    mpz_init(M_decrypted);
    Expo_By_Squaring(M_decrypted, result, e, n);

    // Libération de la mémoire pour les variables GMP
    mpz_clear(p_minus_1); mpz_clear(q_minus_1); mpz_clear(x);
    mpz_clear(p); mpz_clear(q); mpz_clear(d); mpz_clear(e); mpz_clear(n);
    mpz_clear(M); mpz_clear(C); mpz_clear(rop); mpz_clear(randp);
    mpz_clear(randq); mpz_clear(result); mpz_clear(M_decrypted);
    gmp_randclear(r);
}
