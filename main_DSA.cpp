#include <iostream>
#include <gmp.h>
#include <time.h>
#include <openssl/sha.h>

#define L 64    // Longueur en bits de p
#define N 32    // Longueur en bits de q

// Fonction de génération de clés DSA : génère les valeurs p, q, g, y et x
void KeyGen(mpz_t p, mpz_t q, mpz_t g, mpz_t y, mpz_t x) {
    gmp_randstate_t r;
    gmp_randinit_default(r);
    gmp_randseed_ui(r, time(NULL)); // Initialise le générateur aléatoire avec le temps actuel

    mpz_t z, h, p_minus_1;
    mpz_inits(z, h, p_minus_1, NULL);

    // Génère un nombre premier q de N bits
    mpz_urandomb(q, r, N);
    mpz_nextprime(q, q); // Trouve le premier nombre premier >= q

    // Génère p en utilisant q et z tel que p = q * z + 1 soit premier
    while (1) {
        mpz_urandomb(z, r, L - N);      // Génère un z aléatoire de taille (L - N) bits
        mpz_mul(p, q, z);               // Calcule p = q * z
        mpz_add_ui(p, p, 1);            // p = q * z + 1
        if (mpz_probab_prime_p(p, 25)) { // Test de primalité sur p
            break;
        }
    }

    // Calcule p - 1 pour les prochaines étapes
    mpz_sub_ui(p_minus_1, p, 1);

    // Génère g tel que g = h^z mod p et que g soit différent de 1
    while (1) {
        mpz_urandomm(h, r, p_minus_1);  // h est choisi aléatoirement dans [1, p-2]
        mpz_add_ui(h, h, 1);            // On ajoute 1 pour que h soit dans [1, p-1]
        
        mpz_powm(g, h, z, p);           // g = h^z mod p
        if (mpz_cmp_ui(g, 1) > 0) {     // Si g > 1, la condition est remplie
            break;
        }
    }

    // Génère la clé privée x et la clé publique y
    mpz_urandomm(x, r, q);         // x est dans [1, q-1]
    mpz_powm(y, g, x, p);          // y = g^x mod p

    mpz_clears(z, h, p_minus_1, NULL); // Libération de la mémoire
    gmp_randclear(r);
}

// Fonction pour afficher une variable avec un nom donné
void afficher(const char* nom, mpz_t var) {
    char tab[1024];
    mpz_get_str(tab, 10, var);   // Convertit var en une chaîne décimale
    std::cout << nom << " = " << tab << std::endl;
}

// Fonction de hachage SHA-256 pour le message, avec réduction modulo q
void hachage(std::string& message, mpz_t result, mpz_t q) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), hash); // Calcule le hachage SHA-256
    mpz_import(result, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash); // Convertit le hachage en entier
    mpz_mod(result, result, q); // Réduit le hachage modulo q
}

// Fonction de signature DSA : génère la signature (r, s) pour un message h_m
void Sign(mpz_t p, mpz_t q, mpz_t g, mpz_t x, mpz_t r, mpz_t s, mpz_t h_m, mpz_t k_out) {
    gmp_randstate_t rand_state;
    gmp_randinit_default(rand_state);
    gmp_randseed_ui(rand_state, time(NULL));

    mpz_t k, temp, k_inv;
    mpz_inits(k, temp, k_inv, NULL);

    // Boucle jusqu'à ce qu'on obtienne une signature valide
    while (true) {
        mpz_urandomm(k, rand_state, q); // Choisit un k aléatoire dans [1, q-1]
        if (mpz_cmp_ui(k, 0) == 0) continue; // Continue si k = 0

        mpz_powm(temp, g, k, p);  // Calcul de temp = g^k mod p
        mpz_mod(r, temp, q);      // Calcul de r = (g^k mod p) mod q
        if (mpz_cmp_ui(r, 0) == 0) continue; // Continue si r = 0

        // Calcul de s = k^(-1) * (h_m + x * r) mod q
        mpz_mul(temp, x, r);      // temp = x * r
        mpz_add(temp, temp, h_m); // temp = h_m + x * r
        mpz_invert(k_inv, k, q);  // k_inv = k^(-1) mod q
        mpz_mul(s, k_inv, temp);  // s = k^(-1) * (h_m + x * r)
        mpz_mod(s, s, q);         // s = s mod q
        if (mpz_cmp_ui(s, 0) == 0) continue; // Continue si s = 0

        mpz_set(k_out, k); // Enregistre k dans k_out
        break;
    }

    mpz_clears(k, temp, k_inv, NULL); // Libère la mémoire
    gmp_randclear(rand_state);
}

// Fonction de vérification de signature DSA : vérifie que (r, s) est valide pour un message h_m
void Verify(mpz_t s, mpz_t q, mpz_t r, mpz_t h_m, mpz_t p, mpz_t g, mpz_t y) {
    mpz_t s_inv, w, u1, u2, v, temp1, temp2;
    mpz_inits(s_inv, w, u1, u2, v, temp1, temp2, NULL);

    // Vérifie que s et r sont dans les intervalles valides
    if (!(mpz_cmp_ui(s, 0) > 0 && mpz_cmp(s, q) < 0 && mpz_cmp_ui(r, 0) > 0 && mpz_cmp(r, q) < 0)) {
        std::cout << "La signature n'est pas valide" << std::endl;
        mpz_clears(s_inv, w, u1, u2, v, temp1, temp2, NULL);
        return;
    }

    // Calcul de s^-1 mod q pour obtenir w
    if (mpz_invert(s_inv, s, q) == 0) {
        std::cout << "La signature n'est pas valide" << std::endl;
        mpz_clears(s_inv, w, u1, u2, v, temp1, temp2, NULL);
        return;
    }

    // Calcul des valeurs intermédiaires u1 et u2
    mpz_mul(u1, h_m, s_inv); // u1 = h_m * s^-1 mod q
    mpz_mod(u1, u1, q);

    mpz_mul(u2, r, s_inv);   // u2 = r * s^-1 mod q
    mpz_mod(u2, u2, q);

    // Calcul de v = (g^u1 * y^u2 mod p) mod q
    mpz_powm(temp1, g, u1, p);  // temp1 = g^u1 mod p
    mpz_powm(temp2, y, u2, p);  // temp2 = y^u2 mod p
    mpz_mul(v, temp1, temp2);   // v = g^u1 * y^u2
    mpz_mod(v, v, p);           // v mod p
    mpz_mod(v, v, q);           // v mod q

    // Vérifie si la signature est valide en comparant v et r
    if (mpz_cmp(v, r) == 0) {
        std::cout << "La signature est valide" << std::endl;
    } else {
        std::cout << "La signature n'est pas valide" << std::endl;
    }

    mpz_clears(s_inv, w, u1, u2, v, temp1, temp2, NULL); // Libère la mémoire
}

// Fonction d'attaque pour retrouver la clé privée x à partir de la signature et de k
void Attaque(mpz_t x, mpz_t s, mpz_t k, mpz_t h_m, mpz_t r, mpz_t q) {
    mpz_t temp1, temp2, r_inv;
    mpz_inits(temp1, temp2, r_inv, NULL);
    mpz_mul(temp1, s, k);
    mpz_mod(temp1, temp1, q);
    mpz_sub(temp2, temp1, h_m);
    mpz_mod(temp2, temp2, q);
    mpz_invert(r_inv, r, q);
    mpz_mul(x, temp2, r_inv);
    mpz_mod(x, x, q);
    mpz_clears(temp1, temp2, r_inv, NULL);
}
int main() {
    mpz_t p, q, g, y, x, h_m, r, s, h_m_faux, k, x_found;
    mpz_inits(p, q, g, y, x, h_m, r, s, h_m_faux, k, x_found, NULL);
    KeyGen(p, q, g, y, x);
    afficher("p", p);
    afficher("q", q);
    afficher("g", g);
    afficher("y", y);
    afficher("x", x);
    std::string message = "msg to be signed";
    hachage(message, h_m, q);
    Sign(p, q, g, x, r, s, h_m, k);
    afficher("r", r);
    afficher("s", s);
    afficher("k", k);
    std::cout << "test valid signature" << std::endl;
    Verify(s, q, r, h_m, p, g, y);
    /*std::string faux_message = "message modifié.";
    hachage(faux_message, h_m_faux, q);
    std::cout << " Test avec message modifié : " << std::endl;
    Verify(s, q, r, h_m_faux, p, g, y);
    mpz_add_ui(r, r, 1); 
    std::cout << "r modifié" << std::endl;
    Verify(s, q, r, h_m, p, g, y);
    mpz_sub_ui(r, r, 1); 
    mpz_add_ui(s, s, 1);
    std::cout << "s modifié" << std::endl;
    Verify(s, q, r, h_m, p, g, y);
    */
    Attaque(x_found, s, k, h_m, r, q);
    afficher("x privé", x);
    afficher("x retrouvé", x_found);
    if (mpz_cmp(x, x_found) == 0) {
        std::cout << "x found" << std::endl;
    } else {
        std::cout << "attack failed" << std::endl;
    }
    mpz_clears(p, q, g, y, x, h_m, r, s, k, x_found, NULL);
    return 0;
}
