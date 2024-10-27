#include <iostream>
#include <gmp.h>
#include <time.h>
#include <openssl/sha.h>

#define L  64    
#define N  32    

void KeyGen(mpz_t p, mpz_t q, mpz_t g, mpz_t y, mpz_t x) {
    gmp_randstate_t r;
    gmp_randinit_default(r);
    gmp_randseed_ui(r, time(NULL));

    mpz_t z, h, p_minus_1;
    mpz_inits(z, h, p_minus_1, NULL);

    mpz_urandomb(q, r, N);
    mpz_nextprime(q, q); 

    while (1) {
        mpz_urandomb(z, r, L - N);      
        mpz_mul(p, q, z);               
        mpz_add_ui(p, p, 1);            
        if (mpz_probab_prime_p(p, 25)) {
            break;
        }
    }

    mpz_sub_ui(p_minus_1, p, 1);

    while (1) {
        mpz_urandomm(h, r, p_minus_1);  
        mpz_add_ui(h, h, 1);            

        mpz_powm(g, h, z, p);           
        if (mpz_cmp_ui(g, 1) > 0) {     
            break;
        }
    }

    mpz_urandomm(x, r, q);
    mpz_powm(y, g, x, p);

    mpz_clears(z, h, p_minus_1, NULL);
    gmp_randclear(r);
}

void afficher(const char* nom, mpz_t var) {
    char tab[1024]; 
    mpz_get_str(tab, 10, var);
    std::cout << nom << " = " << tab << std::endl;
}

void hachage(std::string& message, mpz_t result, mpz_t q) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), hash);
    mpz_import(result, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);
    mpz_mod(result, result, q);
}

void Sign(mpz_t p, mpz_t q, mpz_t g, mpz_t x, mpz_t r, mpz_t s, mpz_t h_m, mpz_t k_out) {
    gmp_randstate_t rand_state;
    gmp_randinit_default(rand_state);
    gmp_randseed_ui(rand_state, time(NULL));

    mpz_t k, temp, k_inv;
    mpz_inits(k, temp, k_inv, NULL);

    while (true) {
        mpz_urandomm(k, rand_state, q);
        if (mpz_cmp_ui(k, 0) == 0) continue;

        mpz_powm(temp, g, k, p);
        mpz_mod(r, temp, q);
        if (mpz_cmp_ui(r, 0) == 0) continue;

        mpz_mul(temp, x, r);
        mpz_add(temp, temp, h_m);
        mpz_invert(k_inv, k, q);
        mpz_mul(s, k_inv, temp);
        mpz_mod(s, s, q);
        if (mpz_cmp_ui(s, 0) == 0) continue;

        mpz_set(k_out, k); 
        break;
    }

    mpz_clears(k, temp, k_inv, NULL);
    gmp_randclear(rand_state);
}


void Verify(mpz_t s, mpz_t q, mpz_t r, mpz_t h_m, mpz_t p, mpz_t g, mpz_t y) {
    mpz_t s_inv, w, u1, u2, v, temp1, temp2;
    mpz_inits(s_inv, w, u1, u2, v, temp1, temp2, NULL);

    if (!(mpz_cmp_ui(s, 0) > 0 && mpz_cmp(s, q) < 0 && mpz_cmp_ui(r, 0) > 0 && mpz_cmp(r, q) < 0)) {
        std::cout << "La signature n'est pas valide " << std::endl;
        mpz_clears(s_inv, w, u1, u2, v, temp1, temp2, NULL);
        return;
    }

    if (mpz_invert(s_inv, s, q) == 0) {
        std::cout << "La signature n'est pas valide" << std::endl;
        mpz_clears(s_inv, w, u1, u2, v, temp1, temp2, NULL);
        return;
    }

    mpz_mul(u1, h_m, s_inv);
    mpz_mod(u1, u1, q);

    mpz_mul(u2, r, s_inv);
    mpz_mod(u2, u2, q);

    mpz_powm(temp1, g, u1, p);  
    mpz_powm(temp2, y, u2, p);   
    mpz_mul(v, temp1, temp2);   
    mpz_mod(v, v, p);            
    mpz_mod(v, v, q);           

    if (mpz_cmp(v, r) == 0) {
        std::cout << "La signature est valide" << std::endl;
    } else {
        std::cout << "La signature n'est pas valide" << std::endl;
    }

    mpz_clears(s_inv, w, u1, u2, v, temp1, temp2, NULL);
}

void Attaque(mpz_t x, mpz_t s,  mpz_t k, mpz_t h_m, mpz_t r, mpz_t q) {
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
