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

void afficher(const char* nom, const mpz_t var) {
    char tab[1024]; 
    mpz_get_str(tab, 10, var);
    std::cout << nom << " = " << tab << std::endl;
}

void hachage(const std::string& message, mpz_t result) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), hash);
    mpz_import(result, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);
}

void Sign(mpz_t p, mpz_t q, mpz_t g, mpz_t x, mpz_t r, mpz_t s, mpz_t h_m) {
    gmp_randstate_t rand_state;
    gmp_randinit_default(rand_state);
    gmp_randseed_ui(rand_state, time(NULL));

    mpz_t k, temp, k_inv;
    mpz_inits(k, temp, k_inv, NULL);

    while (1) {
        mpz_urandomm(k, rand_state, q);
        if (mpz_cmp_ui(k, 0) == 0) continue;  

        mpz_powm(temp, g, k, p);  
        mpz_mod(r, temp, q);      
        if (mpz_cmp_ui(r, 0) == 0) continue;  

        mpz_mul(temp, x, r);      
        mpz_add(temp, temp, h_m); 

        if (mpz_invert(k_inv, k, q) == 0) continue;  

        mpz_mul(s, k_inv, temp); 
        mpz_mod(s, s, q);        
        if (mpz_cmp_ui(s, 0) == 0) continue;  
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

int main() {
    mpz_t p, q, g, y, x, h_m, r, s, h_m_faux;

    mpz_inits(p, q, g, y, x, h_m, r, s, h_m_faux, NULL);

    KeyGen(p, q, g, y, x);
    afficher("p", p);
    afficher("q", q);
    afficher("g", g);
    afficher("y", y);
    afficher("x", x);

    std::string message = "message à signer.";
    hachage(message, h_m);

    Sign(p, q, g, x, r, s, h_m);
    afficher("Signature r", r);
    afficher("Signature s", s);

    std::cout << "Test de la signature valide : " << std::endl;
    Verify(s, q, r, h_m, p, g, y);

    std::string faux_message = "Bonjour, ceci est un message modifié.";
    hachage(faux_message, h_m_faux);
    std::cout << " Test avec message modifié : " << std::endl;
    Verify(s, q, r, h_m_faux, p, g, y);

    mpz_add_ui(r, r, 1); 
    std::cout << "r modifié..." << std::endl;
    Verify(s, q, r, h_m, p, g, y);
    mpz_sub_ui(r, r, 1); 

    mpz_add_ui(s, s, 1);
    std::cout << "s modifié..." << std::endl;
    Verify(s, q, r, h_m, p, g, y);

    mpz_clears(p, q, g, y, x, h_m, r, s, h_m_faux, NULL);

    return 0;
}
