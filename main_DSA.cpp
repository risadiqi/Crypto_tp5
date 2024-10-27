#include <iostream>
#include <gmp.h>
#include <time.h>

#define L  64    
#define N  32    

void KeyGen(mpz_t p, mpz_t q, mpz_t g, mpz_t y, mpz_t x) {
    gmp_randstate_t r;
    gmp_randinit_default(r);
    gmp_randseed_ui(r, time(NULL));

    mpz_t z, h, p_minus_1;
    mpz_init(z);
    mpz_init(h);
    mpz_init(p_minus_1);

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

    mpz_clear(z);
    mpz_clear(h);
    mpz_clear(p_minus_1);
    gmp_randclear(r);
}

void afficher(const char* nom, const mpz_t var) {
    char tab[1024]; 
    mpz_get_str(tab, 10, var);
    std::cout << nom << " = " << tab << std::endl;
}

int main() {
    mpz_t p, q, g, y, x;

    mpz_init(p);
    mpz_init(q);
    mpz_init(g);
    mpz_init(y);
    mpz_init(x);

    KeyGen(p, q, g, y, x);

    afficher("p", p);
    afficher("q", q);
    afficher("g", g);
    afficher("y", y);
    afficher("x", x);

    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(g);
    mpz_clear(y);
    mpz_clear(x);

    return 0;
}
