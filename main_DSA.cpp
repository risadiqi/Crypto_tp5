#include <stdio.h>
#include <iostream>
#include <gmp.h>
#include <time.h>

#define L  3072             
#define N 256

void KeyGen(mpz_t p,mpz_t q,mpz_t g,mpz_t y, mpz_t x){

    gmp_randstate_t r;
    gmp_randinit_default(r);
    gmp_randseed_ui(r, time(NULL));

    mpz_t p_minus_1; 
    mpz_t z,h,g;          
    mpz_init(p_minus_1);
    mpz_init(z);
    mpz_init(h);
    mpz_init(g);

    
    mpz_urandomb(p, r, L);   
    mpz_nextprime(p, p);     

    while (1) {
        mpz_sub_ui(p_minus_1, p, 1); 

        mpz_urandomb(q, r, N);  
        mpz_nextprime(q, q);    

        mpz_mod(z, p_minus_1, q); 
        if (mpz_cmp_ui(z, 0) == 0) {
            break;
        }
    }
    while(1){
        mpz_urandomm(h,r,p-1);
        mpz_pawn(g,h,z,p)
        int cmp=mpz_cmp(g,1);
        if(cmp>0)
            break;
    }

    mpz_urandomm();    

    mpz_clear(p_minus_1);
    mpz_clear(z);
    mpz_clear(h);
    mpz_clear(g);

}

int main() {


}