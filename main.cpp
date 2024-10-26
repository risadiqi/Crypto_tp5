#include <stdio.h>
#include <iostream>
#include <gmp.h>
#include <time.h>

#define BITSTRENGTH  14              /* size of modulus (n) in bits */
#define PRIMESIZE (BITSTRENGTH / 2)  /* size of the primes p and q  */

/* Declare global variables */

mpz_t d, e, n;
mpz_t M, C;

void Expo_By_Squaring(mpz_t result, mpz_t g, const mpz_t k_orig, mpz_t p){

    mpz_t k;
    mpz_init_set(k, k_orig);  // Création d'une copie locale de k

    if(mpz_sgn(k) < 0){
        mpz_invert(g, g, p);
        mpz_neg(k, k);
    }
    else if(mpz_sgn(k) == 0){
        mpz_set_ui(result, (unsigned long int)1);    
    }
    else {
        mpz_t y;
        mpz_init_set_ui(y, (unsigned long int)1);

        while(mpz_cmp_ui(k, 1) > 0){
            if(mpz_even_p(k) != 0){
                mpz_mul(g, g, g);
                mpz_mod(g, g, p);
                mpz_divexact_ui(k, k, 2);
            }
            else {
                mpz_mul(y, g, y);
                mpz_mul(g, g, g);
                mpz_sub_ui(k, k, (unsigned long int)1);
                mpz_divexact_ui(k, k, 2);
            }
        }
        mpz_mul(result, g, y);
        mpz_mod(result, result, p);
        mpz_clear(y);  // Libérer la mémoire allouée pour y
    }
    mpz_clear(k);  // Libérer la mémoire allouée pour k
}

void gcd_euclidian(mpz_t res, mpz_t a, mpz_t b) {
    if (mpz_cmp_ui(b, 0) == 0)
        mpz_set(res, a);
    else {
        mpz_t m;
        mpz_init(m);
        mpz_mod(m, a, b);
        gcd_euclidian(res, b, m);
        mpz_clear(m);  // Libérer la mémoire allouée pour m
    }
}

void inject_faute(mpz_t faulty_sigma1, mpz_t sigma1) {
    mpz_add_ui(faulty_sigma1, sigma1, 1);
}

void RSA_CTR(mpz_t result, mpz_t p, mpz_t q, mpz_t d, mpz_t M, int faulty = 1) {
    mpz_t A, B, n, i;
    mpz_t sigma1, sigma2;
    mpz_t temp1, temp2;
    mpz_t Mp, Mq; 

    mpz_init(A);
    mpz_init(B);
    mpz_init(sigma1);
    mpz_init(sigma2);
    mpz_init(temp1);
    mpz_init(temp2);
    mpz_init(n);
    mpz_init(Mp);
    mpz_init(Mq);
    mpz_init(i);

    mpz_mul(n, p, q);
    mpz_invert(B, p, q);  
    mpz_invert(A, q, p); 

    mpz_mul(A, q, A);
    mpz_mul(B, p, B);

    mpz_mod(Mp, M, p);
    mpz_mod(Mq, M, q);

    Expo_By_Squaring(sigma1, Mp, d, p);
    Expo_By_Squaring(sigma2, Mq, d, q);

    if (faulty == 0) {
        inject_faute(sigma1, sigma1);  
    }

    mpz_mul(temp1, A, sigma1);  
    mpz_mul(temp2, B, sigma2);  
    mpz_add(result, temp1, temp2); 

    mpz_clear(A);
    mpz_clear(B);
    mpz_clear(Mp);
    mpz_clear(Mq);
    mpz_clear(sigma1);
    mpz_clear(sigma2);
    mpz_clear(temp1);
    mpz_clear(temp2);
    mpz_clear(n);
    mpz_clear(i);
}

void Bellcore_attack(mpz_t real_sigma, mpz_t faulty_sigma, mpz_t p_found, mpz_t q_found) {
    mpz_t sub, q, p;

    mpz_init(sub);
    mpz_init(q);
    mpz_init(p);

    mpz_sub(sub, real_sigma, faulty_sigma);
    mpz_gcd(q, sub, n);  
    mpz_tdiv_q(p, n, q);

    mpz_set(p_found, p);
    mpz_set(q_found, q);

    mpz_clear(sub);
    mpz_clear(p);
    mpz_clear(q);
}


void signature_DS(mpz_t q, mpz p)
{

}
/* Main subroutine */
int main() {
    /* Initialize the GMP integers */
    mpz_init(d);
    mpz_init(e);
    mpz_init(n);
    mpz_init(M);
    mpz_init(C);

    std::cout << "hi4" << std::endl;
    mpz_t p, q;
    mpz_t randp, randq;
    mpz_init(randp);
    mpz_init(randq);
    mpz_init(p);
    mpz_init(q);

    gmp_randstate_t r;
    gmp_randinit_default(r);
    gmp_randseed_ui(r, time(NULL));

    mpz_urandomb(randp, r, PRIMESIZE);
    mpz_urandomb(randq, r, PRIMESIZE);

    mpz_nextprime(p, randp);
    mpz_nextprime(q, randq);

    char p_str[1000];
    char q_str[1000];
    mpz_get_str(p_str, 10, p);
    mpz_get_str(q_str, 10, q);

    std::cout << "Random Prime 'p' = " << p_str << std::endl;
    std::cout << "Random Prime 'q' = " << q_str << std::endl;

    /* Calculate n (=pq) and phi(n) */
    char n_str[1000];
    mpz_t x;
    mpz_init(x);

    mpz_mul(n, p, q);
    mpz_get_str(n_str, 10, n);
    std::cout << "\t n = " << n_str << std::endl;

    mpz_t p_minus_1, q_minus_1;
    mpz_init(p_minus_1);
    mpz_init(q_minus_1);

    mpz_sub_ui(p_minus_1, p, (unsigned long int)1);
    mpz_sub_ui(q_minus_1, q, (unsigned long int)1);

    mpz_mul(x, p_minus_1, q_minus_1);
    char phi_str[1000];
    mpz_get_str(phi_str, 10, x);
    std::cout << "\t phi(n) = " << phi_str << std::endl;

    /* Find e */
    mpz_t rop;
    mpz_init(rop);

    do {
        gmp_randstate_t ra;
        gmp_randinit_default(ra);
        gmp_randseed_ui(ra, time(NULL));

        mpz_urandomb(e, ra, PRIMESIZE);
        gcd_euclidian(rop, e, x);

    } while (mpz_cmp_ui(rop, 1) != 0);

    char e_str[1000];
    mpz_get_str(e_str, 10, e);
    std::cout << "\t e = " << e_str << std::endl;

    /* Calculate d */
    mpz_init(d);
    mpz_invert(d, e, x);

    char d_str[1000];
    mpz_get_str(d_str, 10, d);
    std::cout << "\t d = " << d_str << std::endl << std::endl;

    std::cout << "Public Keys  (e,n): ( " << e_str <<" , " << n_str << " )" << std::endl;
    std::cout << "Private Keys (d,n): ( " << d_str <<" , " << n_str << " )" << std::endl;

    /* Generate random message M < n */
    gmp_randstate_t rs;
    gmp_randinit_default(rs);
    gmp_randseed_ui(rs, time(NULL));

    mpz_urandomb(M, rs, BITSTRENGTH - 1);

    while (mpz_cmp(M, n) >= 0) {
        mpz_urandomb(M, rs, BITSTRENGTH - 1);
    }

    char M_str[1000];
    mpz_get_str(M_str, 10, M);
    std::cout << "Message originale : " << M_str << std::endl;

    /* RSA CRT  */
    mpz_t result;
    mpz_init(result);
    RSA_CTR(result, p, q, d, M);
    char R_str[1000];
    mpz_get_str(R_str, 10, result);
    std::cout << "Résultat : " << R_str << std::endl;

    /* Encrypt message M */
//    Expo_By_Squaring(C, M, e, n);

    /*char C_str[1000];
    mpz_get_str(C_str, 10, C);
    std::cout << "Message chiffré C : " << C_str << std::endl;
    */
    /* Decrypt ciphertext C (fix) */
    mpz_t M_decrypted;
    mpz_init(M_decrypted);
    Expo_By_Squaring(M_decrypted, result, e, n);  // Utilisez C et d pour déchiffrer
    char M_decrypted_str[1000];
    mpz_get_str(M_decrypted_str, 10, M_decrypted);
    std::cout << "Message déchiffré M' : " << M_decrypted_str << std::endl;

    /* Clean up */
    mpz_clear(p_minus_1);
    mpz_clear(q_minus_1);
    mpz_clear(x);
    mpz_clear(p);
    mpz_clear(q);

    mpz_clear(d);
    mpz_clear(e);
    mpz_clear(n);

    mpz_clear(M);
    mpz_clear(C);

    mpz_clear(rop);
    mpz_clear(randp);
    mpz_clear(randq);
    mpz_clear(result);
    mpz_clear(M_decrypted);

    gmp_randclear(r);
}
