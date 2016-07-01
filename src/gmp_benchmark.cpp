
#include <gmp.h>
#include <stdio.h>
#include <time.h>

void test() {
	gmp_randstate_t rstate;
	gmp_randinit_default(rstate);
	for (long long log_n = 9; log_n <= 18; ++log_n) {
		long long bits = 1 << log_n;
		printf("%lld\n", bits);
		mpz_t base, exponent, modulus;
		mpz_init(base);
		mpz_init(exponent);
		mpz_init(modulus);
		mpz_urandomb(base, rstate, bits);
		mpz_urandomb(exponent, rstate, bits);
		mpz_urandomb(modulus, rstate, bits);
		mpz_t result;
		mpz_init(result);
		time_t start = clock();
		mpz_powm(result, base, exponent, modulus);
		time_t end = clock();
		printf("%.4lf\n", (end - start) / (0.0 + CLOCKS_PER_SEC));
	}
}

int main() {
	test();
	return 0;
}