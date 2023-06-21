
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Helper function to calculate modular exponentiation (g^exp % mod)
uint64_t modexp(uint64_t g, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    while (exp > 0) {
        if (exp & 1)
            result = (result * g) % mod;
        g = (g * g) % mod;
        exp >>= 1;
    }
    return result;
}

// Helper function to calculate the greatest common divisor (gcd) of two numbers
uint64_t gcd(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Helper function to calculate the modular inverse (a^(-1) % mod) using extended Euclidean algorithm
uint64_t modinv(uint64_t a, uint64_t mod) {
    int64_t b = mod;
    int64_t x = 0, y = 1;
    while (a > 1) {
        int64_t q = a / mod;
        int64_t t = mod;
        mod = a % mod;
        a = t;
        t = x;
        x = y - q * x;
        y = t;
    }
    if (y < 0)
        y += b;
    return y;
}

int main() {
    // Constants
    uint64_t p = 7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771;
    uint64_t g = 4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143;
    uint64_t q = 236234353446506858198510045061214171961;

    // Step 1: Check Fermat's theorem
    uint64_t result = modexp(g, p - 1, p);
    if (result != 1) {
        printf("Fermat's theorem fails!\n");
        return 0;
    }

    // Step 2: Check the order of g
    result = modexp(g, q, p);
    if (result != 1) {
        printf("Incorrect order!\n");
        return 0;
    }

    // Step 3: Calculate truncated_p and verify it
    uint64_t truncated_p = (p - 1) / q;
    uint64_t expected_truncated_p = 30477252323177606811760882179058908038824640750610513771646768011063128035873508507547741559514324673960576895059570;
    if (truncated_p != expected_truncated_p) {
        printf("Error: Truncated_p does not match expected value!\n");
        return 0;
    }

    // Step 4: Factorize truncated_p
    printf("Factors of truncated_p:\n");
    for (uint64_t i = 2; i <= truncated_p; i++) {
        if (truncated_p % i == 0) {
            printf("%lu ", i);
        }
    }
    printf("\n");

    // Step 5: Perform the secret recovery process
    uint64_t x = rand() % (p - 1) + 1;
    x = modexp(x, q, p);

    // Step 6: Find h values and compute x mod r
    printf("Reduced values (x mod r):\n");
    for (uint64_t i = 2; i <= truncated_p; i++) {
        if (truncated_p % i == 0 && i != 3) {
            uint64_t h;
            do {
                h = rand() % p;
                result = modexp(h, (p - 1) / i, p);
            } while (result == 1);
            uint64_t hexp = modexp(h, x, p);
            printf("%lu %lu\n", hexp, i);
        }
    }

    // Step 7: Chinese Remainder Theorem (CRT) to recover x
    printf("Recovered secret x:\n");
    uint64_t recovered_x = 0;
    uint64_t n = 1;
    for (uint64_t i = 2; i <= truncated_p; i++) {
        if (truncated_p % i == 0 && i != 3) {
            uint64_t h, r;
            do {
                h = rand() % p;
                result = modexp(h, (p - 1) / i, p);
            } while (result == 1);
            uint64_t hexp = modexp(h, x, p);
            r = findxmodr(hexp, h, i);
            uint64_t ni = n / i;
            uint64_t k = modinv(ni, i);
            recovered_x += r * ni * k;
            uint64_t gcd_val = gcd(ni, i);
            if (gcd_val != 1) {
                printf("Not coprime! GCD(%lu, %lu) = %lu\n", ni, i, gcd_val);
                return 0;
            }
            n *= i;
        }
    }
    recovered_x = modexp(recovered_x, q, n);
    printf("%lu\n", recovered_x);

    return 0;
}
