
#include <iostream>
#include <cstdlib>

const uint32_t w = 32;
const uint32_t n = 624;
const uint32_t m = 397;
const uint32_t r = 31;
const uint32_t u = 11;
const uint32_t d = 0xFFFFFFFF;
const uint32_t t = 15;
const uint32_t c = 0xEFC60000;
const uint32_t l = 18;
const uint32_t f = 1812433253;
const uint32_t s = 7;
const uint32_t b = 0x9D2C5680;
const uint32_t a = 0x9908B0DF;
const uint32_t lower_mask = 0x7FFFFFFF;
const uint32_t upper_mask = 0x80000000;

uint32_t MT[n];
uint32_t index = n + 1;

void seed_mt(uint32_t seed) {
    index = n;
    MT[0] = seed;
    for (uint32_t i = 1; i < n; i++) {
        MT[i] = (f * (MT[i - 1] ^ (MT[i - 1] >> (w - 2))) + i) & d;
    }
}

void twist() {
    for (uint32_t i = 0; i < n; i++) {
        uint32_t x = (MT[i] & upper_mask) + (MT[(i + 1) % n] & lower_mask);
        uint32_t xA = x >> 1;
        if (x % 2 != 0) {
            xA = xA ^ a;
        }
        MT[i] = MT[(i + m) % n] ^ xA;
    }
    index = 0;
}

uint32_t extract_number() {
    if (index >= n) {
        if (index > n) {
            std::cout << "Generator was never seeded" << std::endl;
            exit(1);
        }
        twist();
    }
    uint32_t y = MT[index];
    y = y ^ ((y >> u) & d);
    y = y ^ ((y << s) & b);
    y = y ^ ((y << t) & c);
    y = y ^ (y >> l);
    index++;
    return y & d;
}

int main() {
    seed_mt(5489);
    for (int i = 0; i < 5; i++) {
        std::cout << extract_number() << std::endl;
    }
    return 0;
}

