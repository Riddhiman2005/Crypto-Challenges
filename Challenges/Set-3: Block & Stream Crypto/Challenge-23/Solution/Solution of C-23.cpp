
#include <iostream>
#include <cstdint>

class MT19937 {
private:
    static constexpr std::size_t N = 624;
    static constexpr std::size_t M = 397;
    static constexpr std::uint32_t MATRIX_A = 0x9908b0dfUL;
    static constexpr std::uint32_t UPPER_MASK = 0x80000000UL;
    static constexpr std::uint32_t LOWER_MASK = 0x7fffffffUL;

    std::uint32_t mt[N];
    std::size_t index;

public:
    MT19937(std::uint32_t seed) {
        mt[0] = seed;
        for (std::size_t i = 1; i < N; ++i) {
            mt[i] = (1812433253UL * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) & 0xffffffffUL;
        }
        index = N;
    }

    std::uint32_t extract() {
        if (index >= N) {
            twist();
        }

        std::uint32_t y = mt[index++];
        y ^= (y >> 11);
        y ^= (y << 7) & 0x9d2c5680UL;
        y ^= (y << 15) & 0xefc60000UL;
        y ^= (y >> 18);

        return y;
    }

private:
    void twist() {
        for (std::size_t i = 0; i < N; ++i) {
            std::uint32_t x = (mt[i] & UPPER_MASK) + (mt[(i + 1) % N] & LOWER_MASK);
            std::uint32_t xA = x >> 1;
            if (x % 2 != 0) {
                xA ^= MATRIX_A;
            }
            mt[i] = mt[(i + M) % N] ^ xA;
        }
        index = 0;
    }
};

std::uint32_t untemperRightShift(std::uint32_t value, int shift) {
    std::uint32_t result = 0;
    for (int i = 0; i < 32; ++i) {
        std::uint32_t mask = 1 << i;
        std::uint32_t bit = value & mask;
        if (bit != 0) {
            for (int j = 0; j < i; ++j) {
                std::uint32_t prevBit = result & (1 << j);
                if (prevBit != 0) {
                    result |= mask;
                    break;
                }
            }
        }
    }
    return result;
}

std::uint32_t untemperLeftShiftAnd(std::uint32_t value, int shift, std::uint32_t mask) {
    std::uint32_t result = 0;
    for (int i = 0; i < 32; ++i) {
        std::uint32_t maskShifted = mask << i;
        std::uint32_t bit = value & maskShifted;
        if (bit != 0) {
            for (int j = 0; j < i; ++j) {
                std::uint32_t prevBit = result & (mask << j);
                if (prevBit != 0) {
                    result |= maskShifted;
                    break;
                }
            }
        }
    }
    return result;
}

int main() {
    // Generate original MT19937 output
    MT19937 originalGenerator(1234);
    std::cout << "Original MT19937 outputs: ";
    for (int i = 0; i < 624; ++i) {
        std::cout << originalGenerator.extract() << " ";
    }
    std::cout << std::endl;

    // Reconstruct the state and create a new generator
    std::uint32_t state[624];
    for (int i = 0; i < 624; ++i) {
        std::uint32_t output = originalGenerator.extract();
        output = untemperRightShift(output, 18);
        output = untemperLeftShiftAnd(output, 15, 0xefc60000UL);
        output = untemperLeftShiftAnd(output, 7, 0x9d2c5680UL);
        output = untemperRightShift(output, 11);
        state[i] = output;
    }
    MT19937 splicedGenerator(0);
    std::memcpy(splicedGenerator.mt, state, sizeof(state));
    splicedGenerator.index = 624;

    // Predict future values using the spliced generator
    std::cout << "Predicted MT19937 outputs: ";
    for (int i = 0; i < 10; ++i) {
        std::cout << splicedGenerator.extract() << " ";
    }
    std::cout << std::endl;

    return 0;
}
