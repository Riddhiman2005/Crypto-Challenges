
#include <cstdint>

class Rand {
public:
    Rand(uint64_t seed = 0) : state_(seed) {}
    
    uint64_t next() {
        uint64_t x = state_;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state_ = x;
        return x;
    }
    
private:
    uint64_t state_;
};

int main() {
    Rand rand(42); // Initialize with seed 42
    
    for (int i = 0; i < 10; i++) {
        uint64_t value = rand.next();
        std::cout << value << std::endl;
    }
    
    return 0;
}
