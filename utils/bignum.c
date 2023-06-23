
#include <iostream>
#include <vector>
#include <algorithm>
#include <cstdint>

class BigNum {
public:
    BigNum() {}
    BigNum(uint64_t num) {
        while (num > 0) {
            digits_.push_back(num % BASE);
            num /= BASE;
        }
    }
    
    BigNum(const std::vector<uint64_t>& digits) : digits_(digits) {}
    
    BigNum operator+(const BigNum& other) const {
        std::vector<uint64_t> result;
        uint64_t carry = 0;
        size_t i = 0;
        
        while (i < digits_.size() || i < other.digits_.size() || carry > 0) {
            uint64_t sum = carry;
            if (i < digits_.size())
                sum += digits_[i];
            if (i < other.digits_.size())
                sum += other.digits_[i];
            
            result.push_back(sum % BASE);
            carry = sum / BASE;
            i++;
        }
        
        return BigNum(result);
    }
    
    friend std::ostream& operator<<(std::ostream& os, const BigNum& num) {
        if (num.digits_.empty()) {
            os << "0";
        } else {
            for (int i = num.digits_.size() - 1; i >= 0; i--) {
                os << num.digits_[i];
            }
        }
        return os;
    }
    
private:
    static const uint64_t BASE = 1000000000; // Each element represents 9 decimal digits
    std::vector<uint64_t> digits_;
};

int main() {
    BigNum num1(123456789);
    BigNum num2(987654321);
    
    BigNum sum = num1 + num2;
    
    std::cout << "num1: " << num1 << std::endl;
    std::cout << "num2: " << num2 << std::endl;
    std::cout << "sum: " << sum << std::endl;
    
    return 0;
}
