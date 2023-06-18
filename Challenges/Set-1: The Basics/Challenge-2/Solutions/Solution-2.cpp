
//Solution of the problem using C++ 

#include <iostream>
#include <string>
#include <bitset>
#include <cmath>

class Question2 {
public:
    std::bitset<8> xorBigIntegers(const std::bitset<8>& num1, const std::bitset<8>& num2) {
        std::bitset<8> finalNumber = num1 ^ num2;
        return finalNumber;
    }

    std::string decimalToBinary(const long long decimal) {
        std::string binary;
        long long quotient = decimal;
        while (quotient > 0) {
            binary = std::to_string(quotient % 2) + binary;
            quotient /= 2;
        }

        while (binary.length() % 8 != 0) {
            binary = '0' + binary;
        }
        return binary;
    }

    long long hexToDecimal(const std::string& hex) {
        std::string s = "0123456789ABCDEF";
        int j = hex.length() - 1;
        int index = 0;
        long long power = 16;
        long long numberBuff = 0;
        long long number = 0;
        char buffer;
        for (std::size_t i = 0; i < hex.length(); i++) {
            buffer = hex[i];
            index = s.find(buffer);
            numberBuff = std::pow(power, j--);
            numberBuff *= index;
            number += numberBuff;
        }
        return number;
    }

    std::string binaryToHex(const std::string& binary) {
        if (binary.length() % 8 != 0) {
            return "";
        }
        std::string buffer;
        std::string hex;
        for (std::size_t i = 0; i + 8 <= binary.length(); i += 8) {
            buffer = binary.substr(i, 8); // 8 bits make one byte
            int decimal = std::stoi(buffer, nullptr, 2); // Converts byte to decimal
            buffer = std::to_string(decimal);
            hex += buffer;
        }
        return hex;
    }

    void userInterface() {
        std::string hex1;
        std::string hex2;
        std::string binary;
        std::bitset<8> result;
        std::cout << "Enter the hex string 1: ";
        std::getline(std::cin, hex1);
        std::cout << "Enter the hex string 2: ";
        std::getline(std::cin, hex2);

        if (hex2.length() != hex1.length()) {
            std::cout << "Error" << std::endl;
            return;
        }

        result = xorBigIntegers(std::bitset<8>(hexToDecimal(hex1)), std::bitset<8>(hexToDecimal(hex2)));
        binary = decimalToBinary(result.to_ullong());
        std::string hex = binaryToHex(binary);
        std::cout << "The xor'ed hex string is: " << std::endl;
        std::cout << hex << std::endl;
        return;
    }
};

int main() {
    Question2 m;
    m.userInterface();
    return 0;
}
