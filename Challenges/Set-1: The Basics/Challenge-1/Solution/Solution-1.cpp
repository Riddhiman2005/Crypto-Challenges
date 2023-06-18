
// C++ code as a solution of Challenge-1


#include <iostream>
#include <string>
#include <bitset>
#include <cmath>

class Question1 {
public:
    void eightToSix(const std::string& binary) {
        std::string newBinary = binary;

        if (newBinary.length() % 6 != 0) {
            newBinary += '0';
        }
        binaryToDecimal(newBinary);
        return;
    }

    void binaryToDecimal(const std::string& binary) {
        std::string s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; // Base64 table
        std::string result;
        std::string buffer;
        int number = 0;
        for (std::size_t i = 0; i + 6 <= binary.length(); i += 6) {
            buffer = binary.substr(i, 6);
            number = std::stoi(buffer, nullptr, 2);
            result += s[number];
        }
        std::cout << "base64 = " << std::endl;
        std::cout << result << std::endl;
        return;
    }

    std::string decimalToBinary(const long long decimal) {
        std::string binary;
        long long buffer = 0;
        long long quotient = decimal;
        while (quotient > 0) {
            buffer = quotient % 2;
            binary = std::to_string(buffer) + binary;
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

    void userInterface() {
        std::string hex;
        long long decimal = 0;
        std::string binary;
        std::cout << "Please enter the hex string: ";
        std::getline(std::cin, hex);
        decimal = hexToDecimal(hex);
        binary = decimalToBinary(decimal);
        eightToSix(binary);
        return;
    }
};

int main() {
    Question1 m;
    m.userInterface();
    return 0;
}
