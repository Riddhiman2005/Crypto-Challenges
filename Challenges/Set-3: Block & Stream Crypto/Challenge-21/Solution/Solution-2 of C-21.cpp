
 // A short C++ program that uses the mtrand library to generate random numbers using the Mersenne Twister algorithm


#include "../../utils/mtrand.h"
#include <iostream>

int main() {
  mtseed(5489);
  for (int i = 0; i < 10; i++)
    std::cout << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << mtrand() << std::endl;
  std::cout << std::endl;

  return 0;
}
