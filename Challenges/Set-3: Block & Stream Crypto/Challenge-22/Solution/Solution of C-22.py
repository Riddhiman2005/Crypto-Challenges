
import time
import random

class MersenneTwister:
    def __init__(self, seed):
        self.index = 0
        self.MT = [0] * 624
        self.MT[0] = seed & 0xffffffff
        for i in range(1, 624):
            self.MT[i] = (0x6c078965 * (self.MT[i-1] ^ (self.MT[i-1] >> 30)) + i) & 0xffffffff

    def extract(self):
        if self.index == 0:
            self.generate_numbers()

        y = self.MT[self.index]
        y = y ^ (y >> 11)
        y = y ^ ((y << 7) & 0x9d2c5680)
        y = y ^ ((y << 15) & 0xefc60000)
        y = y ^ (y >> 18)

        self.index = (self.index + 1) % 624
        return y

    def generate_numbers(self):
        for i in range(624):
            y = (self.MT[i] & 0x80000000) + (self.MT[(i+1) % 624] & 0x7fffffff)
            self.MT[i] = self.MT[(i + 397) % 624] ^ (y >> 1)
            if y % 2 != 0:
                self.MT[i] = self.MT[i] ^ 0x9908b0df

def main():
    print("|- - - - - - - - - - - - - - - - - - - - - - -")
    print("|            Crack an MT 19937 seed           |")
    print("|- - - - - - - - - - - - - - - - - - - - - - -")

    # Sleeping for rand seconds
    uiToSleep = 1
    print("Sleeping for", uiToSleep, "seconds")
    time.sleep(uiToSleep)

    # Current unix timestamp
    now = int(time.time() * 1000)
    print("Current timestamp is", now)

    # Instantiate and seed
    mt = MersenneTwister(now)

    # Sleeping for rand seconds
    uiToSleep = 2
    print("Sleeping for", uiToSleep, "seconds")
    time.sleep(uiToSleep)

    # Extract RNG
    ulRandom = mt.extract()
    print("Extracted RNG:", ulRandom)

if __name__ == "__main__":
    main()
