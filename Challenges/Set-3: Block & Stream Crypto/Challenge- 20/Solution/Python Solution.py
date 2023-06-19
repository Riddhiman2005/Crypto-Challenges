
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"strings"
)

var (
	blockSize  = 16
	idealFreqs = []float64{
		.08167, .01492, .02792, .04253, .12702, .0228, .02015, .06094, .06966, .0153,
		.0772, .04025, .02406, .06749, .07507, .01929, .0095, .05987, .06327, .09056,
		.02758, .00978, .02360, .00150, .01974, .0074, 0.23200,
	}
)

func initKey() []byte {
	key := make([]byte, blockSize)
	if _, err := rand.Read(key); err != nil {
		log.Fatal("Key Issue")
	}
	return key
}

func aesCTRDecrypt(cipherText, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal("AES error")
	}

	plainText := make([]byte, len(cipherText))
	stream := cipher.NewCTR(block, make([]byte, blockSize))
	stream.XORKeyStream(plainText, cipherText)

	return plainText
}

func xorBytes(input []byte, key byte) string {
	result := make([]byte, len(input))
	for i := range input {
		result[i] = input[i] ^ key
	}
	return string(result)
}

func bruteForce(input []byte) byte {
	var low, score float64
	low = 400.0
	var key byte
	for i := 0; i < 256; i++ {
		k := byte(i)
		score = getScore(xorBytes(input, k))
		if score < low {
			low = score
			key = k
		}
	}
	return key
}

func getScore(input string) float64 {
	inputBuffer := strings.ToLower(input)
	counter := make([]float64, 27)
	total := 0
	for _, ch := range inputBuffer {
		if 'a' <= ch && ch <= 'z' {
			counter[int(ch)-int('a')]++
			total++
		}
		if int(ch) == 32 {
			total++
			counter[26]++
		}
	}
	for i, val := range counter {
		counter[i] = val / float64(total)
	}
	score := chiSquare(counter, float64(len(input)))
	return score
}

func chiSquare(counter []float64, total float64) float64 {
	score := 0.0
	for i := range counter {
		expected := total * idealFreqs[i]
		buffer1 := math.Pow(counter[i]-expected, 2)
		buffer := buffer1 / (expected)
		score = score + buffer
	}
	return score
}

func guessKey(cipherText []byte, keySize int) []byte {
	var key []byte
	blockSize := len(cipherText) / keySize
	for i := 0; i < keySize; i++ {
		blocks := make([]byte, blockSize)
		for j := 0; j < blockSize; j++ {
			blocks[j] = cipherText[i+j*keySize]
		}
		buffer := bruteForce(blocks)
		key = append(key, buffer)
	}
	return key
}

func readByline(filename string) ([]string, int) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal("File read error")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	cipherText := make([]string, 0)
	minLength := math.MaxInt64

	for scanner.Scan() {
		plaintext, err := base64.StdEncoding.DecodeString(scanner.Text())
		if err != nil {
			log.Fatal("Base64 decoding error")
		}

		cipherBlock, err := aesCTRDecrypt(plaintext, key)
		if err != nil {
			log.Fatal("AES CTR decryption error")
		}

		cipherText = append(cipherText, string(cipherBlock))

		if len(cipherBlock) < minLength {
			minLength = len(cipherBlock)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal("Scanner error")
	}

	return cipherText, minLength
}

func truncate(cipherTextArray []string, minLength int) string {
	cipherText := ""
	for _, block := range cipherTextArray {
		if len(block) > minLength {
			cipherText += block[:minLength]
		}
	}
	return cipherText
}

func getPlainText(cipherText string, key []byte) {
	plainText := make([]byte, len(cipherText))
	for j := 0; j < len(cipherText); j++ {
		k := j % len(key)
		plainText[j] = cipherText[j] ^ key[k]
	}
	fmt.Println(string(plainText))
}

func main() {
	filename := "Data.txt"
	cipherTextArray, minLength := readByline(filename)
	cipherText := truncate(cipherTextArray, minLength)
	key := guessKey([]byte(cipherText), minLength)
	getPlainText(cipherText, key)
}
