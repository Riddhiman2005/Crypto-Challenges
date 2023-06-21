//Since the first line of the challenge asks us to assume Javascript programmer, so solution-1 of C-40 is by JAVA Script


// Function to compute the modular multiplicative inverse (invmod)
// Returns -1 if the inverse doesn't exist
function invmod(a, n) {
  const [g, x] = egcd(a, n);
  if (g !== 1) {
    return -1; // Modular inverse doesn't exist
  }
  return (x % n + n) % n;
}

// Extended Euclidean Algorithm (egcd) to compute gcd and Bézout's identity
function egcd(a, b) {
  if (b === 0) {
    return [a, 1, 0];
  }
  const [g, x, y] = egcd(b, a % b);
  return [g, y, x - Math.floor(a / b) * y];
}

// Function to decrypt RSA using the Chinese Remainder Theorem (CRT) and cube root
function decryptCRT(ciphertexts, moduli) {
  // Compute the product of all moduli
  const N = moduli.reduce((product, modulus) => product * modulus, 1);

  // Compute the result using CRT
  let result = 0;
  for (let i = 0; i < ciphertexts.length; i++) {
    const crtProduct = N / moduli[i]; // m_s_n
    const crtInverse = invmod(crtProduct, moduli[i]); // invmod(m_s_n, n_n)
    result += ciphertexts[i] * crtProduct * crtInverse;
  }

  // Take the cube root of the result
  const plaintext = Math.cbrt(result);

  return plaintext;
}

// Example usage
const ciphertexts = [1234, 5678, 91011];
const moduli = [17, 23, 31];

const plaintext = decryptCRT(ciphertexts, moduli);
console.log("Plaintext:", plaintext);
