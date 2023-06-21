
// Constants
const p = BigInt("7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771");
const g = BigInt("4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143");
const q = BigInt("236234353446506858198510045061214171961");

// Fermat's theorem proof
function fermatProof(g) {
  const result = g ** (p - BigInt(1)) % p;
  if (result !== BigInt(1)) {
    throw new Error("Fermat fails!");
  }
}

fermatProof(g);

// Checking the order of g
function checkOrder(g, o) {
  const result = g ** o % p;
  if (result !== BigInt(1)) {
    throw new Error("Incorrect order!");
  }
}

checkOrder(g, q);

// Finding small factors of truncated phi(p)
const truncated_p = (p - BigInt(1)) / q;
const fct = [];

function factorize(n) {
  const factors = [];
  let d = BigInt(2);
  while (d * d <= n) {
    if (n % d === BigInt(0)) {
      factors.push(d);
      n /= d;
    } else {
      d += BigInt(1);
    }
  }
  if (n > 1) {
    factors.push(n);
  }
  return factors;
}

fct.push(...factorize(truncated_p));
const smallFactors = fct.filter((factor) => factor < BigInt(2 ** 16));

console.log(smallFactors.toString());

// Recovering the secret x
function randomRange(min, max) {
  const range = max - min + BigInt(1);
  const random = BigInt(Math.random() * range);
  return random + min;
}

const x = randomRange(BigInt(1), p - BigInt(1));
const hExp = g ** x % p;
const reducedValues = [];

function findH(v) {
  let a = randomRange(BigInt(1), p - BigInt(1));
  while (a ** ((p - BigInt(1)) / v) === BigInt(1)) {
    a = randomRange(BigInt(1), p - BigInt(1));
  }
  return a;
}

function findXModR(hExp, h, v) {
  for (let a = BigInt(1); a < v; a++) {
    if (hExp === h ** a) {
      return a;
    }
  }
  return BigInt(0);
}

for (const factor of smallFactors) {
  const h = findH(factor);
  const xModR = findXModR(hExp, h, factor);
  reducedValues.push([xModR, factor]);
}

const validValues = reducedValues.filter((value) => value[0] > BigInt(0) && value[1] !== BigInt(3));

function chineseRemainderTheorem(values) {
  const val2 = values.map((value) => value[1]);
  const val3 = values.map((value) => value[0]);
  const n = val2.reduce((a, b) => a * b, BigInt(1));
  if (q >= n) {
    throw new Error("Not possible to reconstruct the secret!");
  }
  const ni = val2.map((val) => n / val);
  let answer = BigInt(0);
  for (let i = 0; i < val2.length; i++) {
    if (gcd(ni[i], val2[i]) !== BigInt(1)) {
      throw new Error("Not coprime!");
    }
    const k = Number(ni[i]) % Number(val2[i]);
    const inverse = modInverse(k, val2[i]);
    answer += BigInt(val3[i]) * BigInt(ni[i]) * BigInt(inverse);
  }
  const quotient = answer / n;
  const qd = quotient * (n - q);
  answer -= qd;
  return (answer % q).toString();
}

function gcd(a, b) {
  if (b === BigInt(0)) {
    return a;
  }
  return gcd(b, a % b);
}

function modInverse(a, m) {
  let [x, y, gcd] = extendedEuclidean(a, m);
  if (gcd !== BigInt(1)) {
    throw new Error("The modular inverse does not exist.");
  }
  return (x % m + m) % m;
}

function extendedEuclidean(a, b) {
  if (b === BigInt(0)) {
    return [BigInt(1), BigInt(0), a];
  }
  const [x, y, gcd] = extendedEuclidean(b, a % b);
  return [y, x - (a / b) * y, gcd];
}

try {
  const recoveredSecret = chineseRemainderTheorem(validValues);
  console.log("Successfully recovered the secret x. Hence, the scheme breaks.");
  console.log(recoveredSecret);
} catch (error) {
  console.error(error);
}

