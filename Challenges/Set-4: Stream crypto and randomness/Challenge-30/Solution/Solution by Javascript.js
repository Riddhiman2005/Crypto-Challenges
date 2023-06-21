
const crypto = require('crypto');
const fs = require('fs');

class MD4 {
  constructor(message, ml = null, A = 0x67452301, B = 0xefcdab89, C = 0x98badcfe, D = 0x10325476) {
    this.A = A;
    this.B = B;
    this.C = C;
    this.D = D;

    if (ml === null) {
      ml = message.length * 8;
    }

    const length = Buffer.alloc(8);
    length.writeBigUInt64LE(BigInt(ml));

    while (message.length > 64) {
      this._handle(message.slice(0, 64));
      message = message.slice(64);
    }

    message = Buffer.concat([message, Buffer.from([0x80])]);
    message = Buffer.concat([message, Buffer.alloc((56 - message.length % 64) % 64)]);
    message = Buffer.concat([message, length]);

    while (message.length) {
      this._handle(message.slice(0, 64));
      message = message.slice(64);
    }
  }

  _F(x, y, z) {
    return (x & y) | (~x & z);
  }

  _G(x, y, z) {
    return (x & y) | (x & z) | (y & z);
  }

  _H(x, y, z) {
    return x ^ y ^ z;
  }

  _handle(chunk) {
    const X = [];
    for (let i = 0; i < 16; i++) {
      X.push(chunk.readUInt32LE(i * 4));
    }

    let A = this.A;
    let B = this.B;
    let C = this.C;
    let D = this.D;

    for (let i = 0; i < 16; i++) {
      const k = i;
      if (i % 4 === 0) {
        A = this._leftRotate((A + this._F(B, C, D) + X[k]) & 0xffffffff, 3);
      } else if (i % 4 === 1) {
        D = this._leftRotate((D + this._F(A, B, C) + X[k]) & 0xffffffff, 7);
      } else if (i % 4 === 2) {
        C = this._leftRotate((C + this._F(D, A, B) + X[k]) & 0xffffffff, 11);
      } else if (i % 4 === 3) {
        B = this._leftRotate((B + this._F(C, D, A) + X[k]) & 0xffffffff, 19);
      }
    }

    for (let i = 0; i < 16; i++) {
      const k = (i % 4) * 4 + Math.floor(i / 4);
      if (i % 4 === 0) {
        A = this._leftRotate((A + this._G(B, C, D) + X[k] + 0x5a827999) & 0xffffffff, 3);
      } else if (i % 4 === 1) {
        D = this._leftRotate((D + this._G(A, B, C) + X[k] + 0x5a827999) & 0xffffffff, 5);
      } else if (i % 4 === 2) {
        C = this._leftRotate((C + this._G(D, A, B) + X[k] + 0x5a827999) & 0xffffffff, 9);
      } else if (i % 4 === 3) {
        B = this._leftRotate((B + this._G(C, D, A) + X[k] + 0x5a827999) & 0xffffffff, 13);
      }
    }

    const order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
    for (let i = 0; i < 16; i++) {
      const k = order[i];
      if (i % 4 === 0) {
        A = this._leftRotate((A + this._H(B, C, D) + X[k] + 0x6ed9eba1) & 0xffffffff, 3);
      } else if (i % 4 === 1) {
        D = this._leftRotate((D + this._H(A, B, C) + X[k] + 0x6ed9eba1) & 0xffffffff, 9);
      } else if (i % 4 === 2) {
        C = this._leftRotate((C + this._H(D, A, B) + X[k] + 0x6ed9eba1) & 0xffffffff, 11);
      } else if (i % 4 === 3) {
        B = this._leftRotate((B + this._H(C, D, A) + X[k] + 0x6ed9eba1) & 0xffffffff, 15);
      }
    }

    this.A = (this.A + A) & 0xffffffff;
    this.B = (this.B + B) & 0xffffffff;
    this.C = (this.C + C) & 0xffffffff;
    this.D = (this.D + D) & 0xffffffff;
  }

  digest() {
    const buffer = Buffer.alloc(16);
    buffer.writeUInt32LE(this.A, 0);
    buffer.writeUInt32LE(this.B, 4);
    buffer.writeUInt32LE(this.C, 8);
    buffer.writeUInt32LE(this.D, 12);
    return buffer;
  }

  hexDigest() {
    return this.digest().toString('hex');
  }

  _leftRotate(value, amount) {
    return ((value << amount) | (value >>> (32 - amount))) & 0xffffffff;
  }
}

class Oracle {
  constructor() {
    const dictionary = fs.readFileSync('/usr/share/dict/words', 'utf8');
    const candidates = dictionary.split('\n');
    this._key = candidates[Math.floor(Math.random() * candidates.length)];
  }

  validate(message, digest) {
    const keyBuffer = Buffer.from(this._key);
    const messageBuffer = Buffer.from(message);
    const md4 = new MD4(Buffer.concat([keyBuffer, messageBuffer]));
    return md4.hexDigest() === digest;
  }

  generateDigest(message) {
    const keyBuffer = Buffer.from(this._key);
    const messageBuffer = Buffer.from(message);
    const md4 = new MD4(Buffer.concat([keyBuffer, messageBuffer]));
    return md4.hexDigest();
  }
}

function mdPad(message) {
  const ml = message.length * 8;

  message = Buffer.concat([message, Buffer.from([0x80])]);
  message = Buffer.concat([message, Buffer.alloc((56 - message.length % 64) % 64)]);
  const lengthBuffer = Buffer.alloc(8);
  lengthBuffer.writeBigInt64LE(BigInt(ml));
  message = Buffer.concat([message, lengthBuffer]);

  return message;
}

function lengthExtensionAttack(message, originalDigest, oracle) {
  const extraPayload = Buffer.from(';admin=true');

  for (let keyLength = 0; keyLength < 100; keyLength++) {
    const forgedMessage = mdPad(Buffer.concat([Buffer.from('A'.repeat(keyLength)), message.slice(keyLength)]))
      .slice(keyLength)
      .concat(extraPayload);

    const h = Buffer.from(originalDigest, 'hex').readUInt32LE();

    const forgedDigest = new MD4(extraPayload, (keyLength + forgedMessage.length) * 8, h[0], h[1], h[2], h[3]).hexDigest();

    if (oracle.validate(forgedMessage, forgedDigest)) {
      return { forgedMessage, forgedDigest };
    }
  }

  throw new Error('It was not possible to forge the message: maybe the key was longer than 100 characters.');
}

function main() {
  const oracle = new Oracle();

  const message = Buffer.from(
    'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
  );
  const messageDigest = oracle.generateDigest(message);

  const { forgedMessage, forgedDigest } = lengthExtensionAttack(message, messageDigest, oracle);

  if (!forgedMessage.includes(';admin=true')) {
    throw new Error('Failed to forge the message.');
  }
  if (!oracle.validate(forgedMessage, forgedDigest)) {
    throw new Error('The forged message does not have a valid MAC.');
  }
}

main();
