# ecies-lite

A lightweight ECIES tool implemented in pure Node.JS

## Motivation

First of all, `eccrypto` is a great tool that supports many EC crypto functions. However, it was developed years ago, and the crypto library has evolved a lot since then. It seems that ECIES (Elliptic Curve Integrated Encryption Scheme) can be implemented in pure Node.JS, so I re-implemented it with the help of the latest crypto module released with Node.JS 10.x (according to my test, it runs pretty well with any node version after 6.x).

* Multiple Curves, KDF: SHA-256, HMAC: MAC-WITH-SHA-256, Multiple Cipher Algorithms

## Usage

### ECIES

```js
const crypto = require('crypto'),
    ecies = require('ecies-lite');

let ecdh = crypto.createECDH('secp256k1');
ecdh.generateKeys();
let publicKey = ecdh.getPublicKey();
let body = ecies.encrypt(publicKey, Buffer.from('This message is for demo purpose'));
for (let k of Object.keys(body)) {
    console.log(`${k}(${body[k].length}B):`, body[k].toString('base64'));
}

let plain = ecies.decrypt(ecdh.getPrivateKey(), body);
console.log('Decrypted plain text:', plain.toString('utf-8'));
```

## License

ecies-lite - A lightweight ECIES tool implemented in pure Node.JS

Written in 2018 by tibetty <xihua.duan@gmail.com>
