const crypto = require('crypto'),
	ecies = require('.');

let recEcdh = crypto.createECDH(`secp256k1`);
recEcdh.generateKeys();
let body = ecies.encrypt(recEcdh.getPublicKey(), Buffer.from('This message is encrypted by ecies-lite with default parameters'));
for (const k of Object.keys(body)) {
	console.log(`${k} (${body[k].length}B):`, body[k].toString('base64'));
}
console.log(ecies.decrypt(recEcdh.getPrivateKey(), body).toString('utf-8'));

const curveName = 'prime256v1';
recEcdh = crypto.createECDH(curveName);
recEcdh.generateKeys();
const ephemEcdh = crypto.createECDH(curveName);
ephemEcdh.generateKeys();
body = ecies.encrypt(recEcdh.getPublicKey(), Buffer.from('This message is encrypted by ecies-lite with an assigned ephemeral key'), {esk: ephemEcdh.getPrivateKey(), curveName});
console.log(ecies.decrypt(recEcdh.getPrivateKey(), body, {curveName}).toString('utf-8'));
