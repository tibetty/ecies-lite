const crypto = require('crypto');

const config = {
    curveName: 'secp256k1',
    cipherAlgorithm: 'aes-256-cbc',
    ivSize: 16
};

/**
 * Config the default parameters for ecies-lite
 * @param curveName: String - the elliptic curve to use
 * @param cipherAlgorithm: String - the cipher algorithm to use
 * @param ivSize: Number - the size (in bytes) of initialization vector (for cipher)
 * @return none
 */
exports.config = (curveName, cipherAlgorithm, ivSize) => {
    config.curveName = curveName;
    config.cipherAlgorithm = cipherAlgorithm;
    config.ivSize = ivSize;
};

/**
 * Encrypt a message using the recepient's public key
 * @param pk: Buffer - The recipient's public key
 * @param msg: Buffer - The message to encrypt
 * @param ?opts: {?curveName: String, ?esk: Buffer, ?compressEpk: Boolean, ?cipherAlgorithm: String, ?iv: Buffer}} opts - You can
 * specify the curve name, ephemeral private key, to compress ephemeral public key or not, cipher algorithm and initialization
 * vector to customize the output.
 * @return {epk: Buffer, iv: Buffer, ct: Buffer, mac: Buffer} - the ecies-lite structure with fields correspondingly stands for
 * ephemeral public key, initialization vector, cipher text, mac code for above data, etc.
 */
exports.encrypt = (pk, msg, opts) => {
    if (!opts)
        opts = {
            curveName: config.curveName,
            compressEpk: true,
            cipherAlgorithm: config.cipherAlgorithm
        };

    const ecdh = crypto.createECDH(opts.curveName || config.curveName);
    if (opts.esk) ecdh.setPrivateKey(opts.esk);
    else ecdh.generateKeys();
    let epk = ecdh.getPublicKey(null, opts.compressEpk ? 'compressed' : 'uncompressed');
    let hash = crypto.createHash('sha256').update(ecdh.computeSecret(pk)).digest();
    let encKey = hash.slice(0, 32), macKey = hash.slice(16);
    let iv = opts.iv || crypto.randomBytes(config.ivSize);
    let cipher = crypto.createCipheriv(opts.cipherAlgorithm || config.cipherAlgorithm, encKey, iv);
    let ct = cipher.update(msg);
    ct = Buffer.concat([ct, cipher.final()]);
    let mac = crypto.createHmac('sha256', macKey).update(Buffer.concat([epk, iv, ct])).digest();
    return {epk, iv, ct, mac};
};

/**
 * Decrypt a message in ecies-lite defined format using the recipient's private key
 * @param sk: Buffer - the recepient's private key
 * @param body: ecies-lite structure - the ecies-lite body (seen format in encrypt) to decrypt
 * @param ?opts: {?curveName: String, ?cipherAlgorithm: String} - to specify the curve name and cipher algorithm
 * @return Buffer - the plain text decrypted from the Ecies-lite body
 */
exports.decrypt = (sk, body, opts) => {
    if (!opts)
        opts = {
            curveName: config.curveName,
            cipherAlgorithm: config.cipherAlgorithm
        };

    const ecdh = crypto.createECDH(opts.curveName || config.curveName);
    ecdh.setPrivateKey(sk);
    with (body) {
        let hash = crypto.createHash('sha256').update(ecdh.computeSecret(epk)).digest();
        let encKey = hash.slice(0, 32), macKey = hash.slice(16);
        let mac = crypto.createHmac('sha256', macKey).update(Buffer.concat([epk, iv, ct])).digest();
        if (mac.compare(body.mac) !== 0)
            throw new Error('Corrupted Ecies-lite body: unmatched authentication code');
        let decipher = crypto.createDecipheriv(opts.cipherAlgorithm || config.cipherAlgorithm, encKey, iv);
        let pt = decipher.update(ct);
        return Buffer.concat([pt, decipher.final()]);
    }
};
