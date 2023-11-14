require('dotenv').config();


const crypto = require('crypto');

const defaults = {
    algorithm: "aes-256-gcm",
    keySize: 256,
    ivSize: 96
}


async function generateKey({keySize = defaults.keySize} = {}){
    const key = crypto.randomBytes(keySize/8);

    return {
        dataEncryptionKey: key.toString("hex"),
    }
}

async function decrypt (key = null, {algorithm = defaults.algorithm, tag = null, iv = null, cipherText = ""} = {}){
    if(!key || !iv || !tag){
        throw new Error("Please specify a valid 'key', 'iv' and 'tag'");
    }

    const decipher = crypto.createDecipheriv(algorithm, Buffer.from(key, "hex"), Buffer.from(iv, "hex"));
    decipher.setAuthTag(Buffer.from(tag, "hex"));

    const decrypted = Buffer.concat(
        [
            decipher.update(Buffer.from(cipherText, "hex")),
            decipher.final()
        ]
    )

    return decrypted.toString("utf-8")
}

async function encrypt({algorithm = defaults.algorithm, ivSize = defaults.ivSize, key = null, clear_text = ""} = {}){
    if(!key){
        throw new Error("Please specify a valid 'key'");
    }

    const keyBuffer = Buffer.from(key, "hex")
    const ivBuffer = crypto.randomBytes(ivSize/8);

    const cipher = crypto.createCipheriv(algorithm, keyBuffer, ivBuffer);

    const encrypted = Buffer.concat(
        [
            cipher.update(clear_text, 'utf8'),
            cipher.final()
        ]
    );

    const tag = cipher.getAuthTag();

    return {
        cipherText: encrypted.toString("hex"),
        tag: tag.toString("hex"),
        iv: ivBuffer.toString("hex")
    }
}

module.exports = {generateKey, encrypt, decrypt}
