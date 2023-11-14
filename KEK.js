require('dotenv').config();


const crypto = require('crypto');
const { KeyClient, CryptographyClient } = require("@azure/keyvault-keys");
const { DefaultAzureCredential } = require("@azure/identity");

const azureCredential = new DefaultAzureCredential();
const keyVaultURL = process.env.KEY_VAULT_URL;
const client = new KeyClient(keyVaultURL, azureCredential);

const defaults = {
    keySize: 2048
}

const randomName = () => {
    const randomBytes = crypto.randomUUID();
    const name = Buffer.from(randomBytes).toString("base64");

    return name;
}

async function generateKey({keySize = defaults.keySize, name = randomName()} = {}){
    // Create Encryption Key
    const keyOps = ["encrypt", "decrypt", "sign", "verify"];
    
    // Create an RSA key with specified key operations
    const key = await client.createRsaKey(name, {
        keySize,
        keyOps
    });

    return {
        keyEncryptionKey: key,
        keyEncryptionName: name
    }
}

async function encrypt (KEK, clear_text) {
    const cryptographyClient = new CryptographyClient(KEK.id, azureCredential);

    const encrypted = await cryptographyClient.encrypt({
        algorithm: "RSA1_5",
        plaintext: Buffer.from(clear_text),
    });

    const cipherText = encrypted.result.toString("base64");

    return cipherText;
}

async function decrypt (name, cipherText) {
    const keyVaultKey = await client.getKey(name);

    const cryptographyClient = new CryptographyClient(keyVaultKey.id, azureCredential);

    const decrypted = await cryptographyClient.decrypt({
        algorithm: "RSA1_5",
        ciphertext: Buffer.from(cipherText, "base64"),
    });

    return decrypted.result.toString("utf-8");

}

module.exports = {generateKey, encrypt, decrypt}
