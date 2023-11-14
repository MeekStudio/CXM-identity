const authenticator = require("otplib").authenticator;
const crypto = require('crypto');
const cosmos = require("@MeekStudio/CXM-cosmos");
const argon2 = require("argon2");

const DEK = require("./DEK.js");
const KEK = require("./KEK.js");

// Connect to Azure Key Vault

const serverSalt = "69239f4429f5402fb2e3668f1a7b3de8"; // Get from Azure Secrets

const userDEKs = cosmos.connect({
    database: "vanillacx-accounts",
    collection: "DEKS"
});

const userSalts = cosmos.connect({
    database: "vanillacx-accounts",
    collection: "salts"
});

const users = cosmos.connect({
    database: "vanillacx-accounts",
    collection: "users"
});

const certificates = cosmos.connect({
    database: "vanillacx-accounts",
    collection: "certificates"
});


const generateSalts = (quantity) => {
    const salts = [];

    for(let n = 0; n < quantity; n++){
        let random = crypto.randomUUID();
        random = random.replace(/-/g, "");

        salts.push(random)
    }

    return salts;
}

const generateOTPAuth = (clear_username, clear_service) => {
    // Create otpauth
    const totp = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(clear_username, clear_service, totp);

    return otpauth;
}


async function checkIfUserAccountExists (clear_username) {
    const username = await argon2.hash(clear_username, {salt: Buffer.from(serverSalt)});

    const result = await userSalts.findOne({
        username: username
    })

    return result
}

async function hashAndDeriveUUIDs(UUID, clear_password, clear_username, salts){
    const certificates = Buffer.from(await argon2.hash(`${UUID}${clear_password}${clear_username}`, {salt: Buffer.from(salts[1])})).toString("base64");
    const users = Buffer.from(await argon2.hash(`${certificates}`, {salt: Buffer.from(salts[2])})).toString("base64");
    const email = Buffer.from(await argon2.hash(`${users}`, {salt: Buffer.from(salts[3])})).toString("base64");
    const contacts = Buffer.from(await argon2.hash(`${email}`, {salt: Buffer.from(salts[4])})).toString("base64");
    const content = Buffer.from(await argon2.hash(`${contacts}`, {salt: Buffer.from(salts[5])})).toString("base64");
    const files = Buffer.from(await argon2.hash(`${content}`, {salt: Buffer.from(salts[6])})).toString("base64");
    const deks = Buffer.from(await argon2.hash(`${files}`, {salt: Buffer.from(salts[7])})).toString("base64");


    return {
        certificates,
        deks,
        users,
        email,
        contacts,
        content,
        files
    }
}


async function create (clear_username, clear_password, clear_service = "Vanilla CX") {
    
    const exists = await checkIfUserAccountExists(clear_username);

    if(exists){
        return "ACCOUNT_ALREADY_EXISTS"
    }

    const salts = generateSalts(10);
    const UUID = crypto.randomUUID();
    const hashedUUIDs = await hashAndDeriveUUIDs(UUID, clear_password, clear_username, salts);

    const {dataEncryptionKey} = await DEK.generateKey();
    const {keyEncryptionKey, keyEncryptionName} = await KEK.generateKey();

    const encryptedDEK = await KEK.encrypt(keyEncryptionKey, dataEncryptionKey);
    
    const otpAuth = generateOTPAuth(clear_username, clear_service);

    const profile = JSON.stringify({
        contact: [{
            type: "email",
            value: "lee@bowyer.fr",
            verfied: false
        },{
            type: "phone",
            value: "0033658302010",
            verfied: false
        }],
        authentication: {
            otpAuth: otpAuth
        }
    });

    const encryptedProfile = await DEK.encrypt({
        key: dataEncryptionKey,
        clear_text: profile
    })

    const salts_document = {
        username: await argon2.hash(clear_username, {salt: Buffer.from(serverSalt)}),
        salts
    }
    const users_document = {
        uuid: UUID,
        username: await argon2.hash(clear_username, {salt: Buffer.from(salts[0])}),
        password: await argon2.hash(clear_password, {salt: Buffer.from(salts[1])}),
        profile: encryptedProfile
    }
    const certificates_document = {
        uuid: hashedUUIDs.certificates,
        certificate: keyEncryptionName
    }

    const dek_document = {
        uuid: hashedUUIDs.deks,
        dataEncryptionKey: encryptedDEK
    }

    userSalts.insertOne(salts_document)
    users.insertOne(users_document)
    certificates.insertOne(certificates_document);
    userDEKs.insertOne(dek_document);

    return "ACCOUNT_CREATED"

}


async function authenticate (clear_username, clear_password) {

    const userAccount = await checkIfUserAccountExists(clear_username);

    if(!userAccount){
        return "ACCOUNT_NOT_FOUND"
    }

    const salts = userAccount.salts;
    const username = await argon2.hash(clear_username, {salt: Buffer.from(salts[0])})

    const user_document = await users.findOne({
        username
    })

    const hashedPassword = await argon2.hash(clear_password, {salt: Buffer.from(salts[1])});

    const UUID = user_document.uuid;

    if(hashedPassword !== user_document.password){
        return "INCORRECT_PASSWORD";
    } 

    const hashedUUIDs = await hashAndDeriveUUIDs(UUID, clear_password, clear_username, salts);

    const certificate_document = await certificates.findOne({
        uuid: hashedUUIDs.certificates
    })

    const dek_document = await userDEKs.findOne({
        uuid: hashedUUIDs.deks
    });

    const decryptedDEK = await KEK.decrypt(certificate_document.certificate, dek_document.dataEncryptionKey);

    const decryptedData = await DEK.decrypt(decryptedDEK, user_document.profile);

    return decryptedData;

}

module.exports = {create, authenticate}