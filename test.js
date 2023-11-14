console.log("Welcome to the TEST script");

const identity = require("./index.js")

// These should be stored as ENV vars in prod environment

const username = "arthurbowyer";
const password = "mypassword2";
const service = "Vanilla";

/*const newUser = identity.create(username, password, service);

identity.authenticate(username, password).then((result) => {
    console.log("authentication: ", result);
});*/

async function main(){
    //const newUser = await identity.create(username, password, service);
    //console.log("newUser:", newUser);

    const authenticated = await identity.authenticate(username, password);
    console.log("authenticated:", authenticated);

}

main();