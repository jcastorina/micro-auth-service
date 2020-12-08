require("dotenv").config();
const jwt = require("jsonwebtoken");
const readFileSync = require("fs").readFileSync;

const privateKey = readFileSync(process.env.PATH_PRIVKEY);
const publicKey = readFileSync(process.env.PATH_PUBKEY);
const passphrase = process.env.JWT_PASSPHRASE;

const signOpts = {
  //expiresIn: 10,
  algorithm: "RS256",
};

const signKey = {
  key: privateKey,
  passphrase,
};

const verifyOpts = {
  //expiresIn: 10,
  algorithm: ["RS256"],
};

module.exports = {
  sign: (payload) => {
    //you can provide sign/verify opts from content server for things like expiry
    return jwt.sign({ usr: payload }, signKey, signOpts);
  },
  verify: (token) => {
    try {
      return jwt.verify(token, publicKey, verifyOpts);
    } catch (e) {
      console.error(e);
      return false;
    }
  },
};
