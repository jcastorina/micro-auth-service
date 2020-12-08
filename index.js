require("dotenv").config();

const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const { Credentials } = require("./lib/credentials");
const { sign, verify } = require("./lib/jwt");
const PORT = process.env.PORT || 4444;
const responseTypes = {
  200: "OK",
  201: "Created",
  400: "Bad Request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not Found",
  500: "Internal Server Error",
};

app.use(express.json());
app.listen(PORT, () => console.log(`listening on ${PORT}`));

/////////////////////////////////////////////////////////////
//
// Auth Microservice.
// Returns 403 for bad server-to-server JWT
// Returns 401 for bad user login credentials from client app
//
/////////////////////////////////////////////////////////////

// Auth middleware on all DB APIs
// Return 403 for Bad Token, otherwise continue processing request

const authHandler = function (req, res, next) {
  if (req.headers.authorization) {
    const token = req.headers.authorization.split(" ")[1];
    if (token) {
      const authorized = verify(token);
      if (authorized) {
        console.log("server authorized, completing request...");
        return next();
      }
    }
  }
  console.log("unauthorized");
  res.writeHead(403);
  return res.end(responseTypes[403]);
};

// Generate new key and return to requesting server.
// This is the biggest security vulnerability
// as keys can be generated if one knows the passphrase,
// and can use server creds if they know server name.
// Look into other patterns for this workflow.
// Return 201 and Token to Requester.  Return 403 for Bad Credentials

app.post("/getKey", (req, res) => {
  const { name, passphrase } = req.body;
  if (passphrase === process.env.JWT_PASSPHRASE && name) {
    res.writeHead(201);
    return res.end(sign(name));
  }
  res.writeHead(403);
  return res.end(responseTypes[403]);
});

// Create new DB entry for user, generate a new hash
// Return 201 for Success, 500 for Other Failure

app.post("/create", authHandler, async (req, res) => {
  const { username: usr, password: pw } = req.body;
  console.log(req.body);
  try {
    let salt = await bcrypt.genSalt(10);
    let hash = await bcrypt.hash(pw, salt);
    await Credentials.sync().then(async function () {
      await Credentials.create({
        id: usr,
        hash: hash,
        salt: salt,
      });
      console.log(usr, "registered");
      res.writeHead(201);
      return res.end(responseTypes[201]);
    });
  } catch (e) {
    console.error(e, "reg error");
    res.writeHead(500);
    return res.end(responseTypes[500]);
  }
});

// Validate credentials against existing db entry
// Return 200 for Success, 401 for Bad Login, 500 for Other Failure

app.post("/read", authHandler, async (req, res) => {
  const { username: usr, password: pw } = req.body;
  try {
    const userItem = await Credentials.findOne({ where: { id: usr } });
    const { hash } = userItem.dataValues;

    bcrypt.compare(`${pw}`, hash, (err, result) => {
      if (err) {
        console.error(err, "error with async bcrypt compare");
        res.writeHead(500);
        return res.end(responseTypes[500]);
      }
      if (!result) {
        console.error("bad pass");
        res.writeHead(401);
        return res.end(responseTypes[401]);
      }
      console.log(usr, "logged in");
      res.writeHead(200);
      return res.end(responseTypes[200]);
    });
  } catch (e) {
    console.error(e, "catch login");
    res.writeHead(401);
    return res.end(responseTypes[401]);
  }
});

// Update password
//

app.post("/update", authHandler, async (req, res) => {
  const { username: usr, password: pw } = req.body;
  console.log(req.body);
  try {
    const userItem = await Credentials.findOne({ where: { id: usr } });
    if (userItem) {
      let salt = await bcrypt.genSalt(10);
      let hash = await bcrypt.hash(pw, salt);
      await userItem.update({ hash, salt });
      console.log("successfully updated pw for ", usr);
      res.writeHead(200);
      return res.end(responseTypes[200]);
    }
    console.log("no user for: ", usr);
    res.writeHead(400);
    return res.end(responseTypes[400]);
  } catch (e) {
    console.error(e, "catch block: update error");
    res.writeHead(500);
    return res.end(responseTypes[500]);
  }
});

// Delete user
//

app.post("/delete", authHandler, async (req, res) => {
  const { username: usr, password: pw } = req.body;
  try {
    const destroy = await Credentials.destroy({ where: { id: usr } });
    if (destroy) {
      console.log("destroyed user: ", usr);
      res.writeHead(200);
      return res.end(responseTypes[200]);
    }
    console.log("delete error: can't find user: ", usr);
    res.writeHead(400);
    return res.end(responseTypes[400]);
  } catch (e) {
    console.error(e, "catch block: delete error");
    res.writeHead(500);
    return res.end(responseTypes[500]);
  }
});

// Handle all other reqs
//

app.all("/*", function (req, res, next) {
  console.log("bad req - no route");
  res.writeHead(403);
  res.end(responseTypes[403]);
});
