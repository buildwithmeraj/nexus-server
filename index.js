// add requirements
const express = require("express");
var cors = require("cors");
require("dotenv").config();
const admin = require("firebase-admin");

// define variables
const app = express();
const port = process.env.PORT || 3000;
var serviceAccount = require("./nexus-ed400-firebase-adminsdk-fbsvc-4cd65fc7ce.json");

// middleware
app.use(cors());
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// firebase admin middleware
const verifyFireBaseToken = async (req, res, next) => {
  const authorization = req.headers.authorization;
  if (!authorization) {
    return res.status(401).send({ message: "unauthorized access" });
  }
  const token = authorization.split(" ")[1];

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.token_email = decoded.email;
    next();
  } catch (error) {
    return res.status(401).send({ message: "unauthorized access" });
  }
};

// routes
app.get("/", (req, res) => {
  res.send("Hello from backend!");
});
app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
