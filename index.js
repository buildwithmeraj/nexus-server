// add requirements
const express = require("express");
var cors = require("cors");
require("dotenv").config();
const admin = require("firebase-admin");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

// define variables
const app = express();
const port = process.env.PORT || 3000;
var serviceAccount = require("./nexus-ed400-firebase-adminsdk-fbsvc-4cd65fc7ce.json");
const uri = process.env.mongodb_uri;

// middleware
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);
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

// Create client outside with better options for serverless
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
  maxPoolSize: 10,
  minPoolSize: 0,
  socketTimeoutMS: 45000,
  connectTimeoutMS: 10000,
  serverSelectionTimeoutMS: 10000,
});

// Connection function
async function connectDB() {
  if (!categoriesDB) {
    await client.connect();
    categoriesDB = client.db("categoriesDB");
    codesDB = client.db("categoriesDB");
    categoriesCollection = categoriesDB.collection("categories");
    codesCollection = codesDB.collection("codes");
    console.log("Connected to MongoDB!");
  }
  return { categoriesCollection, codesCollection };
}

// routes
app.get("/", (req, res) => {
  res.send("Hello from backend!");
});
app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
