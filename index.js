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
const uri = process.env.MONGODB_URI;

// Database variables
let categoriesDB, codesDB, categoriesCollection, codesCollection;

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

let usersDB;
let rolesCollection;

// Connection function
async function connectDB() {
  if (!usersDB) {
    await client.connect();
    usersDB = client.db("usersDB");
    rolesCollection = usersDB.collection("rolesCollection");
    console.log("Connected to MongoDB!");
  }
  return { usersDB, rolesCollection };
}

// routes
app.get("/", (req, res) => {
  res.send("Hello from backend!");
});

// roles management
// get user roles
app.get("/users/roles", async (req, res) => {
  try {
    const { rolesCollection } = await connectDB();
    const cursor = rolesCollection.find();
    const result = await cursor.toArray();
    res.send(result);
  } catch (error) {
    console.error("Error:", error);
    res.status(500).send({ message: "Internal server error" });
  }
});

// get a user's role
app.get("/users/roles/:email", async (req, res) => {
  try {
    const { rolesCollection } = await connectDB();
    const email = req.params.email;
    const result = await rolesCollection.findOne({
      email: email,
    });
    if (!result) {
      return res.status(404).send({ message: "User role not found" });
    }
    res.send(result);
  } catch (error) {
    console.error("Error:", error);
    res.status(500).send({ message: "Internal server error" });
  }
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
