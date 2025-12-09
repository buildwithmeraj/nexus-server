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
app.use(express.json());
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
// check admin middleware
const verifyAdmin = async (req, res, next) => {
  const token_email = req.token_email;
  try {
    const { usersCollection } = await connectDB();
    const user = await usersCollection.findOne({ email: token_email });
    if (user?.role !== "admin") {
      return res.status(403).send({ message: "forbidden access" });
    }
    next();
  } catch (error) {
    console.error("Error:", error);
    res.status(500).send({ message: "Internal server error" });
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
let usersCollection;

// Connection function
async function connectDB() {
  if (!usersDB) {
    await client.connect();
    usersDB = client.db("usersDB");
    usersCollection = usersDB.collection("usersCollection");
    console.log("Connected to MongoDB!");
  }
  return { usersDB, usersCollection };
}

// routes
app.get("/", (req, res) => {
  res.send("Hello from backend!");
});

// roles management

// get a user's role
app.get("/users/roles/:email", verifyFireBaseToken, async (req, res) => {
  try {
    const { usersCollection } = await connectDB();
    const email = req.params.email;
    const result = await usersCollection.findOne({
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

// add a user
app.post("/users", async (req, res) => {
  try {
    const user = req.body;
    const newUser = {
      name: user.name,
      email: user.email,
      role: "member",
      createdAt: user.createdAt || new Date(),
    };
    const { usersCollection } = await connectDB();
    const existingUser = await usersCollection.findOne({ email: user.email });
    if (existingUser) {
      return res.status(409).send({ message: "User already exists" });
    }
    const result = await usersCollection.insertOne(newUser);
    res.send(result);
  } catch (error) {
    console.error("Error:", error);
    res.status(500).send({ message: "Internal server error" });
  }
});

// list all users for admin
app.get("/users", verifyFireBaseToken, verifyAdmin, async (req, res) => {
  try {
    const { usersCollection } = await connectDB();
    const users = await usersCollection.find({}).toArray();
    res.json(users);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error fetching categories", error: error.message });
  }
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
