// add requirements
const express = require("express");
var cors = require("cors");
require("dotenv").config();
const admin = require("firebase-admin");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

// define variables
const app = express();
const port = process.env.PORT || 3000;
const serviceAccount = require("./nexus-ed400-firebase-adminsdk-fbsvc-4cd65fc7ce.json");
const uri = process.env.MONGODB_URI;

// middleware
app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);

// firebase admin setup
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// -------------------------------
// DATABASE SETUP
// -------------------------------
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
  maxPoolSize: 10,
  connectTimeoutMS: 10000,
});

let usersDB, clubsDB, usersCollection, applicationsCollection, clubsCollection;

async function connectDB() {
  if (!usersDB || !clubsDB) {
    await client.connect();
    usersDB = client.db("usersDB");
    clubsDB = client.db("clubsDB");
    usersCollection = usersDB.collection("usersCollection");
    applicationsCollection = usersDB.collection("applicationsCollection");
    clubsCollection = clubsDB.collection("clubsCollection");
    console.log("Connected to MongoDB");
  }

  return { usersCollection, applicationsCollection, clubsCollection };
}

// -------------------------------
// MIDDLEWARE
// -------------------------------
const verifyFireBaseToken = async (req, res, next) => {
  const authorization = req.headers.authorization;
  if (!authorization)
    return res.status(401).send({ message: "unauthorized access" });

  const token = authorization.split(" ")[1];
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.token_email = decoded.email;
    next();
  } catch {
    return res.status(401).send({ message: "unauthorized access" });
  }
};

const verifyAdmin = async (req, res, next) => {
  try {
    const { usersCollection } = await connectDB();
    const user = await usersCollection.findOne({ email: req.token_email });

    if (user?.role !== "admin") {
      return res.status(403).send({ message: "forbidden access" });
    }
    next();
  } catch (e) {
    console.error(e);
    res.status(500).send({ message: "Internal server error" });
  }
};

const verifyClubManager = async (req, res, next) => {
  try {
    const { usersCollection } = await connectDB();
    const user = await usersCollection.findOne({ email: req.token_email });

    if (!user) {
      return res.status(404).send({ message: "User not found" });
    }

    if (user.role !== "clubManager" && user.role !== "admin") {
      return res.status(403).send({ message: "forbidden access" });
    }

    next();
  } catch (e) {
    console.error(e);
    res.status(500).send({ message: "Internal server error" });
  }
};

// -------------------------------
// ROUTES
// -------------------------------

app.get("/", (req, res) => res.send("Hello from backend!"));

// -------------------------------
// GET USER ROLE
// -------------------------------
app.get("/users/role/:email", async (req, res) => {
  try {
    const { usersCollection } = await connectDB();
    const result = await usersCollection.findOne({ email: req.params.email });

    if (!result)
      return res.status(404).send({ message: "User role not found" });

    res.send(result);
  } catch (e) {
    console.error(e);
    res.status(500).send({ message: "Internal server error" });
  }
});

// -------------------------------
// UPDATE USER ROLE (PROMOTE/DEMOTE)
// -------------------------------
app.patch(
  "/users/role/:id",
  verifyFireBaseToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { usersCollection, applicationsCollection } = await connectDB();
      const { type } = req.body;
      const id = req.params.id;

      const user = await usersCollection.findOne({ _id: new ObjectId(id) });
      if (!user) return res.status(404).send({ message: "User not found" });

      let newRole = user.role;

      // ------------------------------
      // ROLE UPDATE LOGIC
      // ------------------------------
      if (type === "promote") {
        if (user.role === "member") newRole = "clubManager";
        else if (user.role === "clubManager") newRole = "admin";
      } else if (type === "demote") {
        if (user.role === "clubManager") newRole = "member";
      }

      // Apply the role change
      const updateResult = await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { role: newRole } }
      );

      // ------------------------------
      // APPLICATION SYNCING LOGIC
      // ------------------------------
      const application = await applicationsCollection.findOne({
        email: user.email,
      });

      if (application) {
        // Case 1: Promote → approve pending app
        if (type === "promote" && ["clubManager", "admin"].includes(newRole)) {
          if (application.status === "pending") {
            await applicationsCollection.updateOne(
              { email: user.email },
              { $set: { status: "approved" } }
            );
          }
        }

        // Case 2: Demote → convert approved → pending
        if (type === "demote" && newRole === "member") {
          if (application.status === "approved") {
            await applicationsCollection.updateOne(
              { email: user.email },
              { $set: { status: "pending" } }
            );
          }
        }
      }

      res.send({
        message: "Role updated & application synced",
        newRole,
      });
    } catch (error) {
      console.error(error);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// -------------------------------
// APPLY FOR CLUB MANAGER
// -------------------------------
app.post("/users/apply-club-manager", verifyFireBaseToken, async (req, res) => {
  try {
    const { usersCollection, applicationsCollection } = await connectDB();
    const email = req.token_email;

    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(404).send({ message: "User not found" });

    if (user.role !== "member") {
      return res
        .status(400)
        .send({ message: "Only Members can apply for Club Manager" });
    }

    const existing = await applicationsCollection.findOne({ email });
    if (existing) {
      return res
        .status(400)
        .send({ message: "Already applied for Club Manager" });
    }

    const result = await applicationsCollection.insertOne({
      name: user.name,
      email,
      status: "pending",
      createdAt: new Date(),
    });

    res
      .status(201)
      .send({ message: "Application submitted", id: result.insertedId });
  } catch (e) {
    res.status(500).send({ message: "Internal server error" });
  }
});

// -------------------------------
// LIST ALL CLUB MANAGER APPLICATIONS
// -------------------------------
app.get(
  "/admin/club-manager-applications",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const { clubsCollection } = await connectDB();
      const apps = await applicationsCollection.find({}).toArray();

      res.send(apps);
    } catch (e) {
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// -------------------------------
// APPROVE CLUB MANAGER APPLICATION
// -------------------------------
app.patch(
  "/admin/club-manager-applications",
  verifyFireBaseToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { email } = req.body;
      const { usersCollection, applicationsCollection } = await connectDB();

      if (!email) return res.status(400).send({ message: "Email is required" });

      const application = await applicationsCollection.findOne({
        email,
        status: "pending",
      });
      if (!application) {
        return res
          .status(404)
          .send({ message: "Application not found or already approved" });
      }

      await usersCollection.updateOne(
        { email },
        { $set: { role: "clubManager" } }
      );
      await applicationsCollection.updateOne(
        { email },
        { $set: { status: "approved" } }
      );

      res.send({ message: "Application approved" });
    } catch (e) {
      console.error(e);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// -------------------------------
// CHECK APPLICATION STATUS
// -------------------------------
app.get(
  "/users/apply-club-manager/status",
  verifyFireBaseToken,
  async (req, res) => {
    try {
      const { applicationsCollection } = await connectDB();
      const email = req.token_email;

      const appStatus = await applicationsCollection.findOne({ email });

      if (!appStatus) return res.send({ found: false });

      res.send({ found: true, application: appStatus });
    } catch (e) {
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// -------------------------------
// ADD USER
// -------------------------------
app.post("/users", async (req, res) => {
  try {
    const { usersCollection } = await connectDB();
    const user = req.body;

    const exists = await usersCollection.findOne({ email: user.email });
    if (exists) return res.status(409).send({ message: "User already exists" });

    const newUser = {
      name: user.name,
      email: user.email,
      photoURL: user.photoURL,
      createdAt: user.createdAt || new Date(),
      role: "member",
    };

    const result = await usersCollection.insertOne(newUser);
    res.status(201).send({ message: "User created", id: result.insertedId });
  } catch (e) {
    res.status(500).send({ message: "Internal server error" });
  }
});

// -------------------------------
// LIST ALL USERS
// -------------------------------
app.get("/users", verifyFireBaseToken, verifyAdmin, async (req, res) => {
  try {
    const { usersCollection } = await connectDB();
    const users = await usersCollection.find().toArray();

    res.send(users);
  } catch (e) {
    res.status(500).send({ message: "Internal server error" });
  }
});

// -------------------------------
// CLUBS LIST FOR MANAGERS
// -------------------------------
app.get(
  "/clubs/:email",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const { clubsCollection } = await connectDB();
      const email = req.params.email;
      if (email !== req.token_email)
        return res.status(403).send({
          message: "You are not authorized to view clubs of other managers",
        });
      const filter = { managerEmail: email };
      const clubs = await clubsCollection.find(filter).toArray();
      res.send(clubs);
    } catch (e) {
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// -------------------------------
// ADD NEW CLUB (MANAGER / ADMIN)
// -------------------------------
app.post("/clubs", verifyFireBaseToken, verifyClubManager, async (req, res) => {
  try {
    const { clubsCollection } = await connectDB();
    const managerEmail = req.token_email;

    const {
      clubName,
      description,
      category,
      location,
      bannerImage,
      membershipFee,
    } = req.body;

    // Validate required fields
    if (!clubName || !description || !category || !location || !bannerImage) {
      return res
        .status(400)
        .send({ message: "All required fields must be provided" });
    }

    const newClub = {
      clubName,
      description,
      category,
      location,
      bannerImage,
      membershipFee: Number(membershipFee) || 0,
      managerEmail,
      status: "pending", // new clubs must be approved
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await clubsCollection.insertOne(newClub);

    res.status(201).send({
      message: "Club submitted successfully",
      id: result.insertedId,
      club: newClub,
    });
  } catch (e) {
    console.error(e);
    res.status(500).send({ message: "Internal server error" });
  }
});

// -------------------------------
// DELETE A CLUB
// -------------------------------
app.delete(
  "/clubs/:id",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const { clubsCollection } = await connectDB();
      const id = req.params.id;

      const club = await clubsCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!club) {
        return res.status(404).send({ message: "Club not found" });
      }

      // Only the owner (or admin) can delete the club
      if (club.managerEmail !== req.token_email) {
        return res
          .status(403)
          .send({ message: "Not authorized to delete this club" });
      }

      await clubsCollection.deleteOne({ _id: new ObjectId(id) });

      res.send({ message: "Club deleted successfully" });
    } catch (e) {
      console.error(e);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// -------------------------------
app.listen(port, () => console.log(`Backend running on port ${port}`));
