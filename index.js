// add requirements
const express = require("express");
var cors = require("cors");
require("dotenv").config();
const admin = require("firebase-admin");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

// define variables
const app = express();
const port = process.env.PORT || 3000;
const serviceAccount = require("./nexus-ed400-firebase-adminsdk-fbsvc-4cd65fc7ce.json");
const uri = process.env.MONGODB_URI;
const clientUrl = process.env.CLIENT_URL || "http://localhost:5173";

// middleware
app.use(express.json());
app.use(
  cors({
    origin: clientUrl, // Use env variable
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

let usersDB,
  clubsDB,
  usersCollection,
  applicationsCollection,
  clubsCollection,
  membershipsCollection,
  eventsCollection,
  eventRegistrationsCollection;

async function connectDB() {
  if (!usersDB || !clubsDB) {
    await client.connect();
    usersDB = client.db("usersDB");
    clubsDB = client.db("clubsDB");
    usersCollection = usersDB.collection("usersCollection");
    applicationsCollection = usersDB.collection("applicationsCollection");
    clubsCollection = clubsDB.collection("clubsCollection");
    membershipsCollection = clubsDB.collection("membershipsCollection");
    eventsCollection = clubsDB.collection("eventsCollection");
    eventRegistrationsCollection = clubsDB.collection(
      "eventRegistrationsCollection"
    );

    console.log("Connected to MongoDB");
  }

  return {
    usersCollection,
    applicationsCollection,
    clubsCollection,
    membershipsCollection,
    eventsCollection,
    eventRegistrationsCollection,
  };
}

async function createIndexes() {
  try {
    const {
      membershipsCollection,
      eventsCollection,
      eventRegistrationsCollection,
    } = await connectDB();

    // Drop old problematic indexes first
    try {
      await membershipsCollection.dropIndex("userEmail_1_clubId_1_paymentId_1");
      console.log("Dropped old memberships index");
    } catch (e) {
      // Index doesn't exist, that's fine
    }

    try {
      await membershipsCollection.dropIndex("paymentId_1");
      console.log("Dropped old paymentId index");
    } catch (e) {
      // Index doesn't exist, that's fine
    }

    // Memberships indexes - FIXED
    // 1. Prevent duplicate active memberships per user-club
    await membershipsCollection.createIndex(
      { userEmail: 1, clubId: 1, status: 1 },
      { unique: true, sparse: true }
    );
    console.log("Created index: userEmail_clubId_status");

    // 2. Index for payment lookup (paymentId can be null for free clubs)
    await membershipsCollection.createIndex({ paymentId: 1 }, { sparse: true });
    console.log("Created index: paymentId");

    // 3. General lookup indexes
    await membershipsCollection.createIndex({ userEmail: 1 });
    console.log("Created index: userEmail");

    await membershipsCollection.createIndex({ clubId: 1 });
    console.log("Created index: clubId");

    // Events indexes
    await eventsCollection.createIndex({ clubId: 1 });
    console.log("Created index: events.clubId");

    await eventsCollection.createIndex({ createdAt: -1 });
    console.log("Created index: events.createdAt");

    // Event Registrations indexes
    await eventRegistrationsCollection.createIndex(
      { eventId: 1, userEmail: 1 },
      { unique: true, sparse: true }
    );
    console.log("Created index: eventId_userEmail");

    await eventRegistrationsCollection.createIndex({ userEmail: 1 });
    console.log("Created index: eventRegistrations.userEmail");

    await eventRegistrationsCollection.createIndex({ eventId: 1 });
    console.log("Created index: eventRegistrations.eventId");

    console.log("✅ Database indexes created successfully");
  } catch (err) {
    console.error("❌ Error creating indexes:", err.message);
  }
}

// Call this after connecting
connectDB().then(() => createIndexes());

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
      //const { clubsCollection } = await connectDB();
      const { applicationsCollection } = await connectDB();
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
// LIST ALL EVENTS
// -------------------------------
app.get("/events", async (req, res) => {
  try {
    const { eventsCollection } = await connectDB();
    let clubId = req.query.clubId;
    let limit = parseInt(req.query.limit, 10);

    if (isNaN(limit) || limit <= 0) {
      limit = 0;
    }

    let query = {};

    if (clubId) {
      query = { clubId: new ObjectId(clubId) };
    }
    const events = await eventsCollection
      .find(query)
      .sort({ _id: -1 })
      .limit(limit)
      .toArray();
    res.send(events);
  } catch (e) {
    res.status(500).send({ message: "Internal server error" });
  }
});

// -------------------------------
// FETCH A CLUB
// -------------------------------
app.get("/clubs/details/:param", async (req, res) => {
  try {
    const param = req.params.param;
    const { clubsCollection } = await connectDB();

    const isObjectId = ObjectId.isValid(param);

    if (isObjectId) {
      const club = await clubsCollection.findOne({
        _id: new ObjectId(param),
      });

      if (!club) {
        return res.status(404).send({ message: "Club not found" });
      }

      return res.send(club);
    }
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Internal server error" });
  }
});

// -------------------------------
// FETCH A CLUB FOR ADMIN
// -------------------------------
app.get(
  "/clubs/:param",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const param = req.params.param;
      const { clubsCollection, usersCollection } = await connectDB();

      const isObjectId = ObjectId.isValid(param);

      if (isObjectId) {
        const club = await clubsCollection.findOne({
          _id: new ObjectId(param),
        });

        if (!club) {
          return res.status(404).send({ message: "Club not found" });
        }

        if (club.managerEmail !== req.token_email) {
          const user = await usersCollection.findOne({
            email: req.token_email,
          });

          if (user?.role !== "admin") {
            return res.status(403).send({
              message: "You are not authorized to access this club",
            });
          }
        }

        return res.send(club);
      }
      const email = param;

      if (email !== req.token_email) {
        return res.status(403).send({
          message: "You are not authorized to view clubs of other managers",
        });
      }

      const clubs = await clubsCollection
        .find({ managerEmail: email })
        .toArray();

      return res.send(clubs);
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// -------------------------------
// CHECK MEMBERSHIP STATUS
// -------------------------------
app.get(
  "/clubs/:clubId/membership-status",
  verifyFireBaseToken,
  async (req, res) => {
    try {
      const { clubId } = req.params;
      const email = req.token_email;

      const { membershipsCollection } = await connectDB();

      if (!ObjectId.isValid(clubId)) {
        return res.status(400).send({ message: "Invalid club ID" });
      }

      // Find membership record
      const membership = await membershipsCollection.findOne({
        userEmail: email,
        clubId: new ObjectId(clubId),
      });

      // No membership found
      if (!membership) {
        return res.send({
          isMember: false,
          status: "none",
        });
      }

      // Auto-expire expired memberships
      if (
        membership.expiresAt &&
        new Date(membership.expiresAt).getTime() < Date.now()
      ) {
        await membershipsCollection.updateOne(
          { _id: membership._id },
          { $set: { status: "expired" } }
        );

        membership.status = "expired";
      }

      return res.send({
        isMember: membership.status === "active",
        status: membership.status,
        paymentId: membership.paymentId || null,
        joinedAt: membership.joinedAt,
        expiresAt: membership.expiresAt,
      });
    } catch (err) {
      console.error(err);
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
// UPDATE CLUB DETAILS (MANAGER / ADMIN)
// -------------------------------
app.patch(
  "/clubs/:id",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const { clubsCollection, usersCollection } = await connectDB();
      const id = req.params.id;

      const existingClub = await clubsCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!existingClub) {
        return res.status(404).send({ message: "Club not found" });
      }

      // Only owner or admin can edit
      const user = await usersCollection.findOne({
        email: req.token_email,
      });

      if (
        existingClub.managerEmail !== req.token_email &&
        user?.role !== "admin"
      ) {
        return res
          .status(403)
          .send({ message: "Not authorized to update this club" });
      }

      const {
        clubName,
        description,
        category,
        location,
        membershipFee,
        bannerImage,
      } = req.body;

      const updateDoc = {
        $set: {
          clubName,
          description,
          category,
          location,
          membershipFee: Number(membershipFee),
          bannerImage,
          updatedAt: new Date(),
        },
      };

      await clubsCollection.updateOne({ _id: new ObjectId(id) }, updateDoc);

      res.send({ message: "Club updated successfully" });
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// -------------------------------
// DELETE A CLUB
// -------------------------------
app.delete(
  "/clubs/:id",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const { clubsCollection, usersCollection } = await connectDB();
      const id = req.params.id;

      const club = await clubsCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!club) {
        return res.status(404).send({ message: "Club not found" });
      }

      // Get user role from database
      const user = await usersCollection.findOne({ email: req.token_email });

      if (club.managerEmail !== req.token_email && user?.role !== "admin") {
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
// LIST ALL CLUBS
// -------------------------------
app.get("/clubs", async (req, res) => {
  try {
    let limit = parseInt(req.query.limit, 10);

    if (isNaN(limit) || limit <= 0) {
      limit = 0;
    }

    const { clubsCollection } = await connectDB();

    const clubs = await clubsCollection
      .find()
      .sort({ _id: -1 })
      .limit(limit)
      .toArray();

    res.send(clubs);
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: "Internal server error" });
  }
});

// -------------------------------
// CLUBS APPROVAL FOR ADMIN
// -------------------------------
app.patch(
  "/clubs/status/:id",
  verifyFireBaseToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { clubsCollection } = await connectDB();
      const id = req.params.id;
      const { status } = req.body;

      if (!["pending", "approved", "rejected"].includes(status)) {
        return res.status(400).send({ message: "Invalid status" });
      }

      const result = await clubsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { status, updatedAt: new Date() } }
      );

      res.send({ message: `Club ${status}`, result });
    } catch (e) {
      console.error(e);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// -------------------------------
// JOIN CLUB (CREATE PAYMENT INTENT)
// -------------------------------
app.post("/clubs/:clubId/join", verifyFireBaseToken, async (req, res) => {
  try {
    const { clubId } = req.params;
    const userEmail = req.token_email;
    const { clubsCollection, membershipsCollection } = await connectDB();

    if (!ObjectId.isValid(clubId)) {
      return res.status(400).send({ message: "Invalid club ID" });
    }

    // Check if already an active member
    const existingMembership = await membershipsCollection.findOne({
      userEmail,
      clubId: new ObjectId(clubId),
      status: "active",
    });

    if (existingMembership) {
      return res
        .status(400)
        .send({ message: "Already an active member of this club" });
    }

    // Get club details
    const club = await clubsCollection.findOne({
      _id: new ObjectId(clubId),
    });

    if (!club) {
      return res.status(404).send({ message: "Club not found" });
    }

    if (club.status !== "approved") {
      return res
        .status(400)
        .send({ message: "This club is not available for membership" });
    }

    // If free membership
    if (!club.membershipFee || club.membershipFee === 0) {
      const newMembership = {
        userEmail,
        clubId: new ObjectId(clubId),
        status: "active",
        joinedAt: new Date(),
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
        paymentId: null,
      };

      try {
        const result = await membershipsCollection.insertOne(newMembership);
        return res.send({
          message: "Joined club successfully",
          membershipId: result.insertedId,
        });
      } catch (dbError) {
        // Handle duplicate key error for free clubs
        if (dbError.code === 11000) {
          return res.status(400).send({
            message: "Already a member of this club",
          });
        }
        throw dbError;
      }
    }

    // Create Stripe Payment Intent for paid clubs
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(club.membershipFee * 100), // Convert to cents
      currency: "usd",
      metadata: {
        clubId: clubId,
        userEmail: userEmail,
        clubName: club.clubName,
      },
    });

    res.send({
      clientSecret: paymentIntent.client_secret,
      amount: club.membershipFee,
      clubName: club.clubName,
      message: "Payment intent created",
    });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Internal server error" });
  }
});

// -------------------------------
// CONFIRM PAYMENT & CREATE MEMBERSHIP
// -------------------------------
app.post(
  "/clubs/:clubId/confirm-payment",
  verifyFireBaseToken,
  async (req, res) => {
    try {
      const { clubId } = req.params;
      const { paymentIntentId } = req.body;
      const userEmail = req.token_email;
      const { clubsCollection, membershipsCollection } = await connectDB();

      if (!paymentIntentId) {
        return res.status(400).send({ message: "Payment intent ID required" });
      }

      // Verify payment with Stripe
      const paymentIntent = await stripe.paymentIntents.retrieve(
        paymentIntentId
      );

      if (paymentIntent.status !== "succeeded") {
        return res.status(400).send({ message: "Payment not completed" });
      }

      // Check if membership already exists
      const existingMembership = await membershipsCollection.findOne({
        userEmail,
        clubId: new ObjectId(clubId),
        paymentId: paymentIntentId,
      });

      if (existingMembership) {
        return res
          .status(400)
          .send({ message: "Membership already created for this payment" });
      }

      // Create membership record
      const newMembership = {
        userEmail,
        clubId: new ObjectId(clubId),
        status: "active",
        joinedAt: new Date(),
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
        paymentId: paymentIntentId,
        amount: paymentIntent.amount / 100,
        createdAt: new Date(),
      };

      const result = await membershipsCollection.insertOne(newMembership);

      res.send({
        message: "Membership activated successfully",
        membershipId: result.insertedId,
        membership: newMembership,
      });
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// -------------------------------
// RENEW MEMBERSHIP
// -------------------------------
app.post(
  "/clubs/:clubId/renew-membership",
  verifyFireBaseToken,
  async (req, res) => {
    try {
      const { clubId } = req.params;
      const userEmail = req.token_email;
      const { membershipsCollection, clubsCollection } = await connectDB();

      const club = await clubsCollection.findOne({
        _id: new ObjectId(clubId),
      });

      if (!club) {
        return res.status(404).send({ message: "Club not found" });
      }

      // If free club
      if (!club.membershipFee || club.membershipFee === 0) {
        const membership = await membershipsCollection.findOne({
          userEmail,
          clubId: new ObjectId(clubId),
        });

        if (!membership) {
          return res.status(404).send({ message: "Membership not found" });
        }

        await membershipsCollection.updateOne(
          { _id: membership._id },
          {
            $set: {
              status: "active",
              expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
            },
          }
        );

        return res.send({ message: "Membership renewed successfully" });
      }

      // Create Stripe Payment Intent for renewal
      const paymentIntent = await stripe.paymentIntents.create({
        amount: Math.round(club.membershipFee * 100),
        currency: "usd",
        metadata: {
          clubId: clubId,
          userEmail: userEmail,
          type: "renewal",
        },
      });

      res.send({
        clientSecret: paymentIntent.client_secret,
        amount: club.membershipFee,
        message: "Renewal payment intent created",
      });
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// -------------------------------
// CONFIRM RENEWAL PAYMENT
// -------------------------------
app.post(
  "/clubs/:clubId/confirm-renewal",
  verifyFireBaseToken,
  async (req, res) => {
    try {
      const { clubId } = req.params;
      const { paymentIntentId } = req.body;
      const userEmail = req.token_email;
      const { membershipsCollection } = await connectDB();

      const paymentIntent = await stripe.paymentIntents.retrieve(
        paymentIntentId
      );

      if (paymentIntent.status !== "succeeded") {
        return res.status(400).send({ message: "Payment not completed" });
      }

      const membership = await membershipsCollection.findOne({
        userEmail,
        clubId: new ObjectId(clubId),
      });

      if (!membership) {
        return res.status(404).send({ message: "Membership not found" });
      }

      await membershipsCollection.updateOne(
        { _id: membership._id },
        {
          $set: {
            status: "active",
            expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
            paymentId: paymentIntentId,
          },
        }
      );

      res.send({ message: "Membership renewed successfully" });
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// -------------------------------
// CREATE CHECKOUT SESSION (JOIN)
// -------------------------------
app.post(
  "/clubs/:clubId/create-checkout-session",
  verifyFireBaseToken,
  async (req, res) => {
    try {
      const { clubId } = req.params;
      const userEmail = req.token_email;
      const { clubsCollection, membershipsCollection } = await connectDB();

      if (!ObjectId.isValid(clubId)) {
        return res.status(400).send({ message: "Invalid club ID" });
      }

      // Check if already a member (prevent duplicates before checkout)
      const existingMembership = await membershipsCollection.findOne({
        userEmail,
        clubId: new ObjectId(clubId),
        status: "active",
      });

      if (existingMembership) {
        return res.status(400).send({
          message: "Already an active member of this club",
        });
      }

      // Get club details
      const club = await clubsCollection.findOne({
        _id: new ObjectId(clubId),
      });

      if (!club) {
        return res.status(404).send({ message: "Club not found" });
      }

      if (club.status !== "approved") {
        return res.status(400).send({
          message: "This club is not available for membership",
        });
      }

      if (!club.membershipFee || club.membershipFee === 0) {
        return res.status(400).send({
          message: "This club has free membership",
        });
      }

      // Create Stripe checkout session
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: {
                name: `${club.clubName} Membership`,
                description: `Join ${club.clubName} for 1 year`,
                images: [club.bannerImage],
              },
              unit_amount: Math.round(club.membershipFee * 100),
            },
            quantity: 1,
          },
        ],
        mode: "payment",
        customer_email: userEmail,
        success_url: `${clientUrl}/membership-success?clubId=${clubId}&sessionId={CHECKOUT_SESSION_ID}`,
        cancel_url: `${clientUrl}/clubs/${clubId}`,
        metadata: {
          clubId,
          userEmail,
          type: "join",
        },
      });

      res.send({
        url: session.url,
        sessionId: session.id,
      });
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// -------------------------------
// CREATE CHECKOUT SESSION (RENEWAL)
// -------------------------------
app.post(
  "/clubs/:clubId/create-renewal-session",
  verifyFireBaseToken,
  async (req, res) => {
    try {
      const { clubId } = req.params;
      const userEmail = req.token_email;
      const { membershipsCollection, clubsCollection } = await connectDB();

      if (!ObjectId.isValid(clubId)) {
        return res.status(400).send({ message: "Invalid club ID" });
      }

      const club = await clubsCollection.findOne({
        _id: new ObjectId(clubId),
      });

      if (!club) {
        return res.status(404).send({ message: "Club not found" });
      }

      if (!club.membershipFee || club.membershipFee === 0) {
        return res.status(400).send({
          message: "This club has free membership",
        });
      }

      const membership = await membershipsCollection.findOne({
        userEmail,
        clubId: new ObjectId(clubId),
      });

      if (!membership) {
        return res.status(404).send({ message: "Membership not found" });
      }

      // Create Stripe checkout session
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: {
                name: `${club.clubName} Membership Renewal`,
                description: `Renew ${club.clubName} membership for 1 year`,
                images: [club.bannerImage],
              },
              unit_amount: Math.round(club.membershipFee * 100),
            },
            quantity: 1,
          },
        ],
        mode: "payment",
        customer_email: userEmail,
        success_url: `${clientUrl}/membership-success?clubId=${clubId}&sessionId={CHECKOUT_SESSION_ID}`,
        cancel_url: `${clientUrl}/clubs/${clubId}`,
        metadata: {
          clubId,
          userEmail,
          type: "renewal",
        },
      });

      res.send({
        url: session.url,
        sessionId: session.id,
      });
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// -------------------------------
// VERIFY CHECKOUT SESSION & CREATE MEMBERSHIP
// -------------------------------
app.post("/clubs/verify-session", verifyFireBaseToken, async (req, res) => {
  try {
    const { sessionId } = req.body;
    const userEmail = req.token_email;
    const { membershipsCollection, clubsCollection } = await connectDB();

    if (!sessionId) {
      return res.status(400).send({ message: "Session ID required" });
    }

    console.log("Verifying session:", sessionId, "for user:", userEmail);

    // Retrieve session from Stripe
    let session;
    try {
      session = await stripe.checkout.sessions.retrieve(sessionId);
    } catch (stripeErr) {
      console.error("Stripe retrieval error:", stripeErr);
      return res.status(400).send({ message: "Invalid session ID" });
    }

    console.log("Session status:", session.payment_status);

    if (session.payment_status !== "paid") {
      return res.status(400).send({
        message: `Payment not completed. Status: ${session.payment_status}`,
      });
    }

    const { clubId, type } = session.metadata;

    if (!clubId || !type) {
      return res.status(400).send({ message: "Invalid session metadata" });
    }

    console.log("Processing", type, "for club:", clubId);

    // ============ JOIN ============
    if (type === "join") {
      try {
        // Check if user already has active membership
        const activeMembership = await membershipsCollection.findOne({
          userEmail,
          clubId: new ObjectId(clubId),
          status: "active",
        });

        if (activeMembership) {
          console.log("User already has active membership");
          return res.send({
            message: "Already an active member of this club",
            membershipId: activeMembership._id,
            alreadyMember: true,
          });
        }

        // Check if this exact payment was already processed
        const existingPayment = await membershipsCollection.findOne({
          userEmail,
          clubId: new ObjectId(clubId),
          paymentId: sessionId,
        });

        if (existingPayment) {
          console.log("Payment already processed");
          return res.send({
            message: "Membership already activated for this payment",
            membershipId: existingPayment._id,
            alreadyProcessed: true,
          });
        }

        const club = await clubsCollection.findOne({
          _id: new ObjectId(clubId),
        });

        if (!club) {
          return res.status(404).send({ message: "Club not found" });
        }

        // Create new membership
        const newMembership = {
          userEmail,
          clubId: new ObjectId(clubId),
          status: "active",
          joinedAt: new Date(),
          expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
          paymentId: sessionId,
          amount: session.amount_total / 100,
          createdAt: new Date(),
        };

        const result = await membershipsCollection.insertOne(newMembership);
        console.log("Membership created:", result.insertedId);

        return res.send({
          message: "Membership activated successfully",
          membershipId: result.insertedId,
          success: true,
        });
      } catch (dbError) {
        console.error("Database error during join:", dbError);

        // Handle duplicate key error (E11000)
        if (dbError.code === 11000) {
          console.log("Duplicate key error, checking for existing membership");
          const existingMembership = await membershipsCollection.findOne({
            userEmail,
            clubId: new ObjectId(clubId),
            paymentId: sessionId,
          });

          if (existingMembership) {
            return res.send({
              message: "Membership already exists for this payment",
              membershipId: existingMembership._id,
              alreadyProcessed: true,
            });
          }

          return res.status(400).send({
            message: "Membership already exists for this club",
          });
        }

        throw dbError;
      }
    }
    // ============ RENEWAL ============
    else if (type === "renewal") {
      try {
        const membership = await membershipsCollection.findOne({
          userEmail,
          clubId: new ObjectId(clubId),
        });

        if (!membership) {
          return res.status(404).send({ message: "Membership not found" });
        }

        // Check if this payment was already used for renewal
        const alreadyRenewed = await membershipsCollection.findOne({
          userEmail,
          clubId: new ObjectId(clubId),
          paymentId: sessionId,
        });

        if (alreadyRenewed) {
          console.log("Membership already renewed with this payment");
          return res.send({
            message: "Membership already renewed with this payment",
            alreadyProcessed: true,
          });
        }

        const updateResult = await membershipsCollection.updateOne(
          { _id: membership._id },
          {
            $set: {
              status: "active",
              expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
              paymentId: sessionId,
              renewedAt: new Date(),
            },
          }
        );

        if (updateResult.modifiedCount === 0) {
          return res.status(400).send({
            message: "Failed to update membership",
          });
        }

        console.log("Membership renewed successfully");

        return res.send({
          message: "Membership renewed successfully",
          success: true,
        });
      } catch (dbError) {
        console.error("Database error during renewal:", dbError);
        throw dbError;
      }
    } else {
      return res.status(400).send({ message: "Invalid transaction type" });
    }
  } catch (err) {
    console.error("Verification error:", err);
    res.status(500).send({ message: "Internal server error: " + err.message });
  }
});

// -------------------------------
// GET USER'S ALL MEMBERSHIPS
// -------------------------------
app.get("/users/memberships", verifyFireBaseToken, async (req, res) => {
  try {
    const userEmail = req.token_email;
    const { membershipsCollection, clubsCollection } = await connectDB();

    // Find all memberships for the user
    const memberships = await membershipsCollection
      .find({ userEmail })
      .toArray();

    // Enrich with club details
    const enrichedMemberships = await Promise.all(
      memberships.map(async (membership) => {
        const club = await clubsCollection.findOne({
          _id: membership.clubId,
        });

        return {
          ...membership,
          clubName: club?.clubName || "Unknown Club",
          clubCategory: club?.category || "N/A",
          clubLocation: club?.location || "N/A",
        };
      })
    );

    res.send(enrichedMemberships);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Internal server error" });
  }
});

// -------------------------------
// GET ALL MEMBERSHIPS (ADMIN)
// -------------------------------
app.get(
  "/admin/memberships",
  verifyFireBaseToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { membershipsCollection, clubsCollection } = await connectDB();

      // Get all memberships
      const memberships = await membershipsCollection.find({}).toArray();

      // Enrich with club and user details
      const enrichedMemberships = await Promise.all(
        memberships.map(async (membership) => {
          const club = await clubsCollection.findOne({
            _id: membership.clubId,
          });

          return {
            ...membership,
            clubName: club?.clubName || "Unknown Club",
            clubCategory: club?.category || "N/A",
          };
        })
      );

      res.send(enrichedMemberships);
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// -------------------------------
// GET CLUB MEMBERS (CLUB MANAGER)
// -------------------------------
app.get(
  "/clubs/:clubId/members",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const { clubId } = req.params;
      const { clubsCollection, membershipsCollection, usersCollection } =
        await connectDB();

      if (!ObjectId.isValid(clubId)) {
        return res.status(400).send({ message: "Invalid club ID" });
      }

      // Verify club manager owns this club
      const club = await clubsCollection.findOne({
        _id: new ObjectId(clubId),
      });

      if (!club) {
        return res.status(404).send({ message: "Club not found" });
      }

      // Check permissions
      const user = await usersCollection.findOne({
        email: req.token_email,
      });

      if (club.managerEmail !== req.token_email && user?.role !== "admin") {
        return res
          .status(403)
          .send({ message: "Not authorized to view members" });
      }

      // Get all members of the club
      const members = await membershipsCollection
        .find({ clubId: new ObjectId(clubId) })
        .toArray();

      res.send(members);
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// -------------------------------
// CANCEL/REMOVE MEMBERSHIP (USER/ADMIN/MANAGER)
// -------------------------------
app.delete(
  "/memberships/:membershipId",
  verifyFireBaseToken,
  async (req, res) => {
    try {
      const { membershipId } = req.params;
      const userEmail = req.token_email;
      const { membershipsCollection, clubsCollection, usersCollection } =
        await connectDB();

      if (!ObjectId.isValid(membershipId)) {
        return res.status(400).send({ message: "Invalid membership ID" });
      }

      const membership = await membershipsCollection.findOne({
        _id: new ObjectId(membershipId),
      });

      if (!membership) {
        return res.status(404).send({ message: "Membership not found" });
      }

      // Get user and club info
      const user = await usersCollection.findOne({ email: userEmail });
      const club = await clubsCollection.findOne({ _id: membership.clubId });

      // Authorization logic:
      // 1. User can delete their own membership
      // 2. Club manager can delete any membership in their club
      // 3. Admin can delete any membership
      const isOwnMembership = membership.userEmail === userEmail;
      const isClubManager = club && club.managerEmail === userEmail;
      const isAdmin = user && user.role === "admin";

      if (!isOwnMembership && !isClubManager && !isAdmin) {
        return res.status(403).send({
          message: "Not authorized to remove this membership",
        });
      }

      // Delete the membership
      await membershipsCollection.deleteOne({
        _id: new ObjectId(membershipId),
      });

      res.send({ message: "Membership removed successfully" });
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// -------------------------------
// CREATE EVENT (CLUB MANAGER)
// -------------------------------
app.post(
  "/clubs/:clubId/events",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const { clubId } = req.params;
      const { clubsCollection, eventsCollection, usersCollection } =
        await connectDB();

      if (!ObjectId.isValid(clubId)) {
        return res.status(400).send({ message: "Invalid club ID" });
      }

      // Verify manager owns this club
      const club = await clubsCollection.findOne({
        _id: new ObjectId(clubId),
      });

      if (!club) {
        return res.status(404).send({ message: "Club not found" });
      }

      const user = await usersCollection.findOne({
        email: req.token_email,
      });

      if (club.managerEmail !== req.token_email && user?.role !== "admin") {
        return res
          .status(403)
          .send({ message: "Not authorized to create events for this club" });
      }

      const {
        title,
        description,
        eventDate,
        location,
        isPaid,
        eventFee,
        maxAttendees,
      } = req.body;

      if (!title || !description || !eventDate || !location) {
        return res.status(400).send({ message: "Missing required fields" });
      }

      const newEvent = {
        clubId: new ObjectId(clubId),
        title,
        description,
        eventDate: new Date(eventDate),
        location,
        isPaid: Boolean(isPaid),
        eventFee: isPaid ? Number(eventFee) : 0,
        maxAttendees: maxAttendees ? Number(maxAttendees) : null,
        attendeeCount: 0,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await eventsCollection.insertOne(newEvent);

      res.status(201).send({
        message: "Event created successfully",
        eventId: result.insertedId,
        event: newEvent,
      });
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// -------------------------------
// GET ALL EVENTS FOR A CLUB
// -------------------------------
app.get("/clubs/:clubId/events", async (req, res) => {
  try {
    const { clubId } = req.params;
    const { eventsCollection, clubsCollection } = await connectDB();

    if (!ObjectId.isValid(clubId)) {
      return res.status(400).send({ message: "Invalid club ID" });
    }

    const club = await clubsCollection.findOne({
      _id: new ObjectId(clubId),
    });

    if (!club) {
      return res.status(404).send({ message: "Club not found" });
    }

    const events = await eventsCollection
      .find({ clubId: new ObjectId(clubId) })
      .sort({ eventDate: 1 })
      .toArray();

    res.send(events);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Internal server error" });
  }
});

// -------------------------------
// GET SINGLE EVENT
// -------------------------------
app.get("/events/:eventId", async (req, res) => {
  try {
    const { eventId } = req.params;
    const { eventsCollection } = await connectDB();

    if (!ObjectId.isValid(eventId)) {
      return res.status(400).send({ message: "Invalid event ID" });
    }

    const event = await eventsCollection.findOne({
      _id: new ObjectId(eventId),
    });

    if (!event) {
      return res.status(404).send({ message: "Event not found" });
    }

    res.send(event);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Internal server error" });
  }
});

// -------------------------------
// UPDATE EVENT (CLUB MANAGER)
// -------------------------------
app.patch(
  "/events/:eventId",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const { eventId } = req.params;
      const { eventsCollection, clubsCollection, usersCollection } =
        await connectDB();

      if (!ObjectId.isValid(eventId)) {
        return res.status(400).send({ message: "Invalid event ID" });
      }

      const event = await eventsCollection.findOne({
        _id: new ObjectId(eventId),
      });

      if (!event) {
        return res.status(404).send({ message: "Event not found" });
      }

      const club = await clubsCollection.findOne({
        _id: event.clubId,
      });

      const user = await usersCollection.findOne({
        email: req.token_email,
      });

      if (club.managerEmail !== req.token_email && user?.role !== "admin") {
        return res
          .status(403)
          .send({ message: "Not authorized to update this event" });
      }

      const {
        title,
        description,
        eventDate,
        location,
        isPaid,
        eventFee,
        maxAttendees,
      } = req.body;

      const updateDoc = {
        $set: {
          title: title || event.title,
          description: description || event.description,
          eventDate: eventDate ? new Date(eventDate) : event.eventDate,
          location: location || event.location,
          isPaid: isPaid !== undefined ? Boolean(isPaid) : event.isPaid,
          eventFee:
            isPaid && eventFee ? Number(eventFee) : isPaid ? event.eventFee : 0,
          maxAttendees: maxAttendees
            ? Number(maxAttendees)
            : event.maxAttendees,
          updatedAt: new Date(),
        },
      };

      await eventsCollection.updateOne(
        { _id: new ObjectId(eventId) },
        updateDoc
      );

      res.send({ message: "Event updated successfully" });
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// -------------------------------
// DELETE EVENT (CLUB MANAGER)
// -------------------------------
app.delete(
  "/events/:eventId",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const { eventId } = req.params;
      const { eventsCollection, clubsCollection, usersCollection } =
        await connectDB();

      if (!ObjectId.isValid(eventId)) {
        return res.status(400).send({ message: "Invalid event ID" });
      }

      const event = await eventsCollection.findOne({
        _id: new ObjectId(eventId),
      });

      if (!event) {
        return res.status(404).send({ message: "Event not found" });
      }

      const club = await clubsCollection.findOne({
        _id: event.clubId,
      });

      const user = await usersCollection.findOne({
        email: req.token_email,
      });

      if (club.managerEmail !== req.token_email && user?.role !== "admin") {
        return res
          .status(403)
          .send({ message: "Not authorized to delete this event" });
      }

      await eventsCollection.deleteOne({ _id: new ObjectId(eventId) });

      res.send({ message: "Event deleted successfully" });
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// =============================== EVENT REGISTRATION ROUTES ===============================

// REGISTER FOR EVENT (CREATE PAYMENT INTENT OR REGISTER DIRECTLY)
app.post("/events/:eventId/register", verifyFireBaseToken, async (req, res) => {
  try {
    const { eventId } = req.params;
    const userEmail = req.token_email;
    const { eventsCollection, eventRegistrationsCollection } =
      await connectDB();

    if (!ObjectId.isValid(eventId)) {
      return res.status(400).send({ message: "Invalid event ID" });
    }

    // Check if event exists
    const event = await eventsCollection.findOne({
      _id: new ObjectId(eventId),
    });

    if (!event) {
      return res.status(404).send({ message: "Event not found" });
    }

    // Check if already registered
    const existingRegistration = await eventRegistrationsCollection.findOne({
      eventId: new ObjectId(eventId),
      userEmail,
    });

    if (existingRegistration) {
      return res.status(400).send({
        message: "Already registered for this event",
      });
    }

    // Check attendee limit
    if (event.maxAttendees && event.attendeeCount >= event.maxAttendees) {
      return res.status(400).send({ message: "Event is full" });
    }

    // If free event, register directly
    if (!event.isPaid || event.eventFee === 0) {
      const registration = {
        eventId: new ObjectId(eventId),
        userEmail,
        clubId: event.clubId,
        status: "registered",
        registeredAt: new Date(),
        paymentId: null,
      };

      const result = await eventRegistrationsCollection.insertOne(registration);

      // Update attendee count
      await eventsCollection.updateOne(
        { _id: new ObjectId(eventId) },
        { $inc: { attendeeCount: 1 } }
      );

      return res.send({
        message: "Registered successfully",
        registrationId: result.insertedId,
      });
    }

    // Create Stripe payment intent for paid event
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(event.eventFee * 100),
      currency: "usd",
      metadata: {
        eventId,
        userEmail,
        clubId: event.clubId.toString(),
        type: "eventRegistration",
      },
    });

    res.send({
      clientSecret: paymentIntent.client_secret,
      amount: event.eventFee,
      eventTitle: event.title,
      message: "Payment intent created",
    });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Internal server error" });
  }
});

// CREATE CHECKOUT SESSION FOR EVENT REGISTRATION
app.post(
  "/events/:eventId/create-registration-session",
  verifyFireBaseToken,
  async (req, res) => {
    try {
      const { eventId } = req.params;
      const userEmail = req.token_email;
      const { eventsCollection, eventRegistrationsCollection } =
        await connectDB();

      if (!ObjectId.isValid(eventId)) {
        return res.status(400).send({ message: "Invalid event ID" });
      }

      const event = await eventsCollection.findOne({
        _id: new ObjectId(eventId),
      });

      if (!event) {
        return res.status(404).send({ message: "Event not found" });
      }

      // Check if already registered
      const existingRegistration = await eventRegistrationsCollection.findOne({
        eventId: new ObjectId(eventId),
        userEmail,
      });

      if (existingRegistration) {
        return res.status(400).send({
          message: "Already registered for this event",
        });
      }

      // Check attendee limit
      if (event.maxAttendees && event.attendeeCount >= event.maxAttendees) {
        return res.status(400).send({ message: "Event is full" });
      }

      if (!event.isPaid || event.eventFee === 0) {
        return res.status(400).send({
          message: "This is a free event",
        });
      }

      const session = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: {
                name: `${event.title} - Registration`,
                description: `Register for ${event.title}`,
              },
              unit_amount: Math.round(event.eventFee * 100),
            },
            quantity: 1,
          },
        ],
        mode: "payment",
        customer_email: userEmail,
        success_url: `${clientUrl}/event-registration-success?eventId=${eventId}&sessionId={CHECKOUT_SESSION_ID}`,
        cancel_url: `${clientUrl}/events/${eventId}`,
        metadata: {
          eventId,
          userEmail,
          type: "eventRegistration",
        },
      });

      res.send({
        url: session.url,
        sessionId: session.id,
      });
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// VERIFY EVENT REGISTRATION SESSION & CREATE REGISTRATION
app.post(
  "/events/verify-registration-session",
  verifyFireBaseToken,
  async (req, res) => {
    try {
      const { sessionId } = req.body;
      const userEmail = req.token_email;
      const { eventsCollection, eventRegistrationsCollection } =
        await connectDB();

      if (!sessionId) {
        return res.status(400).send({ message: "Session ID required" });
      }

      const session = await stripe.checkout.sessions.retrieve(sessionId);

      if (session.payment_status !== "paid") {
        return res.status(400).send({ message: "Payment not completed" });
      }

      const { eventId } = session.metadata;

      // Check if already registered
      const existingRegistration = await eventRegistrationsCollection.findOne({
        eventId: new ObjectId(eventId),
        userEmail,
      });

      if (existingRegistration) {
        return res.send({
          message: "Already registered for this event",
          registrationId: existingRegistration._id,
          alreadyRegistered: true,
        });
      }

      const event = await eventsCollection.findOne({
        _id: new ObjectId(eventId),
      });

      if (!event) {
        return res.status(404).send({ message: "Event not found" });
      }

      // Check attendee limit
      if (event.maxAttendees && event.attendeeCount >= event.maxAttendees) {
        return res.status(400).send({ message: "Event is full" });
      }

      try {
        const registration = {
          eventId: new ObjectId(eventId),
          userEmail,
          clubId: event.clubId,
          status: "registered",
          registeredAt: new Date(),
          paymentId: sessionId,
          amount: session.amount_total / 100,
        };

        const result = await eventRegistrationsCollection.insertOne(
          registration
        );

        // Update attendee count
        await eventsCollection.updateOne(
          { _id: new ObjectId(eventId) },
          { $inc: { attendeeCount: 1 } }
        );

        return res.send({
          message: "Registration successful",
          registrationId: result.insertedId,
          success: true,
        });
      } catch (dbError) {
        if (dbError.code === 11000) {
          const existingReg = await eventRegistrationsCollection.findOne({
            eventId: new ObjectId(eventId),
            userEmail,
          });

          return res.send({
            message: "Registration already exists for this payment",
            registrationId: existingReg._id,
            alreadyRegistered: true,
          });
        }
        throw dbError;
      }
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// GET USER'S EVENT REGISTRATIONS
app.get("/users/event-registrations", verifyFireBaseToken, async (req, res) => {
  try {
    const userEmail = req.token_email;
    const { eventRegistrationsCollection, eventsCollection } =
      await connectDB();

    const registrations = await eventRegistrationsCollection
      .find({ userEmail })
      .toArray();

    // Enrich with event details
    const enrichedRegistrations = await Promise.all(
      registrations.map(async (reg) => {
        const event = await eventsCollection.findOne({
          _id: reg.eventId,
        });

        return {
          ...reg,
          eventTitle: event?.title || "Unknown Event",
          eventDate: event?.eventDate,
          eventLocation: event?.location,
        };
      })
    );

    res.send(enrichedRegistrations);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Internal server error" });
  }
});

// GET EVENT REGISTRATIONS FOR SPECIFIC EVENT
app.get(
  "/events/:eventId/registrations",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const { eventId } = req.params;
      const {
        eventRegistrationsCollection,
        eventsCollection,
        usersCollection,
      } = await connectDB();

      if (!ObjectId.isValid(eventId)) {
        return res.status(400).send({ message: "Invalid event ID" });
      }

      const event = await eventsCollection.findOne({
        _id: new ObjectId(eventId),
      });

      if (!event) {
        return res.status(404).send({ message: "Event not found" });
      }

      // Check permissions
      const user = await usersCollection.findOne({
        email: req.token_email,
      });

      const club = await clubsCollection.findOne({
        _id: event.clubId,
      });

      if (club.managerEmail !== req.token_email && user?.role !== "admin") {
        return res.status(403).send({
          message: "Not authorized to view registrations",
        });
      }

      const registrations = await eventRegistrationsCollection
        .find({ eventId: new ObjectId(eventId) })
        .toArray();

      res.send(registrations);
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// CANCEL EVENT REGISTRATION
app.delete(
  "/event-registrations/:registrationId",
  verifyFireBaseToken,
  async (req, res) => {
    try {
      const { registrationId } = req.params;
      const userEmail = req.token_email;
      const { eventRegistrationsCollection, eventsCollection } =
        await connectDB();

      if (!ObjectId.isValid(registrationId)) {
        return res.status(400).send({ message: "Invalid registration ID" });
      }

      const registration = await eventRegistrationsCollection.findOne({
        _id: new ObjectId(registrationId),
      });

      if (!registration) {
        return res.status(404).send({ message: "Registration not found" });
      }

      // Only the registered user or admin can cancel
      if (registration.userEmail !== userEmail) {
        const user = await eventsCollection
          .aggregate([{ $match: { _id: registration.eventId } }])
          .toArray();

        if (user[0]?.managerEmail !== userEmail) {
          return res.status(403).send({
            message: "Not authorized to cancel this registration",
          });
        }
      }

      // Delete registration
      await eventRegistrationsCollection.deleteOne({
        _id: new ObjectId(registrationId),
      });

      // Decrement attendee count
      await eventsCollection.updateOne(
        { _id: registration.eventId },
        { $inc: { attendeeCount: -1 } }
      );

      res.send({ message: "Registration cancelled successfully" });
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// =============================== NEW ROUTE ===============================
// GET ALL EVENTS FOR A MANAGER (across all clubs)
// ===============================
app.get(
  "/manager/events",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const { eventsCollection, clubsCollection } = await connectDB();
      const managerEmail = req.token_email;

      // Find all clubs managed by this user
      const managedClubs = await clubsCollection
        .find({ managerEmail })
        .toArray();

      if (managedClubs.length === 0) {
        return res.send([]);
      }

      // Get all events for these clubs
      const clubIds = managedClubs.map((club) => club._id);
      const events = await eventsCollection
        .find({ clubId: { $in: clubIds } })
        .sort({ eventDate: -1 })
        .toArray();

      // Enrich events with club data
      const enrichedEvents = events.map((event) => {
        const club = managedClubs.find((c) => c._id.equals(event.clubId));
        return {
          ...event,
          clubData: club,
        };
      });

      res.send(enrichedEvents);
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);

// -------------------------------
// ADMIN STATS
// -------------------------------
app.get("/admin/stats", verifyFireBaseToken, verifyAdmin, async (req, res) => {
  try {
    const { usersCollection, clubsCollection, membershipsCollection } =
      await connectDB();

    const totalUsers = await usersCollection.countDocuments();
    const totalClubs = await clubsCollection.countDocuments();
    const totalRevenue = await membershipsCollection
      .aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }])
      .toArray();

    // User growth (last 6 months)
    const sixMonthsAgo = new Date();
    sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);

    const userGrowth = await usersCollection
      .aggregate([
        {
          $group: {
            _id: {
              year: { $year: { $toDate: "$_id" } },
              month: { $month: { $toDate: "$_id" } },
            },
            users: { $sum: 1 },
          },
        },
        { $sort: { "_id.year": 1, "_id.month": 1 } },
        {
          $project: {
            name: {
              $dateToString: {
                format: "%Y-%m",
                date: {
                  $toDate: {
                    $dateFromParts: {
                      year: "$_id.year",
                      month: "$_id.month",
                      day: 1,
                    },
                  },
                },
              },
            },
            users: 1,
            _id: 0,
          },
        },
      ])
      .toArray();

    // Clubs by category
    const clubsByCategory = await clubsCollection
      .aggregate([
        { $group: { _id: "$category", value: { $sum: 1 } } },
        { $project: { name: "$_id", value: 1, _id: 0 } },
      ])
      .toArray();

    // Revenue by month (last 6 months)
    const revenueByMonth = await membershipsCollection
      .aggregate([
        {
          $group: {
            _id: {
              year: { $year: "$createdAt" },
              month: { $month: "$createdAt" },
            },
            revenue: { $sum: "$amount" },
          },
        },
        { $sort: { "_id.year": 1, "_id.month": 1 } },
        {
          $project: {
            name: {
              $dateToString: {
                format: "%b",
                date: {
                  $toDate: {
                    $dateFromParts: {
                      year: "$_id.year",
                      month: "$_id.month",
                      day: 1,
                    },
                  },
                },
              },
            },
            revenue: 1,
            _id: 0,
          },
        },
      ])
      .toArray();

    // Membership status distribution
    const membershipDistribution = await membershipsCollection
      .aggregate([
        { $group: { _id: "$status", value: { $sum: 1 } } },
        { $project: { name: "$_id", value: 1, _id: 0 } },
      ])
      .toArray();

    // Calculate trends
    const thisMonth = new Date();
    thisMonth.setDate(1);
    const lastMonth = new Date(thisMonth);
    lastMonth.setMonth(lastMonth.getMonth() - 1);

    const thisMonthUsers = await usersCollection.countDocuments({
      createdAt: { $gte: thisMonth },
    });
    const lastMonthUsers = await usersCollection.countDocuments({
      createdAt: {
        $gte: lastMonth,
        $lt: thisMonth,
      },
    });

    const usersTrend =
      lastMonthUsers > 0
        ? Math.round(((thisMonthUsers - lastMonthUsers) / lastMonthUsers) * 100)
        : 0;

    res.json({
      totalUsers,
      totalClubs,
      totalRevenue: totalRevenue[0]?.total || 0,
      userGrowth,
      clubsByCategory,
      revenueByMonth,
      membershipDistribution,
      usersTrend,
      clubsTrend: 5,
      revenueTrend: 12,
    });
  } catch (error) {
    console.error("Error fetching admin stats:", error);
    res.status(500).json({ message: "Error fetching stats" });
  }
});

// -------------------------------
// CLUB MANAGER STATS
// -------------------------------
app.get(
  "/club-manager/stats",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const managerEmail = req.token_email;
      const {
        clubsCollection,
        membershipsCollection,
        eventsCollection,
        eventRegistrationsCollection,
      } = await connectDB();

      // Get all clubs managed by this user
      const managedClubs = await clubsCollection
        .find({ managerEmail })
        .toArray();

      if (managedClubs.length === 0) {
        return res.json({
          totalMembers: 0,
          totalClubs: 0,
          totalEvents: 0,
          totalRevenue: 0,
          membershipGrowth: [],
          clubsDistribution: [],
          eventAttendance: [],
          membershipStatus: [],
          revenueByClub: [],
          eventStatus: [],
          membersTrend: 0,
          clubsTrend: 0,
          eventsTrend: 0,
          revenueTrend: 0,
        });
      }

      const clubIds = managedClubs.map((club) => club._id);

      // Total members across all clubs
      const totalMembers = await membershipsCollection.countDocuments({
        clubId: { $in: clubIds },
        status: "active",
      });

      const totalClubs = managedClubs.length;

      // Total events
      const totalEvents = await eventsCollection.countDocuments({
        clubId: { $in: clubIds },
      });

      // Total revenue
      const totalRevenueResult = await membershipsCollection
        .aggregate([
          { $match: { clubId: { $in: clubIds } } },
          { $group: { _id: null, total: { $sum: "$amount" } } },
        ])
        .toArray();

      const totalRevenue = totalRevenueResult[0]?.total || 0;

      // Membership growth (last 6 months)
      const membershipGrowth = await membershipsCollection
        .aggregate([
          { $match: { clubId: { $in: clubIds } } },
          {
            $group: {
              _id: {
                year: { $year: "$joinedAt" },
                month: { $month: "$joinedAt" },
              },
              members: { $sum: 1 },
            },
          },
          { $sort: { "_id.year": 1, "_id.month": 1 } },
          {
            $project: {
              name: {
                $dateToString: {
                  format: "%b",
                  date: {
                    $toDate: {
                      $dateFromParts: {
                        year: "$_id.year",
                        month: "$_id.month",
                        day: 1,
                      },
                    },
                  },
                },
              },
              members: 1,
              _id: 0,
            },
          },
        ])
        .toArray();

      // Members distribution by club
      const clubsDistribution = await membershipsCollection
        .aggregate([
          { $match: { clubId: { $in: clubIds } } },
          {
            $lookup: {
              from: "clubsCollection",
              localField: "clubId",
              foreignField: "_id",
              as: "club",
            },
          },
          { $unwind: "$club" },
          {
            $group: {
              _id: "$club.clubName",
              value: { $sum: 1 },
            },
          },
          { $project: { name: "$_id", value: 1, _id: 0 } },
        ])
        .toArray();

      // Event attendance
      const eventAttendance = await eventsCollection
        .aggregate([
          { $match: { clubId: { $in: clubIds } } },
          {
            $project: {
              name: "$title",
              attendance: "$attendeeCount",
            },
          },
          { $sort: { attendance: -1 } },
          { $limit: 10 },
        ])
        .toArray();

      // Membership status
      const membershipStatus = await membershipsCollection
        .aggregate([
          { $match: { clubId: { $in: clubIds } } },
          { $group: { _id: "$status", value: { $sum: 1 } } },
          { $project: { name: "$_id", value: 1, _id: 0 } },
        ])
        .toArray();

      // Revenue by club
      const revenueByClub = await membershipsCollection
        .aggregate([
          { $match: { clubId: { $in: clubIds } } },
          {
            $lookup: {
              from: "clubsCollection",
              localField: "clubId",
              foreignField: "_id",
              as: "club",
            },
          },
          { $unwind: "$club" },
          {
            $group: {
              _id: "$club.clubName",
              revenue: { $sum: "$amount" },
            },
          },
          {
            $project: {
              name: "$_id",
              revenue: { $round: ["$revenue", 2] },
              _id: 0,
            },
          },
          { $sort: { revenue: -1 } },
        ])
        .toArray();

      // Event status distribution
      const eventStatus = await eventsCollection
        .aggregate([
          { $match: { clubId: { $in: clubIds } } },
          {
            $group: {
              _id: {
                $cond: [
                  { $lt: ["$eventDate", new Date()] },
                  "Completed",
                  "Upcoming",
                ],
              },
              value: { $sum: 1 },
            },
          },
          { $project: { name: "$_id", value: 1, _id: 0 } },
        ])
        .toArray();

      // Calculate trends (this month vs last month)
      const thisMonth = new Date();
      thisMonth.setDate(1);
      thisMonth.setHours(0, 0, 0, 0);

      const lastMonth = new Date(thisMonth);
      lastMonth.setMonth(lastMonth.getMonth() - 1);

      const thisMonthMembers = await membershipsCollection.countDocuments({
        clubId: { $in: clubIds },
        joinedAt: { $gte: thisMonth },
      });

      const lastMonthMembers = await membershipsCollection.countDocuments({
        clubId: { $in: clubIds },
        joinedAt: {
          $gte: lastMonth,
          $lt: thisMonth,
        },
      });

      const membersTrend =
        lastMonthMembers > 0
          ? Math.round(
              ((thisMonthMembers - lastMonthMembers) / lastMonthMembers) * 100
            )
          : 0;

      const thisMonthEvents = await eventsCollection.countDocuments({
        clubId: { $in: clubIds },
        createdAt: { $gte: thisMonth },
      });

      const lastMonthEvents = await eventsCollection.countDocuments({
        clubId: { $in: clubIds },
        createdAt: {
          $gte: lastMonth,
          $lt: thisMonth,
        },
      });

      const eventsTrend =
        lastMonthEvents > 0
          ? Math.round(
              ((thisMonthEvents - lastMonthEvents) / lastMonthEvents) * 100
            )
          : 0;

      res.json({
        totalMembers,
        totalClubs,
        totalEvents,
        totalRevenue: Math.round(totalRevenue * 100) / 100,
        membershipGrowth,
        clubsDistribution,
        eventAttendance,
        membershipStatus,
        revenueByClub,
        eventStatus,
        membersTrend,
        clubsTrend: 2,
        eventsTrend,
        revenueTrend: 8,
      });
    } catch (error) {
      console.error("Error fetching club manager stats:", error);
      res.status(500).json({ message: "Error fetching stats" });
    }
  }
);

// -------------------------------
// MEMBER STATS
// -------------------------------
app.get("/member/stats", verifyFireBaseToken, async (req, res) => {
  try {
    const userEmail = req.token_email;

    const totalClubs = await membershipsCollection.countDocuments({
      userEmail,
      status: "active",
    });

    const eventsAttended = await eventRegistrationsCollection.countDocuments({
      userEmail,
      status: "attended",
    });

    const activeMemberships = await membershipsCollection.countDocuments({
      userEmail,
      status: "active",
    });

    // Get membership breakdown by club
    const clubsBreakdown = await membershipsCollection
      .aggregate([
        { $match: { userEmail } },
        {
          $lookup: {
            from: "clubsCollection",
            localField: "clubId",
            foreignField: "_id",
            as: "club",
          },
        },
        { $unwind: "$club" },
        {
          $group: {
            _id: "$club.clubName",
            value: { $sum: 1 },
          },
        },
        { $project: { name: "$_id", value: 1, _id: 0 } },
      ])
      .toArray();

    // Event attendance history (last 6 months)
    const sixMonthsAgo = new Date();
    sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);

    const eventAttendanceHistory = await eventRegistrationsCollection
      .aggregate([
        { $match: { userEmail, createdAt: { $gte: sixMonthsAgo } } },
        {
          $group: {
            _id: {
              year: { $year: "$createdAt" },
              month: { $month: "$createdAt" },
            },
            attendance: { $sum: 1 },
          },
        },
        { $sort: { "_id.year": 1, "_id.month": 1 } },
        {
          $project: {
            name: {
              $dateToString: {
                format: "%b",
                date: {
                  $toDate: {
                    $dateFromParts: {
                      year: "$_id.year",
                      month: "$_id.month",
                      day: 1,
                    },
                  },
                },
              },
            },
            attendance: 1,
            _id: 0,
          },
        },
      ])
      .toArray();

    // Get membership status
    const membershipStatus = await membershipsCollection.findOne(
      { userEmail, status: "active" },
      { projection: { status: 1 } }
    );

    res.json({
      totalClubs,
      eventsAttended,
      activeMemberships,
      friendsCount: 0,
      membershipStatus: membershipStatus?.status || "inactive",
      clubsBreakdown,
      eventAttendanceHistory,
      clubsTrend: 5,
      eventsTrend: 3,
      membershipsTrend: 2,
      friendsTrend: 1,
    });
  } catch (error) {
    console.error("Error fetching member stats:", error);
    res.status(500).json({ message: "Error fetching stats" });
  }
});

// Get member's clubs
app.get("/member/clubs", verifyFireBaseToken, async (req, res) => {
  try {
    const userEmail = req.token_email;

    const clubs = await membershipsCollection
      .aggregate([
        { $match: { userEmail } },
        {
          $lookup: {
            from: "clubsCollection",
            localField: "clubId",
            foreignField: "_id",
            as: "club",
          },
        },
        { $unwind: "$club" },
        {
          $project: {
            _id: "$club._id",
            clubName: "$club.clubName",
            description: "$club.description",
            clubImage: "$club.clubImage",
            category: "$club.category",
            membershipStatus: "$status",
            memberCount: "$club.memberCount",
          },
        },
      ])
      .toArray();

    res.json(clubs);
  } catch (error) {
    console.error("Error fetching member clubs:", error);
    res.status(500).json({ message: "Error fetching clubs" });
  }
});

// Get member's events
app.get("/member/events", verifyFireBaseToken, async (req, res) => {
  try {
    const userEmail = req.token_email;

    const events = await eventRegistrationsCollection
      .aggregate([
        { $match: { userEmail } },
        {
          $lookup: {
            from: "eventsCollection",
            localField: "eventId",
            foreignField: "_id",
            as: "event",
          },
        },
        { $unwind: "$event" },
        {
          $lookup: {
            from: "clubsCollection",
            localField: "event.clubId",
            foreignField: "_id",
            as: "club",
          },
        },
        { $unwind: "$club" },
        {
          $project: {
            _id: "$event._id",
            title: "$event.title",
            description: "$event.description",
            eventImage: "$event.eventImage",
            eventDate: "$event.eventDate",
            clubName: "$club.clubName",
            attended: { $eq: ["$status", "attended"] },
          },
        },
        { $sort: { eventDate: -1 } },
      ])
      .toArray();

    res.json(events);
  } catch (error) {
    console.error("Error fetching member events:", error);
    res.status(500).json({ message: "Error fetching events" });
  }
});

app.listen(port, () => console.log(`Backend running on port ${port}`));
