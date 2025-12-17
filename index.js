// Add requirements
const express = require("express");
const cors = require("cors");
require("dotenv").config();
const admin = require("firebase-admin");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

// Define variables
const app = express();
const port = process.env.PORT || 3000;
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf8"
);
const serviceAccount = JSON.parse(decoded);
const uri = process.env.MONGODB_URI;
const clientUrl = process.env.CLIENT_URL || "http://localhost:5173";

// Middlewares
app.use(express.json());
app.use(
  cors({
    origin: clientUrl, // Use env variable
    credentials: true,
  })
);

// Firebase admin setup
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// MongoDB Setup
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
  maxPoolSize: 10,
  connectTimeoutMS: 10000,
});

let usersDB, clubsDB, paymentsDB;
let usersCollection,
  applicationsCollection,
  clubsCollection,
  membershipsCollection,
  eventsCollection,
  eventRegistrationsCollection,
  paymentsCollection;
async function connectDB() {
  if (!usersDB || !clubsDB || !paymentsDB) {
    await client.connect();
    usersDB = client.db("usersDB");
    clubsDB = client.db("clubsDB");
    paymentsDB = client.db("paymentsDB");
    usersCollection = usersDB.collection("usersCollection");
    applicationsCollection = usersDB.collection("applicationsCollection");
    clubsCollection = clubsDB.collection("clubsCollection");
    membershipsCollection = clubsDB.collection("membershipsCollection");
    eventsCollection = clubsDB.collection("eventsCollection");
    eventRegistrationsCollection = clubsDB.collection(
      "eventRegistrationsCollection"
    );
    paymentsCollection = paymentsDB.collection("paymentsCollection");
    console.log("Connected to MongoDB");
  }
  return {
    usersCollection,
    applicationsCollection,
    clubsCollection,
    membershipsCollection,
    eventsCollection,
    eventRegistrationsCollection,
    paymentsCollection,
  };
}
async function createIndexes() {
  try {
    const {
      membershipsCollection,
      eventsCollection,
      eventRegistrationsCollection,
      paymentsCollection,
    } = await connectDB();
    // Drop old indexes
    try {
      await membershipsCollection.dropIndex("userEmail_1_clubId_1_paymentId_1");
      await membershipsCollection.dropIndex("paymentId_1");
    } catch (e) {
      // Indexes don't exist, continue
    }
    // Memberships indexes
    await membershipsCollection.createIndex(
      { userEmail: 1, clubId: 1, status: 1 },
      { unique: true, sparse: true }
    );
    await membershipsCollection.createIndex({ paymentId: 1 }, { sparse: true });
    await membershipsCollection.createIndex({ userEmail: 1 });
    await membershipsCollection.createIndex({ clubId: 1 });
    // Events indexes
    await eventsCollection.createIndex({ clubId: 1 });
    await eventsCollection.createIndex({ createdAt: -1 });
    // Event Registrations indexes
    await eventRegistrationsCollection.createIndex(
      { eventId: 1, userEmail: 1 },
      { unique: true, sparse: true }
    );
    await eventRegistrationsCollection.createIndex({ userEmail: 1 });
    await eventRegistrationsCollection.createIndex({ eventId: 1 });
    // Payments indexes
    await paymentsCollection.createIndex(
      { transactionId: 1 },
      { unique: true }
    );
    await paymentsCollection.createIndex({ userEmail: 1 });
    await paymentsCollection.createIndex({ paymentType: 1 });
    await paymentsCollection.createIndex({ status: 1 });
    await paymentsCollection.createIndex({ createdAt: -1 });
  } catch (err) {
    console.error("Error creating indexes:", err.message);
  }
}
// Call this after connecting
connectDB().then(() => createIndexes());

// Custom Middlewares
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

// Helper Functions
async function recordPayment(paymentData) {
  const { paymentsCollection } = await connectDB();
  const payment = {
    transactionId: paymentData.transactionId,
    userEmail: paymentData.userEmail,
    paymentType: paymentData.paymentType,
    amount: paymentData.amount,
    currency: "usd",
    status: paymentData.status,
    relatedId: paymentData.relatedId,
    relatedName: paymentData.relatedName,
    paymentMethod: "stripe",
    stripeSessionId: paymentData.stripeSessionId,
    stripePlatformFee: paymentData.stripePlatformFee || 0,
    netAmount: paymentData.amount - (paymentData.stripePlatformFee || 0),
    description: paymentData.description,
    metadata: paymentData.metadata || {},
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  console.log("Recording payment:", payment);
  return await paymentsCollection.insertOne(payment);
}
async function verifyClubOwnership(clubId, managerEmail) {
  const { clubsCollection, usersCollection } = await connectDB();
  const club = await clubsCollection.findOne({ _id: new ObjectId(clubId) });
  if (!club) return { authorized: false, club: null };
  const user = await usersCollection.findOne({ email: managerEmail });
  const authorized =
    club.managerEmail === managerEmail || user?.role === "admin";
  return { authorized, club };
}
async function verifyEventOwnership(eventId, managerEmail) {
  const { eventsCollection, clubsCollection, usersCollection } =
    await connectDB();
  const event = await eventsCollection.findOne({ _id: new ObjectId(eventId) });
  if (!event) return { authorized: false, event: null };
  const club = await clubsCollection.findOne({ _id: event.clubId });
  const user = await usersCollection.findOne({ email: managerEmail });
  const authorized =
    club?.managerEmail === managerEmail || user?.role === "admin";
  return { authorized, event };
}

/*===== Public routes =====*/
// Server startup
app.listen(port, () => console.log(`Backend running on port ${port}`));
// The default route
app.get("/", (req, res) => res.send("Hello from backend!"));
// Get a user's role
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
// Add new user
app.post("/users", async (req, res) => {
  try {
    const { usersCollection } = await connectDB();
    const { name, email, photoURL, createdAt } = req.body;
    const exists = await usersCollection.findOne({ email });
    if (exists) return res.status(409).send({ message: "User already exists" });
    const result = await usersCollection.insertOne({
      name,
      email,
      photoURL,
      createdAt: createdAt || new Date(),
      role: "member",
    });
    res.status(201).send({ message: "User created", id: result.insertedId });
  } catch (e) {
    res.status(500).send({ message: "Internal server error" });
  }
});
// List all clubs with filters
app.get("/clubs", async (req, res) => {
  try {
    const { search, category, minFee, maxFee, status } = req.query;
    const { clubsCollection } = await connectDB();

    // Build filter object
    const filter = {};

    // Search by club name or description
    if (search && search.trim()) {
      filter.$or = [
        { clubName: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
        { location: { $regex: search, $options: "i" } },
      ];
    }

    // Filter by category
    if (category && category.trim()) {
      filter.category = category;
    }

    // Filter by membership fee range
    if (minFee || maxFee) {
      filter.membershipFee = {};
      if (minFee) filter.membershipFee.$gte = parseFloat(minFee);
      if (maxFee) filter.membershipFee.$lte = parseFloat(maxFee);
    }

    // Filter by status
    if (status) {
      filter.status = status;
    }

    // Execute query
    const clubs = await clubsCollection
      .find(filter)
      .sort({ createdAt: -1 })
      .toArray();

    res.json({
      success: true,
      data: clubs,
      count: clubs.length,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.message });
  }
});
// Get club categories
app.get("/clubs/categories", async (req, res) => {
  try {
    const { clubsCollection } = await connectDB();

    const categories = await clubsCollection
      .aggregate([
        { $match: { status: "approved" } },
        { $group: { _id: "$category" } },
        { $sort: { _id: 1 } },
      ])
      .toArray();

    res.json({
      success: true,
      data: categories.map((c) => c._id).filter(Boolean),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.message });
  }
});
// Fetch club details
app.get("/clubs/details/:param", async (req, res) => {
  try {
    const { clubsCollection } = await connectDB();
    const param = req.params.param;
    if (!ObjectId.isValid(param))
      return res.status(400).send({ message: "Invalid club ID" });
    const club = await clubsCollection.findOne({ _id: new ObjectId(param) });
    if (!club) return res.status(404).send({ message: "Club not found" });
    res.send(club);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Internal server error" });
  }
});
// List all events with filters
app.get("/events", async (req, res) => {
  try {
    const {
      search,
      clubId,
      location,
      isPaid,
      minDate,
      maxDate,
      sort,
      limit = 0,
    } = req.query;
    const { eventsCollection } = await connectDB();

    // Build filter object
    const filter = {};

    // Search by event title or description
    if (search && search.trim()) {
      filter.$or = [
        { title: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
      ];
    }

    // Filter by club
    if (clubId && clubId.trim()) {
      filter.clubId = new ObjectId(clubId);
    }

    // Filter by location
    if (location && location.trim()) {
      filter.location = { $regex: location, $options: "i" };
    }

    // Filter by paid/free
    if (isPaid !== undefined && isPaid !== "") {
      filter.isPaid = isPaid === "true" || isPaid === true;
    }

    // Filter by date range
    if (minDate || maxDate) {
      filter.eventDate = {};
      if (minDate) filter.eventDate.$gte = new Date(minDate);
      if (maxDate) filter.eventDate.$lte = new Date(maxDate);
    }

    // Determine sort
    let sortObj = { createdAt: -1 }; // Default: newest first
    if (sort === "oldest") {
      sortObj = { createdAt: 1 };
    } else if (sort === "highest-fee") {
      sortObj = { eventFee: -1 };
    } else if (sort === "lowest-fee") {
      sortObj = { eventFee: 1 };
    } else if (sort === "upcoming") {
      sortObj = { eventDate: 1 };
    }

    // Execute query
    let query = eventsCollection.find(filter).sort(sortObj);

    if (parseInt(limit) > 0) {
      query = query.limit(parseInt(limit));
    }

    const events = await query.toArray();

    res.json({
      success: true,
      data: events,
      count: events.length,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.message });
  }
});
// Get events of a specific club
app.get("/clubs/:clubId/events", async (req, res) => {
  try {
    const { clubId } = req.params;
    const { eventsCollection, clubsCollection } = await connectDB();
    if (!ObjectId.isValid(clubId))
      return res.status(400).send({ message: "Invalid club ID" });
    const club = await clubsCollection.findOne({ _id: new ObjectId(clubId) });
    if (!club) return res.status(404).send({ message: "Club not found" });
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
// Get event details
app.get("/events/:eventId", async (req, res) => {
  try {
    const { eventId } = req.params;
    const { eventsCollection } = await connectDB();
    if (!ObjectId.isValid(eventId))
      return res.status(400).send({ message: "Invalid event ID" });
    const event = await eventsCollection.findOne({
      _id: new ObjectId(eventId),
    });
    if (!event) return res.status(404).send({ message: "Event not found" });
    res.send(event);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Internal server error" });
  }
});

/*===== Protected routes (for members) =====*/
// Apply for Club Manager role
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
// Check Club Manager application status
app.get(
  "/users/apply-club-manager/status",
  verifyFireBaseToken,
  async (req, res) => {
    try {
      const { applicationsCollection } = await connectDB();
      const appStatus = await applicationsCollection.findOne({
        email: req.token_email,
      });
      res.send(
        appStatus ? { found: true, application: appStatus } : { found: false }
      );
    } catch (e) {
      res.status(500).send({ message: "Internal server error" });
    }
  }
);
// Get member payment statistics
app.get(
  "/member/payments/statistics",
  verifyFireBaseToken,
  async (req, res) => {
    try {
      const userEmail = req.token_email;
      const { paymentsCollection } = await connectDB();

      // Overall statistics
      const totalStats = await paymentsCollection
        .aggregate([
          {
            $match: {
              userEmail,
              status: "completed",
            },
          },
          {
            $group: {
              _id: null,
              totalSpent: { $sum: "$amount" },
              totalTransactions: { $sum: 1 },
            },
          },
        ])
        .toArray();

      // Revenue by type
      const spendingByType = await paymentsCollection
        .aggregate([
          {
            $match: {
              userEmail,
              status: "completed",
            },
          },
          {
            $group: {
              _id: "$paymentType",
              amount: { $sum: "$amount" },
              count: { $sum: 1 },
            },
          },
        ])
        .toArray();

      // Membership spending specifically
      const membershipStats = spendingByType.find(
        (r) => r._id === "membership"
      ) || { amount: 0, count: 0 };

      // Event spending specifically
      const eventStats = spendingByType.find((r) => r._id === "event") || {
        amount: 0,
        count: 0,
      };

      // Monthly spending
      const monthlySpending = await paymentsCollection
        .aggregate([
          {
            $match: {
              userEmail,
              status: "completed",
            },
          },
          {
            $addFields: {
              createdAtDate: {
                $cond: [
                  { $eq: [{ $type: "$createdAt" }, "date"] },
                  "$createdAt",
                  { $toDate: "$createdAt" },
                ],
              },
            },
          },
          {
            $group: {
              _id: {
                $dateToString: {
                  format: "%b %Y",
                  date: "$createdAtDate",
                },
              },
              amount: { $sum: "$amount" },
              count: { $sum: 1 },
            },
          },
          { $sort: { _id: 1 } },
          {
            $project: {
              _id: 0,
              month: "$_id",
              amount: { $round: ["$amount", 2] },
              count: 1,
            },
          },
        ])
        .toArray();

      const stats = totalStats[0] || {
        totalSpent: 0,
        totalTransactions: 0,
      };

      res.json({
        ...stats,
        membershipSpent: membershipStats.amount || 0,
        eventSpent: eventStats.amount || 0,
        membershipCount: membershipStats.count || 0,
        eventCount: eventStats.count || 0,
        spendingByType,
        monthlySpending,
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: error.message });
    }
  }
);
// Check membership status for a club
app.get(
  "/clubs/:clubId/membership-status",
  verifyFireBaseToken,
  async (req, res) => {
    try {
      const { clubId } = req.params;
      const email = req.token_email;
      const { membershipsCollection } = await connectDB();
      if (!ObjectId.isValid(clubId))
        return res.status(400).send({ message: "Invalid club ID" });
      const membership = await membershipsCollection.findOne({
        userEmail: email,
        clubId: new ObjectId(clubId),
      });
      if (!membership) return res.send({ isMember: false, status: "none" });
      // Auto-expire expired memberships
      if (membership.expiresAt && new Date(membership.expiresAt) < new Date()) {
        await membershipsCollection.updateOne(
          { _id: membership._id },
          { $set: { status: "expired" } }
        );
        membership.status = "expired";
      }
      res.send({
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
// Join a club (creates membership & payment intent)
app.post("/clubs/:clubId/join", verifyFireBaseToken, async (req, res) => {
  try {
    const { clubId } = req.params;
    const userEmail = req.token_email;
    const { clubsCollection, membershipsCollection } = await connectDB();
    if (!ObjectId.isValid(clubId)) {
      return res.status(400).send({ message: "Invalid club ID" });
    }
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
        // RECORD PAYMENT ✅ - ADD THIS (free membership payment record)
        await recordPayment({
          transactionId: `free-${clubId}-${userEmail}-${Date.now()}`,
          userEmail,
          paymentType: "membership",
          amount: 0,
          status: "completed",
          relatedId: clubId,
          relatedName: club.clubName,
          description: `Free membership for ${club.clubName}`,
          stripeSessionId: null,
        });
        return res.send({
          message: "Joined club successfully",
          membershipId: result.insertedId,
        });
      } catch (dbError) {
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
      amount: Math.round(club.membershipFee * 100),
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
// Confirm membership payment
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

      const club = await clubsCollection.findOne({
        _id: new ObjectId(clubId),
      });
      if (!club) {
        return res.status(404).send({ message: "Club not found" });
      }

      // Create membership record
      const newMembership = {
        userEmail,
        clubId: new ObjectId(clubId),
        status: "active",
        joinedAt: new Date(),
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
        paymentId: paymentIntentId,
        amount: paymentIntent.amount / 100,
        createdAt: new Date(),
      };

      const result = await membershipsCollection.insertOne(newMembership);

      // RECORD PAYMENT ✅ - ADD THIS
      await recordPayment({
        transactionId: paymentIntentId,
        userEmail,
        paymentType: "membership",
        amount: paymentIntent.amount / 100,
        status: "completed",
        relatedId: clubId,
        relatedName: club.clubName,
        description: `Membership payment for ${club.clubName}`,
        stripeSessionId: paymentIntentId,
      });

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
// Register for Event
app.post("/events/:eventId/register", verifyFireBaseToken, async (req, res) => {
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
    if (!event) return res.status(404).send({ message: "Event not found" });
    const existingRegistration = await eventRegistrationsCollection.findOne({
      eventId: new ObjectId(eventId),
      userEmail,
    });
    if (existingRegistration) {
      return res
        .status(400)
        .send({ message: "Already registered for this event" });
    }
    if (event.maxAttendees && event.attendeeCount >= event.maxAttendees) {
      return res.status(400).send({ message: "Event is full" });
    }
    // Free event
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
      await eventsCollection.updateOne(
        { _id: new ObjectId(eventId) },
        { $inc: { attendeeCount: 1 } }
      );
      return res.send({
        message: "Registered successfully",
        registrationId: result.insertedId,
      });
    }
    // Paid event - create payment intent
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
    });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Internal server error" });
  }
});
// Create Event Registration Checkout Session
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
      if (!event) return res.status(404).send({ message: "Event not found" });
      const existingRegistration = await eventRegistrationsCollection.findOne({
        eventId: new ObjectId(eventId),
        userEmail,
      });
      if (existingRegistration) {
        return res
          .status(400)
          .send({ message: "Already registered for this event" });
      }
      if (event.maxAttendees && event.attendeeCount >= event.maxAttendees) {
        return res.status(400).send({ message: "Event is full" });
      }
      if (!event.isPaid || event.eventFee === 0) {
        return res.status(400).send({ message: "This is a free event" });
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
        metadata: { eventId, userEmail, type: "eventRegistration" },
      });
      res.send({ url: session.url, sessionId: session.id });
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);
// Verify Event Registration Session
app.post(
  "/events/verify-registration-session",
  verifyFireBaseToken,
  async (req, res) => {
    try {
      const { sessionId } = req.body;
      const userEmail = req.token_email;
      const { eventsCollection, eventRegistrationsCollection } =
        await connectDB();
      if (!sessionId)
        return res.status(400).send({ message: "Session ID required" });
      const session = await stripe.checkout.sessions.retrieve(sessionId);
      if (session.payment_status !== "paid") {
        return res.status(400).send({ message: "Payment not completed" });
      }
      const { eventId } = session.metadata;
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
      if (!event) return res.status(404).send({ message: "Event not found" });
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
        await eventsCollection.updateOne(
          { _id: new ObjectId(eventId) },
          { $inc: { attendeeCount: 1 } }
        );
        await recordPayment({
          transactionId: sessionId,
          userEmail,
          paymentType: "event",
          amount: session.amount_total / 100,
          status: "completed",
          relatedId: eventId,
          relatedName: event.title,
          description: `Event registration for ${event.title}`,
          stripeSessionId: sessionId,
        });
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
// Renew Membership
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
// Confirm Membership Renewal Payment
app.post(
  "/clubs/:clubId/confirm-renewal",
  verifyFireBaseToken,
  async (req, res) => {
    try {
      const { clubId } = req.params;
      const { paymentIntentId } = req.body;
      const userEmail = req.token_email;
      const { membershipsCollection, clubsCollection } = await connectDB();

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
      if (!membership)
        return res.status(404).send({ message: "Membership not found" });
      const club = await clubsCollection.findOne({ _id: new ObjectId(clubId) });
      await membershipsCollection.updateOne(
        { _id: membership._id },
        {
          $set: {
            status: "active",
            expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
            paymentId: paymentIntentId,
            renewedAt: new Date(),
          },
        }
      );
      // RECORD PAYMENT ✅ - ADD THIS
      await recordPayment({
        transactionId: paymentIntentId,
        userEmail,
        paymentType: "membership",
        amount: paymentIntent.amount / 100,
        status: "completed",
        relatedId: clubId,
        relatedName: club?.clubName || "Unknown Club",
        description: `Membership renewal for ${
          club?.clubName || "Unknown Club"
        }`,
        stripeSessionId: paymentIntentId,
      });
      res.send({ message: "Membership renewed successfully" });
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);
// Remove Membership
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
      if (!membership)
        return res.status(404).send({ message: "Membership not found" });
      const user = await usersCollection.findOne({ email: userEmail });
      const club = await clubsCollection.findOne({ _id: membership.clubId });
      const isOwnMembership = membership.userEmail === userEmail;
      const isClubManager = club && club.managerEmail === userEmail;
      const isAdmin = user && user.role === "admin";
      if (!isOwnMembership && !isClubManager && !isAdmin) {
        return res
          .status(403)
          .send({ message: "Not authorized to remove this membership" });
      }
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
// Get Member's Statistics
app.get("/member/statistics", verifyFireBaseToken, async (req, res) => {
  try {
    const userEmail = req.token_email;
    const {
      membershipsCollection,
      eventRegistrationsCollection,
      clubsCollection,
    } = await connectDB();
    const totalClubs = await membershipsCollection.countDocuments({
      userEmail,
      status: "active",
    });
    const eventsRegistered = await eventRegistrationsCollection.countDocuments({
      userEmail,
    });
    // Club breakdown
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
        { $group: { _id: "$club.clubName", value: { $sum: 1 } } },
        { $project: { name: "$_id", value: 1, _id: 0 } },
      ])
      .toArray();
    // Event attendance history (last 6 months)
    const sixMonthsAgo = new Date();
    sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
    const eventAttendanceHistory = await eventRegistrationsCollection
      .aggregate([
        { $match: { userEmail, registeredAt: { $gte: sixMonthsAgo } } },
        {
          $group: {
            _id: {
              year: { $year: "$registeredAt" },
              month: { $month: "$registeredAt" },
            },
            attendance: { $sum: 1 },
          },
        },
        { $sort: { _id: 1 } },
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
    res.json({
      totalClubs,
      eventsRegistered,
      clubsBreakdown,
      eventAttendanceHistory,
      clubsTrend: 5,
      eventsTrend: 3,
    });
  } catch (error) {
    console.error("Error fetching member stats:", error);
    res.status(500).json({ message: "Error fetching stats" });
  }
});
// Get Member's Clubs
app.get("/member/clubs", verifyFireBaseToken, async (req, res) => {
  try {
    const userEmail = req.token_email;
    const { membershipsCollection } = await connectDB();
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
            bannerImage: "$club.bannerImage",
            category: "$club.category",
            membershipStatus: "$status",
            joinedAt: "$joinedAt",
            expiresAt: "$expiresAt",
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
// Get Member's Events
app.get("/member/events", verifyFireBaseToken, async (req, res) => {
  try {
    const userEmail = req.token_email;
    const { eventRegistrationsCollection } = await connectDB();
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
            eventDate: "$event.eventDate",
            location: "$event.location",
            clubName: "$club.clubName",
            status: "$status",
            registeredAt: "$registeredAt",
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
// Create Checkout Session - Join Club
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

      const club = await clubsCollection.findOne({
        _id: new ObjectId(clubId),
      });
      if (!club) return res.status(404).send({ message: "Club not found" });
      if (club.status !== "approved") {
        return res.status(400).send({
          message: "This club is not available for membership",
        });
      }
      if (!club.membershipFee || club.membershipFee === 0) {
        return res
          .status(400)
          .send({ message: "This club has free membership" });
      }

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
        metadata: { clubId, userEmail, type: "join" },
      });

      res.send({ url: session.url, sessionId: session.id });
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);
// Create Checkout Session - Renew Membership
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
      if (!club) return res.status(404).send({ message: "Club not found" });
      if (!club.membershipFee || club.membershipFee === 0) {
        return res
          .status(400)
          .send({ message: "This club has free membership" });
      }

      const membership = await membershipsCollection.findOne({
        userEmail,
        clubId: new ObjectId(clubId),
      });

      if (!membership) {
        return res.status(404).send({ message: "Membership not found" });
      }

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
        metadata: { clubId, userEmail, type: "renewal" },
      });

      res.send({ url: session.url, sessionId: session.id });
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);
// Verify Checkout Session
app.post("/clubs/verify-session", verifyFireBaseToken, async (req, res) => {
  try {
    const { sessionId } = req.body;
    const userEmail = req.token_email;
    const { membershipsCollection, clubsCollection } = await connectDB();

    if (!sessionId) {
      return res.status(400).send({ message: "Session ID required" });
    }

    let session;
    try {
      session = await stripe.checkout.sessions.retrieve(sessionId);
    } catch (stripeErr) {
      console.error("Stripe retrieval error:", stripeErr);
      return res.status(400).send({ message: "Invalid session ID" });
    }

    if (session.payment_status !== "paid") {
      return res.status(400).send({
        message: `Payment not completed. Status: ${session.payment_status}`,
      });
    }

    const { clubId, type } = session.metadata;
    if (!clubId || !type) {
      return res.status(400).send({ message: "Invalid session metadata" });
    }

    if (type === "join") {
      const activeMembership = await membershipsCollection.findOne({
        userEmail,
        clubId: new ObjectId(clubId),
        status: "active",
      });

      if (activeMembership) {
        return res.send({
          message: "Already an active member of this club",
          alreadyMember: true,
        });
      }

      const existingPayment = await membershipsCollection.findOne({
        userEmail,
        clubId: new ObjectId(clubId),
        paymentId: sessionId,
      });

      if (existingPayment) {
        return res.send({
          message: "Membership already activated for this payment",
          alreadyProcessed: true,
        });
      }

      const club = await clubsCollection.findOne({
        _id: new ObjectId(clubId),
      });
      if (!club) return res.status(404).send({ message: "Club not found" });

      const newMembership = {
        userEmail,
        clubId: new ObjectId(clubId),
        status: "active",
        joinedAt: new Date(),
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
        paymentId: sessionId,
        amount: session.amount_total / 100,
        createdAt: new Date(),
      };

      try {
        const result = await membershipsCollection.insertOne(newMembership);

        await recordPayment({
          transactionId: sessionId,
          userEmail,
          paymentType: "membership",
          amount: session.amount_total / 100,
          status: "completed",
          relatedId: clubId,
          relatedName: club.clubName,
          description: `Membership payment for ${club.clubName}`,
          stripeSessionId: sessionId,
        });

        return res.send({
          message: "Membership activated successfully",
          membershipId: result.insertedId,
          success: true,
        });
      } catch (dbError) {
        if (dbError.code === 11000) {
          const existingMembership = await membershipsCollection.findOne({
            userEmail,
            clubId: new ObjectId(clubId),
            paymentId: sessionId,
          });

          if (existingMembership) {
            return res.send({
              message: "Membership already exists for this payment",
              alreadyProcessed: true,
            });
          }

          return res.status(400).send({
            message: "Membership already exists for this club",
          });
        }
        throw dbError;
      }
    } else if (type === "renewal") {
      const membership = await membershipsCollection.findOne({
        userEmail,
        clubId: new ObjectId(clubId),
      });

      if (!membership) {
        return res.status(404).send({ message: "Membership not found" });
      }

      const alreadyRenewed = await membershipsCollection.findOne({
        userEmail,
        clubId: new ObjectId(clubId),
        paymentId: sessionId,
      });

      if (alreadyRenewed) {
        return res.send({
          message: "Membership already renewed with this payment",
          alreadyProcessed: true,
        });
      }

      const club = await clubsCollection.findOne({
        _id: new ObjectId(clubId),
      });

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
        return res.status(400).send({ message: "Failed to update membership" });
      }

      await recordPayment({
        transactionId: sessionId,
        userEmail,
        paymentType: "membership",
        amount: session.amount_total / 100,
        status: "completed",
        relatedId: clubId,
        relatedName: club?.clubName || "Unknown Club",
        description: `Membership renewal for ${
          club?.clubName || "Unknown Club"
        }`,
        stripeSessionId: sessionId,
      });

      return res.send({
        message: "Membership renewed successfully",
        success: true,
      });
    } else {
      return res.status(400).send({ message: "Invalid transaction type" });
    }
  } catch (err) {
    console.error("Verification error:", err);
    res.status(500).send({ message: "Internal server error: " + err.message });
  }
});
// Get user event registration for a specific event
app.get(
  "/users/event-registrations/:eventId",
  verifyFireBaseToken,
  async (req, res) => {
    try {
      const { eventId } = req.params;
      const userEmail = req.token_email;
      const { eventRegistrationsCollection } = await connectDB();

      if (!ObjectId.isValid(eventId)) {
        return res.status(400).send({ message: "Invalid event ID" });
      }

      const registration = await eventRegistrationsCollection.findOne({
        eventId: new ObjectId(eventId),
        userEmail,
      });

      if (!registration) {
        return res.send({ isRegistered: false, registration: null });
      }

      res.send({
        isRegistered: true,
        registration: {
          _id: registration._id,
          status: registration.status,
          registeredAt: registration.registeredAt,
          paymentId: registration.paymentId,
        },
      });
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);
// Get all user event registrations
app.get("/users/event-registrations", verifyFireBaseToken, async (req, res) => {
  try {
    const userEmail = req.token_email;
    const { eventRegistrationsCollection } = await connectDB();

    const registrations = await eventRegistrationsCollection
      .find({ userEmail })
      .toArray();

    res.send(registrations);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Internal server error" });
  }
});
// Get all user memberships
app.get("/users/memberships", verifyFireBaseToken, async (req, res) => {
  try {
    const userEmail = req.token_email;
    const { membershipsCollection } = await connectDB();

    const memberships = await membershipsCollection
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
            _id: 1,
            clubId: 1,
            clubName: "$club.clubName",
            clubCategory: "$club.category",
            clubLocation: "$club.location",
            status: 1,
            joinedAt: 1,
            expiresAt: 1,
            amount: 1,
            userEmail: 1,
          },
        },
      ])
      .toArray();

    res.send(memberships);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Internal server error" });
  }
});
// Cancel Event Registration
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

      // Verify ownership
      if (registration.userEmail !== userEmail) {
        return res.status(403).send({ message: "Not authorized" });
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
// Get Member's Payments
app.get("/member/payments", verifyFireBaseToken, async (req, res) => {
  try {
    const userEmail = req.token_email;
    const { paymentsCollection } = await connectDB();

    // Get all payments for this user
    const payments = await paymentsCollection
      .find({
        userEmail,
        status: "completed",
      })
      .sort({ createdAt: -1 })
      .toArray();

    // Separate payments by type
    const membershipPayments = payments.filter(
      (p) => p.paymentType === "membership"
    );
    const eventPayments = payments.filter((p) => p.paymentType === "event");

    res.json({
      membershipPayments,
      eventPayments,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.message });
  }
});
// Get payments for a user
// app.get("/payments/user/:email", verifyFireBaseToken, async (req, res) => {
//   try {
//     const { paymentsCollection, usersCollection } = await connectDB();
//     const email = req.params.email;
//     const user = await usersCollection.findOne({ email: req.token_email });
//     if (req.token_email !== email && user?.role !== "admin") {
//       return res.status(403).json({ message: "Unauthorized" });
//     }
//     const payments = await paymentsCollection
//       .find({ userEmail: email })
//       .sort({ createdAt: -1 })
//       .toArray();
//     res.json(payments);
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({ message: error.message });
//   }
// });

/*===== Club Manager Routes =====*/
// Get club(s) by ID or manager email
app.get(
  "/clubs/:param",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const { clubsCollection } = await connectDB();
      const param = req.params.param;
      if (ObjectId.isValid(param)) {
        const club = await clubsCollection.findOne({
          _id: new ObjectId(param),
        });
        if (!club) return res.status(404).send({ message: "Club not found" });
        const { authorized } = await verifyClubOwnership(
          param,
          req.token_email
        );
        if (!authorized)
          return res.status(403).send({ message: "Not authorized" });
        return res.send(club);
      }
      // Fetch by manager email
      if (param !== req.token_email)
        return res.status(403).send({ message: "Not authorized" });
      const clubs = await clubsCollection
        .find({ managerEmail: param })
        .toArray();
      res.send(clubs);
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);
// Create a new club
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
// Update a club
app.patch(
  "/clubs/:id",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const { clubsCollection } = await connectDB();
      const id = req.params.id;
      const { authorized } = await verifyClubOwnership(id, req.token_email);
      if (!authorized)
        return res.status(403).send({ message: "Not authorized" });
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
// Delete a club
app.delete(
  "/clubs/:id",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const { clubsCollection } = await connectDB();
      const id = req.params.id;
      const { authorized } = await verifyClubOwnership(id, req.token_email);
      if (!authorized)
        return res.status(403).send({ message: "Not authorized" });
      await clubsCollection.deleteOne({ _id: new ObjectId(id) });
      res.send({ message: "Club deleted successfully" });
    } catch (e) {
      console.error(e);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);
// Create Event
app.post(
  "/clubs/:clubId/events",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const { clubId } = req.params;
      const { clubsCollection, eventsCollection } = await connectDB();
      if (!ObjectId.isValid(clubId))
        return res.status(400).send({ message: "Invalid club ID" });
      const { authorized } = await verifyClubOwnership(clubId, req.token_email);
      if (!authorized)
        return res.status(403).send({ message: "Not authorized" });
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
      });
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);
// Update an Event
app.patch(
  "/events/:eventId",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const { eventId } = req.params;
      const { authorized } = await verifyEventOwnership(
        eventId,
        req.token_email
      );
      if (!authorized)
        return res.status(403).send({ message: "Not authorized" });
      const { eventsCollection } = await connectDB();
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
          ...(title && { title }),
          ...(description && { description }),
          ...(eventDate && { eventDate: new Date(eventDate) }),
          ...(location && { location }),
          ...(isPaid !== undefined && { isPaid: Boolean(isPaid) }),
          ...(isPaid && eventFee && { eventFee: Number(eventFee) }),
          ...(maxAttendees && { maxAttendees: Number(maxAttendees) }),
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
// Delete Event
app.delete(
  "/events/:eventId",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const { eventId } = req.params;
      const { authorized } = await verifyEventOwnership(
        eventId,
        req.token_email
      );
      if (!authorized)
        return res.status(403).send({ message: "Not authorized" });
      const { eventsCollection } = await connectDB();
      await eventsCollection.deleteOne({ _id: new ObjectId(eventId) });
      res.send({ message: "Event deleted successfully" });
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);
// // Manager's Events
// app.get(
//   "/manager/events",
//   verifyFireBaseToken,
//   verifyClubManager,
//   async (req, res) => {
//     try {
//       const { eventsCollection, clubsCollection } = await connectDB();
//       const managerEmail = req.token_email;
//       const managedClubs = await clubsCollection
//         .find({ managerEmail })
//         .toArray();
//       if (managedClubs.length === 0) return res.send([]);
//       const clubIds = managedClubs.map((club) => club._id);
//       const events = await eventsCollection
//         .find({ clubId: { $in: clubIds } })
//         .sort({ eventDate: -1 })
//         .toArray();
//       const enrichedEvents = events.map((event) => {
//         const club = managedClubs.find((c) => c._id.equals(event.clubId));
//         return { ...event, clubData: club };
//       });
//       res.send(enrichedEvents);
//     } catch (err) {
//       console.error(err);
//       res.status(500).send({ message: "Internal server error" });
//     }
//   }
// );
// Club Manager Stats
app.get(
  "/club-manager/statistics",
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
        paymentsCollection,
      } = await connectDB();
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
        });
      }
      const clubIds = managedClubs.map((club) => club._id);
      const totalMembers = await membershipsCollection.countDocuments({
        clubId: { $in: clubIds },
        status: "active",
      });
      const totalEvents = await eventsCollection.countDocuments({
        clubId: { $in: clubIds },
      });
      const totalRevenue = await paymentsCollection
        .aggregate([
          {
            $match: {
              relatedId: { $in: clubIds.map((id) => id.toString()) },
              status: "completed",
            },
          },
          { $group: { _id: null, total: { $sum: "$amount" } } },
        ])
        .toArray();
      // Membership growth
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
          { $group: { _id: "$club.clubName", value: { $sum: 1 } } },
          { $project: { name: "$_id", value: 1, _id: 0 } },
        ])
        .toArray();
      // Top events by attendance
      const eventAttendance = await eventsCollection
        .aggregate([
          { $match: { clubId: { $in: clubIds } } },
          { $project: { name: "$title", attendance: "$attendeeCount" } },
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
          { $group: { _id: "$club.clubName", revenue: { $sum: "$amount" } } },
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
      // Event status
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
      res.json({
        totalMembers,
        totalClubs: managedClubs.length,
        totalEvents,
        totalRevenue: totalRevenue[0]?.total || 0,
        membershipGrowth,
        clubsDistribution,
        eventAttendance,
        membershipStatus,
        revenueByClub,
        eventStatus,
      });
    } catch (error) {
      console.error("Error fetching club manager stats:", error);
      res.status(500).json({ message: "Error fetching stats" });
    }
  }
);
// Get manager payments
app.get(
  "/manager/payments",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const managerEmail = req.token_email;
      const { clubsCollection, paymentsCollection } = await connectDB();

      // Get all clubs managed by this manager
      const managedClubs = await clubsCollection
        .find({ managerEmail })
        .toArray();

      if (managedClubs.length === 0) {
        return res.json({
          membershipPayments: [],
          eventPayments: [],
        });
      }

      const clubIds = managedClubs.map((club) => club._id.toString());

      // Get all payments related to these clubs
      const payments = await paymentsCollection
        .find({
          relatedId: { $in: clubIds },
          status: "completed",
        })
        .sort({ createdAt: -1 })
        .toArray();

      // Separate payments by type
      const membershipPayments = payments.filter(
        (p) => p.paymentType === "membership"
      );
      const eventPayments = payments.filter((p) => p.paymentType === "event");

      res.json({
        membershipPayments,
        eventPayments,
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: error.message });
    }
  }
);
// Get manager payment statistics
app.get(
  "/manager/payments/statistics",
  verifyFireBaseToken,
  verifyClubManager,
  async (req, res) => {
    try {
      const managerEmail = req.token_email;
      const { clubsCollection, paymentsCollection } = await connectDB();

      // Get all clubs managed by this manager
      const managedClubs = await clubsCollection
        .find({ managerEmail })
        .toArray();

      if (managedClubs.length === 0) {
        return res.json({
          totalRevenue: 0,
          membershipRevenue: 0,
          eventRevenue: 0,
          totalTransactions: 0,
          revenueByType: [],
          monthlyRevenue: [],
        });
      }

      const clubIds = managedClubs.map((club) => club._id.toString());

      // Overall statistics
      const totalStats = await paymentsCollection
        .aggregate([
          {
            $match: {
              status: "completed",
              relatedId: { $in: clubIds },
            },
          },
          {
            $group: {
              _id: null,
              totalRevenue: { $sum: "$amount" },
              totalTransactions: { $sum: 1 },
              totalNetAmount: { $sum: "$netAmount" },
              totalPlatformFees: { $sum: "$stripePlatformFee" },
            },
          },
        ])
        .toArray();

      // Revenue by type
      const revenueByType = await paymentsCollection
        .aggregate([
          {
            $match: {
              status: "completed",
              relatedId: { $in: clubIds },
            },
          },
          {
            $group: {
              _id: "$paymentType",
              revenue: { $sum: "$amount" },
              count: { $sum: 1 },
            },
          },
        ])
        .toArray();

      // Membership revenue specifically
      const membershipStats = revenueByType.find(
        (r) => r._id === "membership"
      ) || { revenue: 0, count: 0 };

      // Event revenue specifically
      const eventStats = revenueByType.find((r) => r._id === "event") || {
        revenue: 0,
        count: 0,
      };

      // Monthly revenue
      const monthlyRevenue = await paymentsCollection
        .aggregate([
          {
            $match: {
              status: "completed",
              relatedId: { $in: clubIds },
            },
          },
          {
            $addFields: {
              createdAtDate: {
                $cond: [
                  { $eq: [{ $type: "$createdAt" }, "date"] },
                  "$createdAt",
                  { $toDate: "$createdAt" },
                ],
              },
            },
          },
          {
            $group: {
              _id: {
                $dateToString: {
                  format: "%b %Y",
                  date: "$createdAtDate",
                },
              },
              revenue: { $sum: "$amount" },
              count: { $sum: 1 },
            },
          },
          { $sort: { _id: 1 } },
          {
            $project: {
              _id: 0,
              month: "$_id",
              revenue: { $round: ["$revenue", 2] },
              count: 1,
            },
          },
        ])
        .toArray();

      const stats = totalStats[0] || {
        totalRevenue: 0,
        totalTransactions: 0,
        totalNetAmount: 0,
        totalPlatformFees: 0,
      };

      res.json({
        ...stats,
        membershipRevenue: membershipStats.revenue || 0,
        eventRevenue: eventStats.revenue || 0,
        membershipCount: membershipStats.count || 0,
        eventCount: eventStats.count || 0,
        revenueByType,
        monthlyRevenue,
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: error.message });
    }
  }
);

/*===== Admin Routes =====*/
// Admin Stats
app.get("/admin/stats", verifyFireBaseToken, verifyAdmin, async (req, res) => {
  try {
    const {
      usersCollection,
      clubsCollection,
      membershipsCollection,
      eventsCollection,
      eventRegistrationsCollection,
      paymentsCollection,
    } = await connectDB();
    const totalUsers = await usersCollection.countDocuments();
    const totalClubs = await clubsCollection.countDocuments();
    const totalEvents = await eventsCollection.countDocuments();
    const totalRevenue = await paymentsCollection
      .aggregate([
        { $match: { status: "completed" } },
        { $group: { _id: null, total: { $sum: "$amount" } } },
      ])
      .toArray();

    // Events revenue
    const eventsRevenue = await paymentsCollection
      .aggregate([
        { $match: { status: "completed", paymentType: "event" } },
        { $group: { _id: null, total: { $sum: "$amount" } } },
      ])
      .toArray();

    // Membership revenue
    const membershipRevenue = await paymentsCollection
      .aggregate([
        { $match: { status: "completed", paymentType: "membership" } },
        { $group: { _id: null, total: { $sum: "$amount" } } },
      ])
      .toArray();

    // Total event registrations
    const totalEventRegistrations =
      await eventRegistrationsCollection.countDocuments();

    // User growth (last 6 months)
    const userGrowth = await usersCollection
      .aggregate([
        {
          $addFields: {
            createdAtDate: {
              $cond: [
                { $eq: [{ $type: "$createdAt" }, "date"] },
                "$createdAt",
                { $toDate: "$createdAt" },
              ],
            },
          },
        },
        {
          $group: {
            _id: {
              $dateToString: {
                format: "%b %Y",
                date: "$createdAtDate",
              },
            },
            users: { $sum: 1 },
          },
        },
        { $sort: { _id: 1 } },
        {
          $project: {
            _id: 0,
            name: "$_id",
            users: 1,
          },
        },
      ])
      .toArray();
    // Clubs by category
    const clubsByCategory = await clubsCollection
      .aggregate([
        { $group: { _id: "$category", value: { $sum: 1 } } },
        {
          $project: {
            _id: 0,
            name: { $ifNull: ["$_id", "Uncategorized"] },
            value: 1,
          },
        },
      ])
      .toArray();
    // Monthly revenue
    const revenueByMonth = await paymentsCollection
      .aggregate([
        { $match: { status: "completed" } },
        {
          $addFields: {
            createdAtDate: {
              $cond: [
                { $eq: [{ $type: "$createdAt" }, "date"] },
                "$createdAt",
                { $toDate: "$createdAt" },
              ],
            },
          },
        },
        {
          $group: {
            _id: {
              $dateToString: {
                format: "%b %Y",
                date: "$createdAtDate",
              },
            },
            revenue: { $sum: "$amount" },
            count: { $sum: 1 },
          },
        },
        { $sort: { _id: 1 } },
        {
          $project: {
            _id: 0,
            month: "$_id",
            revenue: { $round: ["$revenue", 2] },
            count: 1,
          },
        },
      ])
      .toArray();
    // Membership status distribution
    const membershipDistribution = await membershipsCollection
      .aggregate([
        { $group: { _id: "$status", value: { $sum: 1 } } },
        {
          $project: {
            _id: 0,
            name: { $ifNull: ["$_id", "Unknown"] },
            value: 1,
          },
        },
      ])
      .toArray();

    // Events status distribution
    const eventsStatusDistribution = await eventsCollection
      .aggregate([
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
        {
          $project: {
            _id: 0,
            name: "$_id",
            value: 1,
          },
        },
      ])
      .toArray();

    // Top events by registration
    const topEvents = await eventsCollection
      .aggregate([
        {
          $lookup: {
            from: "eventRegistrationsCollection",
            localField: "_id",
            foreignField: "eventId",
            as: "registrations",
          },
        },
        {
          $project: {
            title: 1,
            registrations: { $size: "$registrations" },
            eventDate: 1,
          },
        },
        { $sort: { registrations: -1 } },
        { $limit: 5 },
        {
          $project: {
            name: "$title",
            value: "$registrations",
            _id: 0,
          },
        },
      ])
      .toArray();

    // Monthly trends
    const thisMonth = new Date();
    thisMonth.setDate(1);
    thisMonth.setHours(0, 0, 0, 0);
    const lastMonth = new Date(thisMonth);
    lastMonth.setMonth(lastMonth.getMonth() - 1);
    const thisMonthUsers = await usersCollection.countDocuments({
      createdAt: { $gte: thisMonth },
    });
    const lastMonthUsers = await usersCollection.countDocuments({
      createdAt: { $gte: lastMonth, $lt: thisMonth },
    });
    const usersTrend =
      lastMonthUsers > 0
        ? Math.round(((thisMonthUsers - lastMonthUsers) / lastMonthUsers) * 100)
        : 0;

    // Calculate club trend
    const thisMonthClubs = await clubsCollection.countDocuments({
      createdAt: { $gte: thisMonth },
    });
    const lastMonthClubs = await clubsCollection.countDocuments({
      createdAt: { $gte: lastMonth, $lt: thisMonth },
    });
    const clubsTrend =
      lastMonthClubs > 0
        ? Math.round(((thisMonthClubs - lastMonthClubs) / lastMonthClubs) * 100)
        : 0;

    // Calculate events trend
    const thisMonthEvents = await eventsCollection.countDocuments({
      createdAt: { $gte: thisMonth },
    });
    const lastMonthEvents = await eventsCollection.countDocuments({
      createdAt: { $gte: lastMonth, $lt: thisMonth },
    });
    const eventsTrend =
      lastMonthEvents > 0
        ? Math.round(
            ((thisMonthEvents - lastMonthEvents) / lastMonthEvents) * 100
          )
        : 0;

    // Calculate revenue trend
    const thisMonthRevenue = await paymentsCollection
      .aggregate([
        {
          $match: {
            status: "completed",
            createdAt: { $gte: thisMonth },
          },
        },
        { $group: { _id: null, total: { $sum: "$amount" } } },
      ])
      .toArray();
    const lastMonthRevenue = await paymentsCollection
      .aggregate([
        {
          $match: {
            status: "completed",
            createdAt: { $gte: lastMonth, $lt: thisMonth },
          },
        },
        { $group: { _id: null, total: { $sum: "$amount" } } },
      ])
      .toArray();
    const thisMonthRevenueTotal = thisMonthRevenue[0]?.total || 0;
    const lastMonthRevenueTotal = lastMonthRevenue[0]?.total || 0;
    const revenueTrend =
      lastMonthRevenueTotal > 0
        ? Math.round(
            ((thisMonthRevenueTotal - lastMonthRevenueTotal) /
              lastMonthRevenueTotal) *
              100
          )
        : 0;

    res.json({
      totalUsers,
      totalClubs,
      totalEvents,
      totalEventRegistrations,
      totalRevenue: totalRevenue[0]?.total || 0,
      eventsRevenue: eventsRevenue[0]?.total || 0,
      membershipRevenue: membershipRevenue[0]?.total || 0,
      userGrowth,
      clubsByCategory,
      revenueByMonth,
      membershipDistribution,
      eventsStatusDistribution,
      topEvents,
      usersTrend,
      clubsTrend,
      eventsTrend,
      revenueTrend,
    });
  } catch (error) {
    console.error("Error fetching admin stats:", error);
    res.status(500).json({ message: "Error fetching stats" });
  }
});
// Get all payments (admin only)
app.get(
  "/admin/payments",
  verifyFireBaseToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { paymentsCollection } = await connectDB();
      const payments = await paymentsCollection
        .find({})
        .sort({ createdAt: -1 })
        .toArray();

      // Separate payments by type
      const membershipPayments = payments.filter(
        (p) => p.paymentType === "membership"
      );
      const eventPayments = payments.filter((p) => p.paymentType === "event");

      res.json({
        membershipPayments,
        eventPayments,
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: error.message });
    }
  }
);
// Get payment statistics (admin only)
app.get(
  "/admin/payments/statistics",
  verifyFireBaseToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { paymentsCollection } = await connectDB();

      // Overall statistics
      const totalStats = await paymentsCollection
        .aggregate([
          { $match: { status: "completed" } },
          {
            $group: {
              _id: null,
              totalRevenue: { $sum: "$amount" },
              totalTransactions: { $sum: 1 },
              totalNetAmount: { $sum: "$netAmount" },
              totalPlatformFees: { $sum: "$stripePlatformFee" },
            },
          },
        ])
        .toArray();

      // Revenue by type
      const revenueByType = await paymentsCollection
        .aggregate([
          { $match: { status: "completed" } },
          {
            $group: {
              _id: "$paymentType",
              revenue: { $sum: "$amount" },
              count: { $sum: 1 },
            },
          },
        ])
        .toArray();

      // Membership revenue specifically
      const membershipStats = revenueByType.find(
        (r) => r._id === "membership"
      ) || { revenue: 0, count: 0 };

      // Event revenue specifically
      const eventStats = revenueByType.find((r) => r._id === "event") || {
        revenue: 0,
        count: 0,
      };

      // Monthly revenue
      const monthlyRevenue = await paymentsCollection
        .aggregate([
          { $match: { status: "completed" } },
          {
            $group: {
              _id: {
                year: { $year: "$createdAt" },
                month: { $month: "$createdAt" },
              },
              revenue: { $sum: "$amount" },
              count: { $sum: 1 },
            },
          },
          { $sort: { "_id.year": 1, "_id.month": 1 } },
          {
            $project: {
              month: {
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
              count: 1,
              _id: 0,
            },
          },
        ])
        .toArray();

      const stats = totalStats[0] || {
        totalRevenue: 0,
        totalTransactions: 0,
        totalNetAmount: 0,
        totalPlatformFees: 0,
      };

      res.json({
        ...stats,
        membershipRevenue: membershipStats.revenue || 0,
        eventRevenue: eventStats.revenue || 0,
        membershipCount: membershipStats.count || 0,
        eventCount: eventStats.count || 0,
        revenueByType,
        monthlyRevenue,
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: error.message });
    }
  }
);
// List all clubs (admin only)
app.get("/admin/clubs", verifyFireBaseToken, verifyAdmin, async (req, res) => {
  try {
    const { clubsCollection } = await connectDB();
    const clubs = await clubsCollection
      .find({})
      .sort({ createdAt: -1 })
      .toArray();
    res.send(clubs);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Internal server error" });
  }
});
// Update club status (Admin only)
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
      await clubsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { status, updatedAt: new Date() } }
      );
      res.send({ message: `Club ${status}` });
    } catch (e) {
      console.error(e);
      res.status(500).send({ message: "Internal server error" });
    }
  }
);
// Update user role (Admin only)
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
      // ROLE UPDATE LOGIC
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
      // APPLICATION SYNCING LOGIC
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
// List all club manager applications
app.get(
  "/admin/club-manager-applications",
  verifyFireBaseToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { applicationsCollection } = await connectDB();
      const apps = await applicationsCollection.find({}).toArray();
      res.send(apps);
    } catch (e) {
      res.status(500).send({ message: "Internal server error" });
    }
  }
);
// Approve club manager application
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
// List all users (admin only)
app.get("/admin/users", verifyFireBaseToken, verifyAdmin, async (req, res) => {
  try {
    const { usersCollection } = await connectDB();
    const users = await usersCollection.find().toArray();
    res.send(users);
  } catch (e) {
    res.status(500).send({ message: "Internal server error" });
  }
});
