// server.js — Grievance Portal Backend (MongoDB + Twilio)
// Requires: dotenv, express, cors, body-parser, mongoose, twilio, nanoid
// Make sure your package.json has "type": "module"

// ------------------ 1️⃣ Core imports ------------------
import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import dotenv from "dotenv";
dotenv.config();

import mongoose from "mongoose";
import twilio from "twilio";
import { nanoid } from "nanoid";

// ------------------ 2️⃣ Connect to MongoDB ------------------
async function connectDB() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("✅ MongoDB connected");
  } catch (err) {
    console.error("❌ DB connection failed:", err);
    process.exit(1);
  }
}
await connectDB();
console.log("🔍 ENV check:");
console.log("MONGO_URI:", process.env.MONGO_URI ? "loaded" : "missing");
console.log("TWILIO_SID:", process.env.TWILIO_SID ? "loaded" : "missing");
console.log("TWILIO_FROM:", process.env.TWILIO_FROM ? process.env.TWILIO_FROM : "missing");

// ------------------ 3️⃣ Twilio client ------------------
if (!process.env.TWILIO_SID || !process.env.TWILIO_TOKEN) {
  console.warn("⚠️ Twilio credentials not found in .env. SMS won't work.");
}
const twilioClient = twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN);

// ------------------ 4️⃣ Express setup ------------------
const app = express();
app.use(
  cors({
    origin: ["http://localhost:3000", "http://localhost:3001"],
    credentials: true,
  })
);
app.use(bodyParser.json());

// ------------------ 5️⃣ Define Schemas & Models ------------------
const userSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  role: { type: String, enum: ["student", "staff", "admin"], required: true },
  fullName: String,
  email: String,
  phone: String,
  password: String,
  program: String,
});

const otpSchema = new mongoose.Schema({
  userId: String,
  role: String,
  phone: String,
  otp: String,
  createdAt: Number,
  expiresAt: Number,
});

const grievanceSchema = new mongoose.Schema({
  userId: String,
  name: String,
  email: String,
  school: String,
  category: String,
  message: String,
  status: { type: String, default: "Pending" },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.models.User || mongoose.model("User", userSchema);
const OTP = mongoose.models.OTP || mongoose.model("OTP", otpSchema);
const Grievance =
  mongoose.models.Grievance || mongoose.model("Grievance", grievanceSchema);

// ------------------ 6️⃣ Routes ------------------

// Health check
app.get("/", (req, res) => {
  res.send("✅ Grievance Portal Backend Running (MongoDB + Twilio)");
});

// ------------------ Register Endpoint ------------------
app.post("/api/auth/register", async (req, res) => {
  try {
    const { id, role, fullName, email, phone, password, program } = req.body;
    if (!id || !phone || !password || !role)
      return res.status(400).json({ message: "Missing fields" });

    const exists = await User.findOne({ id });
    if (exists) return res.status(400).json({ message: "User already exists" });

    const newUser = await User.create({
      id,
      role,
      fullName,
      email,
      phone,
      password,
      program,
    });

    return res.status(201).json({ message: "Registered", user: newUser });
  } catch (err) {
    console.error("❌ Error /api/auth/register:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// ------------------ Request OTP ------------------
app.post("/api/auth/request-otp", async (req, res) => {
  try {
    const { role, id, phone } = req.body;
    if (!role || !id || !phone)
      return res.status(400).json({ message: "Missing fields" });

    const user = await User.findOne({ role, id, phone });
    if (!user)
      return res
        .status(404)
        .json({ message: "User not found or phone mismatch" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    const otpRecord = await OTP.create({
      userId: id,
      role,
      phone,
      otp,
      createdAt: Date.now(),
      expiresAt: Date.now() + 5 * 60 * 1000,
    });

    if (
      process.env.TWILIO_SID &&
      process.env.TWILIO_TOKEN &&
      process.env.TWILIO_FROM
    ) {
      try {
        console.log(`📨 Sending OTP to +91${phone}...`);
        const message = await twilioClient.messages.create({
          body: `Your Grievance Portal OTP is ${otp}`,
          from: process.env.TWILIO_FROM,
          to: `+91${phone}`,
        });
        console.log(`✅ Twilio Message SID: ${message.sid}`);
        return res.json({ message: "OTP sent successfully", otpId: otpRecord._id });
      } catch (twErr) {
        console.error("❌ Twilio send error:", twErr.message);
      }
    }

    console.log(`🧩 Mock OTP for ${role} (${id}): ${otp}`);
    return res.json({ message: "OTP sent (mock)", otpId: otpRecord._id, otp });
  } catch (err) {
    console.error("❌ Error /api/auth/request-otp:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// ------------------ Verify OTP ------------------
app.post("/api/auth/verify-otp", async (req, res) => {
  try {
    const { id, otp } = req.body;
    if (!id || !otp) return res.status(400).json({ message: "Missing fields" });

    const record = await OTP.findOne({ userId: id, otp });
    if (!record) return res.status(400).json({ message: "Invalid OTP" });

    if (Date.now() > record.expiresAt) {
      await OTP.deleteOne({ _id: record._id });
      return res.status(400).json({ message: "OTP expired" });
    }

    const user = await User.findOne({ id: record.userId });
    if (!user) return res.status(404).json({ message: "User not found" });

    await OTP.deleteOne({ _id: record._id });

    return res.json({
      message: "Verified",
      role: user.role,
      id: user.id,
      token: "mock-jwt-token",
    });
  } catch (err) {
    console.error("❌ Error /api/auth/verify-otp:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// ------------------ Submit Grievance ------------------
app.post("/api/grievances", async (req, res) => {
  try {
    const { userId, name, email, school, category, message } = req.body;
    if (!userId || !name || !email || !school || !category || !message)
      return res.status(400).json({ message: "All fields required" });

    const newGrievance = await Grievance.create({
      userId,
      name,
      email,
      school,
      category,
      message,
    });

    return res
      .status(201)
      .json({ message: "Grievance submitted successfully", newGrievance });
  } catch (err) {
    console.error("❌ Error /api/grievances:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// ------------------ Get All Grievances (for staff/admin) ------------------
app.get("/api/grievances", async (req, res) => {
  try {
    const grievances = await Grievance.find().sort({ createdAt: -1 }).lean();
    return res.json(grievances);
  } catch (err) {
    console.error("❌ Error /api/grievances GET:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// ------------------ 7️⃣ Start server ------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
