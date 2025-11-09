// server.js — Grievance Portal Backend (MongoDB + Twilio)
// Requires: dotenv, express, cors, body-parser, mongoose, twilio, nanoid, bcrypt, jsonwebtoken
// Ensure package.json has "type": "module"

// ------------------ 1️⃣ Core imports ------------------
import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import dotenv from "dotenv";
dotenv.config();

import mongoose from "mongoose";
import twilio from "twilio";
import { nanoid } from "nanoid";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

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

// ------------------ 3️⃣ Twilio client ------------------
if (!process.env.TWILIO_SID || !process.env.TWILIO_TOKEN) {
  console.warn("⚠️ Twilio credentials not found. SMS will not be sent.");
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

// ------------------ 5️⃣ Schemas & Models ------------------
const userSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  role: { type: String, enum: ["student", "staff", "admin"], required: true },
  fullName: String,
  email: String,
  phone: String,
  password: String, // stored hashed
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

// ------------------ Register ------------------
app.post("/api/auth/register", async (req, res) => {
  try {
    const { id, role, fullName, email, phone, password, program } = req.body;
    if (!id || !phone || !password || !role)
      return res.status(400).json({ message: "Missing required fields" });

    const exists = await User.findOne({ id });
    if (exists) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await User.create({
      id,
      role,
      fullName,
      email,
      phone,
      password: hashedPassword,
      program,
    });

    res.status(201).json({ message: "Registered successfully", user: newUser });
  } catch (err) {
    console.error("❌ /register:", err);
    res.status(500).json({ message: "Internal server error" });
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
      return res.status(404).json({ message: "User not found or phone mismatch" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    const otpRecord = await OTP.create({
      userId: id,
      role,
      phone,
      otp,
      createdAt: Date.now(),
      expiresAt: Date.now() + 5 * 60 * 1000, // expires in 5 min
    });

    if (
      process.env.TWILIO_SID &&
      process.env.TWILIO_TOKEN &&
      process.env.TWILIO_FROM
    ) {
      try {
        await twilioClient.messages.create({
          body: `Your Grievance Portal OTP is ${otp}`,
          from: process.env.TWILIO_FROM,
          to: `+91${phone}`,
        });
        console.log(`✅ OTP sent via Twilio to +91${phone}`);
      } catch (err) {
        console.error("❌ Twilio send error:", err.message);
      }
    } else {
      console.log(`🧩 Mock OTP for ${id}: ${otp}`);
    }

    res.json({ message: "OTP generated", otpId: otpRecord._id });
  } catch (err) {
    console.error("❌ /request-otp:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});



// ------------------ Verify OTP + Password ------------------
app.post("/api/auth/verify-otp-password", async (req, res) => {
  try {
    const { id, otp, password, role } = req.body;
    if (!id || !otp || !password || !role)
      return res.status(400).json({ message: "Missing fields" });

    // Step 1: Verify OTP exists and is valid
    const record = await OTP.findOne({ userId: id, otp });
    if (!record) return res.status(400).json({ message: "Invalid OTP" });
    if (Date.now() > record.expiresAt) {
      await OTP.deleteOne({ _id: record._id });
      return res.status(400).json({ message: "OTP expired" });
    }

    // Step 2: Get user
    const user = await User.findOne({ id, role });
    if (!user) return res.status(404).json({ message: "User not found" });

    // Step 3: Compare password (bcrypt check)
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Incorrect password" });

    // Step 4: Delete OTP (for security)
    await OTP.deleteOne({ _id: record._id });

    // Step 5: Return success
    res.json({
      message: "Verified successfully",
      role: user.role,
      id: user.id,
      token: "mock-jwt-token",
    });
  } catch (err) {
    console.error("❌ Error /api/auth/verify-otp-password:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});



// ------------------ ✅ Verify OTP + Password (New Endpoint) ------------------
app.post("/api/auth/verify-otp-password", async (req, res) => {
  try {
    const { id, otp, password, role } = req.body;
    if (!id || !otp || !password || !role)
      return res.status(400).json({ message: "Missing fields" });

    // 1️⃣ Check user
    const user = await User.findOne({ id, role });
    if (!user) return res.status(404).json({ message: "User not found" });

    // 2️⃣ Check OTP
    const otpRecord = await OTP.findOne({ userId: id, otp });
    if (!otpRecord) return res.status(400).json({ message: "Invalid OTP" });
    if (Date.now() > otpRecord.expiresAt) {
      await OTP.deleteOne({ _id: otpRecord._id });
      return res.status(400).json({ message: "OTP expired" });
    }

    // 3️⃣ Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid password" });

    // 4️⃣ Success
    await OTP.deleteOne({ _id: otpRecord._id });
    const token = jwt.sign({ id: user.id, role: user.role }, "mock_secret");

    res.json({
      message: "✅ OTP + Password verified successfully",
      id: user.id,
      role: user.role,
      token,
    });
  } catch (err) {
    console.error("❌ /verify-otp-password:", err);
    res.status(500).json({ message: "Internal server error" });
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

    res
      .status(201)
      .json({ message: "Grievance submitted successfully", newGrievance });
  } catch (err) {
    console.error("❌ /grievances POST:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// ------------------ Get All Grievances ------------------
app.get("/api/grievances", async (req, res) => {
  try {
    const grievances = await Grievance.find().sort({ createdAt: -1 }).lean();
    res.json(grievances);
  } catch (err) {
    console.error("❌ /grievances GET:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// ------------------ 7️⃣ Start server ------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`🚀 Server running at http://localhost:${PORT}`)
);
