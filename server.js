import express from "express";
import http from "http";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import validator from "validator";
import jwt from "jsonwebtoken";
import { fileURLToPath } from "url";
import path from "path";
import nodemailer from "nodemailer";
import { Server } from "socket.io";
import { v2 as cloudinary } from 'cloudinary';
import multer from 'multer';
import fs from 'fs';
import Razorpay from "razorpay";
import crypto from "crypto";

// imports ke baad add karein
import admin from "firebase-admin";
import { readFileSync } from 'fs';

// JSON file ko read karke initialize karein
const serviceAccount = JSON.parse(readFileSync('./firebase-key.json', 'utf8'));

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

// 🟢 SECURITY IMPORTS (Yahan add karein)
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import mongoSanitize from "express-mongo-sanitize";
import xss from "xss-clean";
import morgan from "morgan";

// ✅ 1. Load Environment Variables
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);

// 🟢 1. Sabse pehle CORS hona chahiye (Frontend port 5174 allow kiya)
app.use(cors({
    origin: [
        "http://localhost:5173", 
        "http://localhost:5174", 
        "http://localhost:5175",
        "http://192.168.1.15:5173", // 🟢 Aapka frontend IP + Port
        "http://192.168.1.15:5174",
        "http://192.168.1.15:5175",
        "http://10.0.2.2:5173", // Emulator browser ke liye
        "http://10.0.2.2"  // Capacitor app ke liye
    ],
    methods: ["GET", "POST", "DELETE", "PUT", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true
}));

// 🟢 2. Uske baad JSON parser
app.use(express.json({ limit: '50mb' })); 

// 🟢 3. Phir baaki security (Helmet ko local ke liye thoda loose rakha hai)
app.use(helmet({
    crossOriginResourcePolicy: false,
}));
app.use(morgan("dev")); 
app.use(mongoSanitize());
app.use(xss());

// 🟢 4. Rate Limiter (Isse CORS ke baad hona chahiye)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 200, // Limit thodi badha di taaki analytics block na ho
  message: "Too many requests, please try again later."
});
app.use("/api", limiter);


// Injection Attacks Rokne ke liye
app.use(mongoSanitize());
app.use(xss());


// Socket Setup
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
});

// ✅ 2. Use Variables from .env
const PORT = process.env.PORT || 5001;
const HOST = '0.0.0.0';
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/fixmate";
const JWT_SECRET = process.env.JWT_SECRET || "supersecret";

// 🟢 3. CLOUDINARY CONFIGURATION
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// 🟢 4. MULTER SETUP (Temp Storage)
if (!fs.existsSync('./uploads')){
    fs.mkdirSync('./uploads');
}
const upload = multer({ dest: 'uploads/' });

// 🟢 5. RAZORPAY CONFIGURATION
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// 👇 Email Credentials
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER, 
    pass: process.env.EMAIL_PASS ? process.env.EMAIL_PASS.replace(/\s+/g, '') : '',
  },
});

mongoose.connect(MONGODB_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("MongoDB Error:", err.message));

// --- HELPERS ---
const generateOtp = () => Math.floor(1000 + Math.random() * 9000).toString();
const signToken = (payload) => jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });
const verifyToken = (token) => { try { return jwt.verify(token, JWT_SECRET); } catch(e) { return null; } };

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "No token" });
  const token = authHeader.split(" ")[1];
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: "Invalid token" });
  req.user = payload;
  next();
};

// --- MODELS ---
const userSchema = new mongoose.Schema({
  fullName: String,
  email: { type: String, unique: true },
  phone: { type: String, required: true },
  role: { type: String, default: "user" }, 
  isBlocked: { type: Boolean, default: false },
  fcmToken: { type: String, default: null },
  otp: String,
  profilePhoto: { type: String, default: null },
  aadhaarFront: { type: String, default: null },
  aadhaarBack: { type: String, default: null },
  verificationStatus: { type: String, default: "new" }, 
  bankDetails: { accountNumber: String, ifsc: String, holderName: String },
   walletBalance: { type: Number, default: 0 }, 
  cashCollected: { type: Number, default: 0 },
  rating: { type: Number, default: 5.0 },
   isBlocked: { type: Boolean, default: false },

}, { timestamps: true });

const User = mongoose.model("User", userSchema);

const jobSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  type: String,
  status: { type: String, default: "requested" }, 
  location: { type: { type: String, default: "Point" }, coordinates: [Number] },
  details: String,
  price: { type: Number, default: 0 }, 
  paymentMethod: { type: String, default: "Cash" },
  completionOtp: String,
  rating: { type: Number, default: 0 }
}, { timestamps: true });


const categorySchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  icon: String, // Cloudinary image URL
  description: String,
  isActive: { type: Boolean, default: true }
}, { timestamps: true });

const Category = mongoose.model("Category", categorySchema);


jobSchema.index({ location: "2dsphere" });
const Job = mongoose.model("Job", jobSchema);

// 🟢 NEW BANNER MODEL
const bannerSchema = new mongoose.Schema({
  image: String,
  title: String,
  subtitle: String,
  isActive: { type: Boolean, default: true }
});
const Banner = mongoose.model("Banner", bannerSchema);


// --- 1. SUPPORT CHAT MODEL (New) ---
const supportSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  messages: [{
      sender: String, // 'user', 'admin', 'system'
      text: String,
      createdAt: { type: Date, default: Date.now }
  }],
  lastUpdated: { type: Date, default: Date.now }
}, { timestamps: true });

const Support = mongoose.model("Support", supportSchema);

// Har wallet transaction ka record rakhne ke liye
const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  amount: Number,
  type: { type: String, enum: ['credit', 'debit'] }, // credit = add, debit = deduct
  description: String,
  date: { type: Date, default: Date.now }
});
const Transaction = mongoose.model("Transaction", transactionSchema);


const withdrawalSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  amount: { type: Number, required: true },
  status: { type: String, default: "pending" }, // pending, approved, rejected
  date: { type: Date, default: Date.now }
}, { timestamps: true });
const Withdrawal = mongoose.model("Withdrawal", withdrawalSchema);


// --- 2. SUPPORT ROUTES (Add this in Routes Section) ---

// 🟢 USER: Send Message & Get Auto Reply
app.post("/api/support/send", authMiddleware, async (req, res) => {
    try {
        const { text } = req.body;
        const cleanText = validator.escape(text); // <--- Ye line add karein (XSS Protection)
// Database me 'cleanText' save karein.
        let chat = await Support.findOne({ userId: req.user.id });

        if (!chat) {
            chat = new Support({ userId: req.user.id, messages: [] });
        }

        // 1. User Message Save
        chat.messages.push({ sender: 'user', text });

        // 2. Auto Reply Logic (Bot)
        let autoReply = null;
        if (chat.messages.length === 1) {
            autoReply = "Hi! Welcome to FixMate Support. How can we help you?";
        } else if (text.toLowerCase().includes("refund")) {
            autoReply = "For refunds, please share your Job ID. Our team will check.";
        } else if (text.toLowerCase().includes("hello") || text.toLowerCase().includes("hi")) {
            autoReply = "Hello! An admin will be with you shortly.";
        }

        if (autoReply) {
            chat.messages.push({ sender: 'system', text: autoReply });
        }

        chat.lastUpdated = new Date();
        await chat.save();
        res.json({ success: true, chat });

    } catch (err) { res.status(500).json({ error: "Message Failed" }); }
});

// 🟢 USER: Get Chat History
app.get("/api/support/history", authMiddleware, async (req, res) => {
    try {
        const chat = await Support.findOne({ userId: req.user.id });
        res.json({ success: true, messages: chat ? chat.messages : [] });
    } catch (err) { res.status(500).json({ error: "Error" }); }
});

// 🟢 ADMIN: Get All Support Tickets
app.get("/api/admin/support-tickets", async (req, res) => {
    try {
        // 'role' field add kiya hai populate mein
        const tickets = await Support.find()
            .populate("userId", "fullName email role") 
            .sort({ lastUpdated: -1 });
        res.json({ success: true, tickets });
    } catch (err) { res.status(500).json({ error: "Error" }); }
});

// 🟢 ADMIN: Reply to User
app.post("/api/admin/support-reply", async (req, res) => {
    try {
        const { ticketId, text } = req.body;
        const chat = await Support.findById(ticketId);
        if (!chat) return res.status(404).json({ error: "Chat not found" });

        chat.messages.push({ sender: 'admin', text });
        chat.lastUpdated = new Date();
        await chat.save();

        res.json({ success: true, chat });
    } catch (err) { res.status(500).json({ error: "Reply Failed" }); }
});

app.post("/api/admin/toggle-block", async (req, res) => {
    try {
        const { userId, status } = req.body; // status: true/false
        // Logic: seedha findByIdAndUpdate use karenge
        const user = await User.findByIdAndUpdate(userId, { isBlocked: status }, { new: true });
        
        if (!user) return res.status(404).json({ success: false, error: "User nahi mila" });

        res.json({ success: true, message: status ? "Blocked" : "Unblocked", user });
    } catch (err) {
        res.status(500).json({ success: false, error: "Server Error" });
    }
});


// Admin routes ke paas ye add karein
app.post("/api/admin/update-wallet", async (req, res) => {
    try {
        const { userId, amount, actionType } = req.body;
        const user = await User.findById(userId);
        
        let transType = actionType === 'add' ? 'credit' : 'debit';
        let desc = actionType === 'add' ? "Recharge by Admin" : "Payout by Admin";

        if (actionType === 'add') user.walletBalance += Number(amount);
        else user.walletBalance -= Number(amount);

        await user.save();

        // 🟢 History save karein
        await Transaction.create({ userId, amount, type: transType, description: desc });

        res.json({ success: true, newBalance: user.walletBalance });
    } catch (err) { res.status(500).json({ error: "Failed" }); }
});



// server.js mein Admin Routes ke paas add karein
app.get("/api/admin/all-jobs", async (req, res) => {
    try {
        // Hum userId aur partnerId ko populate karenge taaki unka naam dikh sake
        const jobs = await Job.find()
            .populate("userId", "fullName phone")
            .populate("partnerId", "fullName phone partnerType")
            .sort({ createdAt: -1 }); // Nayi bookings sabse upar
        res.json({ success: true, jobs });
    } catch (err) { 
        res.status(500).json({ error: "Failed to fetch jobs" });  } 
});


app.get("/api/admin/transactions/:userId", async (req, res) => {
    try {
        const history = await Transaction.find({ userId: req.params.userId }).sort({ date: -1 });
        res.json({ success: true, history });
    } catch (err) { res.status(500).json({ error: "Failed" }); }
});


app.post("/api/admin/send-notification", async (req, res) => {
    try {
        const { title, body, target } = req.body; // target: 'all', 'user', 'partner'
        
        let query = {};
        if (target !== 'all') query.role = target;

        // Sirf unhe dhoondo jinke paas fcmToken hai
        const users = await User.find(query).select("fcmToken");
        const tokens = users.map(u => u.fcmToken).filter(t => t != null);

        if (tokens.length === 0) {
            return res.json({ success: false, message: "Kisi bhi device par token nahi mila." });
        }

        const message = {
            notification: { title, body },
            tokens: tokens,
        };

        // Bulk notification send
        const response = await admin.messaging().sendEachForMulticast(message);
        
        res.json({ 
            success: true, 
            sentCount: response.successCount, 
            failureCount: response.failureCount 
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Notification bhejte waqt error aaya" });
    }
});



// server.js mein Admin Routes ke paas add karein
app.get("/api/admin/analytics", async (req, res) => {
    try {
        const last7Days = new Date();
        last7Days.setDate(last7Days.getDate() - 7);

        // 1. Revenue Analytics (Pichle 7 din ki kamayi)
        const revenueData = await Job.aggregate([
            { $match: { status: "completed", createdAt: { $gte: last7Days } } },
            {
                $group: {
                    _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
                    dailyRevenue: { $sum: { $multiply: ["$price", 0.20] } } // 20% commission
                }
            },
            { $sort: { "_id": 1 } }
        ]);

        // 2. Job Status Breakdown (Kitne complete, kitne cancel, etc.)
        const jobStats = await Job.aggregate([
            { $group: { _id: "$status", count: { $sum: 1 } } }
        ]);

        res.json({ success: true, revenueData, jobStats });
    } catch (err) { 
        res.status(500).json({ error: "Analytics fetch failed" }); 
    }
});


// server.js mein Admin Routes mein add karein
app.get("/api/admin/reviews", async (req, res) => {
    try {
        // Sirf wo jobs nikalenge jisme rating di gayi ho (> 0)
        const reviews = await Job.find({ rating: { $gt: 0 } })
            .populate("userId", "fullName")
            .populate("partnerId", "fullName partnerType")
            .sort({ updatedAt: -1 });
        res.json({ success: true, reviews });
    } catch (err) { res.status(500).json({ error: "Reviews load failed" }); }
});



// Saari categories lene ke liye
app.get("/api/admin/categories", async (req, res) => {
    try {
        const cats = await Category.find().sort({ createdAt: -1 });
        res.json({ success: true, categories: cats });
    } catch (err) { res.status(500).json({ error: "Failed to fetch categories" }); }
});

// Nayi category add karne ke liye
app.post("/api/admin/add-category", async (req, res) => {
    try {
        const { name, icon, description } = req.body;
        const cat = await Category.create({ name, icon, description });
        res.json({ success: true, category: cat });
    } catch (err) { res.status(500).json({ error: "Failed to add category" }); }
});

// Category delete karne ke liye
app.delete("/api/admin/category/:id", async (req, res) => {
    try {
        await Category.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: "Delete failed" }); }
});



// 1. Delete Account ke liye OTP bhejna
app.post("/api/user/request-delete-otp", authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ error: "User not found" });

        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        user.otp = otp; // Purana OTP field reuse kar rahe hain
        await user.save();

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: "FixMate - Account Deletion OTP",
            text: `Your OTP for account deletion is: ${otp}. Warning: This will permanently remove your account data.`
        };

        await transporter.sendMail(mailOptions);
        res.json({ success: true, message: "OTP sent to your email" });
    } catch (err) {
        res.status(500).json({ error: "Failed to send OTP" });
    }
});

// 2. OTP Verify karke account delete karna
app.post("/api/user/confirm-delete", authMiddleware, async (req, res) => {
    try {
        const { otp } = req.body;
        const user = await User.findById(req.user.id);

        if (!user || user.otp !== otp) {
            return res.status(400).json({ error: "Invalid OTP" });
        }

        // Sab sahi hai, toh delete kardo
        await User.findByIdAndDelete(req.user.id);
        res.json({ success: true, message: "Account deleted" });
    } catch (err) {
        res.status(500).json({ error: "Deletion failed" });
    }
});



// 1. Partner payout request bheje
app.post("/api/withdraw/request", authMiddleware, async (req, res) => {
    try {
        const { amount } = req.body;
        const user = await User.findById(req.user.id);
        if (user.walletBalance < amount) return res.status(400).json({ error: "Balance kam hai!" });
        if (amount < 100) return res.status(400).json({ error: "Minimum ₹100 nikal sakte hain." });

        await Withdrawal.create({ userId: req.user.id, amount });
        res.json({ success: true, message: "Request sent to Admin" });
    } catch (err) { res.status(500).send("Error"); }
});

// 2. Admin saari requests dekhe
app.get("/api/admin/withdrawals", async (req, res) => {
    try {
        const list = await Withdrawal.find().populate("userId", "fullName phone walletBalance bankDetails").sort({ createdAt: -1 });
        res.json({ success: true, withdrawals: list });
    } catch (err) { res.status(500).send("Error"); }
});

// 3. Admin Approve ya Reject kare
app.post("/api/admin/withdraw/action", async (req, res) => {
    try {
        const { reqId, status } = req.body;
        const draw = await Withdrawal.findById(reqId);
        if (status === 'approved') {
            const user = await User.findById(draw.userId);
            user.walletBalance -= draw.amount; // Balance deduct karo
            await user.save();
        }
        draw.status = status;
        await draw.save();
        res.json({ success: true });
    } catch (err) { res.status(500).send("Error"); }
});



// 🟢 Partner ki payout history fetch karne ka route
app.get("/api/withdraw/history", authMiddleware, async (req, res) => {
    try {
        const list = await Withdrawal.find({ userId: req.user.id }).sort({ createdAt: -1 });
        res.json({ success: true, withdrawals: list });
    } catch (err) {
        res.status(500).json({ error: "History fetch failed" });
    }
});


// server.js mein Admin Routes ke paas add karein
app.post("/api/admin/cancel-job", async (req, res) => {
    try {
        const { jobId } = req.body;
        const job = await Job.findById(jobId);

        if (!job) return res.status(404).json({ error: "Job not found" });
        if (job.status === 'completed' || job.status === 'cancelled') {
            return res.status(400).json({ error: "Is job ko cancel nahi kiya ja sakta." });
        }

        job.status = 'cancelled';
        await job.save();

        // 📡 Socket: Customer aur Partner ko turant batao
        if (job.userId) io.to(String(job.userId)).emit("jobTimeout", { message: "Admin has cancelled this booking." });
        if (job.partnerId) io.to(String(job.partnerId)).emit("jobCancelled", { message: "Admin has cancelled this booking." });

        res.json({ success: true, message: "Job cancelled by Admin" });
    } catch (err) {
        res.status(500).json({ error: "Failed to cancel job" });
    }
});



// --- ROUTES ---

app.get("/", (req, res) => res.send("FixMate Backend Running"));

// 🟢 RAZORPAY
app.post("/api/payment/order", authMiddleware, async (req, res) => {
    try {
        const { amount } = req.body;
        const options = { amount: amount * 100, currency: "INR", receipt: "receipt_" + Date.now() };
        const order = await razorpay.orders.create(options);
        res.json({ success: true, order });
    } catch (err) { res.status(500).json({ error: "Payment Order Failed" }); }
});

app.post("/api/payment/verify", authMiddleware, async (req, res) => {
    try {
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
        const sign = razorpay_order_id + "|" + razorpay_payment_id;
        const expectedSign = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET).update(sign.toString()).digest("hex");
        if (razorpay_signature === expectedSign) res.json({ success: true, message: "Verified" });
        else res.status(400).json({ error: "Invalid Signature" });
    } catch (err) { res.status(500).json({ error: "Verification Error" }); }
});

// 🟢 IMAGE UPLOAD
app.post("/api/upload", upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file" });
    const result = await cloudinary.uploader.upload(req.file.path, { folder: "fixmate_uploads" });
    if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.json({ success: true, url: result.secure_url });
  } catch (err) { 
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      res.status(500).json({ error: "Upload failed" }); 
  }
});

// 🟢 BANNER ROUTES (Admin + User)
app.get("/api/banners", async (req, res) => {
    try { const banners = await Banner.find({ isActive: true }).sort({ _id: -1 }); res.json({ success: true, banners }); } 
    catch (err) { res.status(500).json({ error: "Error" }); }
});

app.get("/api/admin/banners", async (req, res) => {
    try { const banners = await Banner.find().sort({ _id: -1 }); res.json({ success: true, banners }); } 
    catch (err) { res.status(500).json({ error: "Error" }); }
});

app.post("/api/admin/add-banner", upload.single('image'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: "Image required" });
        const result = await cloudinary.uploader.upload(req.file.path, { folder: "fixmate_banners" });
        if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        const banner = await Banner.create({ image: result.secure_url, title: req.body.title, subtitle: req.body.subtitle });
        res.json({ success: true, message: "Banner Added", banner });
    } catch (err) { res.status(500).json({ error: "Upload Failed" }); }
});

app.delete("/api/admin/banner/:id", async (req, res) => {
    try { await Banner.findByIdAndDelete(req.params.id); res.json({ success: true }); } 
    catch (err) { res.status(500).json({ error: "Delete Failed" }); }
});

// 1. Send OTP (Role Check)
app.post("/api/send-otp", async (req, res) => {
  try {
    const { email, fullName, phone, role, partnerType, isSignup } = req.body;

    // 🟢 1. Pehle Email ko Normalize (Clean) karein
    if (!email) return res.status(400).json({ error: "Email is required" });
    const cleanEmail = validator.normalizeEmail(email);

    // 🟢 2. Ab CleanEmail se Database mein dhoondo
    let user = await User.findOne({ email: cleanEmail });

    // Role mismatch check (Jo aapne likha tha)
    if (user) {
        if (role === 'partner' && user.role === 'user') {
            return res.status(400).json({ error: "Registered as Customer. Use User App." });
        }
        if (role === 'user' && user.role === 'partner') {
            return res.status(400).json({ error: "Registered as Partner. Use Partner App." });
        }
    }

    // 🟢 3. Signup vs Login Logic
    if (isSignup) {
      if (user) return res.status(400).json({ error: "User already exists, please login." });
      
      // Naya user banate waqt cleanEmail aur partnerType (agar hai) save karein
      user = await User.create({ 
          email: cleanEmail, 
          fullName, 
          phone, 
          role: role || "user", 
          partnerType: partnerType || null, // Mechanic ya Helper save karne ke liye
          otp: generateOtp() 
      });
    } else {
      if (!user) return res.status(400).json({ error: "User not found. Please register first." });
      
      // Purane user ke liye naya OTP generate karein
      user.otp = generateOtp();
      await user.save();
    }

    // 🟢 4. Email hamesha cleanEmail par bhejein
    const mailOptions = { 
        from: process.env.EMAIL_USER, 
        to: cleanEmail, 
        subject: "FixMate - Your OTP", 
        text: `Your OTP for FixMate is: ${user.otp}` 
    };

    try { 
        await transporter.sendMail(mailOptions); 
        console.log(`✅ OTP for ${cleanEmail}: ${user.otp}`);
    } catch (e) { 
        console.error("❌ Email sending failed:", e); 
    }

    res.json({ success: true, message: `OTP sent to ${cleanEmail}` });

  } catch (err) { 
      console.error("❌ Server Error:", err);
      res.status(500).json({ error: "Server error. Please try again later." }); 
  }
});
// 2. Verify OTP
app.post("/api/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    const user = await User.findOne({ email });
    if (!user || user.otp !== otp) return res.status(400).json({ error: "Invalid OTP" });
    user.otp = null; await user.save();
    const token = signToken({ id: user._id, email: user.email, role: user.role });
    res.json({ success: true, token, user });
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

// 3. Partner Profile
app.get("/api/partner/profile", authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        const history = await Job.find({ partnerId: req.user.id, status: "completed" }).sort({ createdAt: -1 });
        res.json({ success: true, data: { ...user.toObject(), history } });
    } catch (err) { res.status(500).json({ error: "Error" }); }
});

app.post("/api/partner/update-profile", authMiddleware, async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.user.id, req.body, { new: true });
        if (user.profilePhoto && user.aadhaarFront && user.bankDetails?.accountNumber) user.verificationStatus = 'pending';
        await user.save();
        res.json({ success: true, user });
    } catch (err) { res.status(500).json({ error: "Error" }); }
});

// 4. Jobs
app.get("/api/user/jobs", authMiddleware, async (req, res) => {
    try { const jobs = await Job.find({ userId: req.user.id }).sort({ createdAt: -1 }).populate("partnerId"); res.json({ success: true, jobs }); } 
    
    catch (err) { res.status(500).json({ error: "Error" }); }
});

app.post("/api/jobs", authMiddleware, async (req, res) => {
    try {
      const { type, lat, lng, details, price, paymentMethod } = req.body; 
      const job = await Job.create({ userId: req.user.id, type, location: { type: "Point", coordinates: [lng, lat] }, details, price, paymentMethod });
      
      io.emit("newJobAvailable", { jobId: job._id, userId: req.user.id, type, location: { lat, lng }, details, price, paymentMethod });
      
      setTimeout(async () => {
          const currentJob = await Job.findById(job._id);
          if (currentJob && currentJob.status === 'requested') {
              currentJob.status = 'cancelled'; await currentJob.save();
              io.to(String(job.userId)).emit("jobTimeout", { message: "No mechanics found." });
          }
      }, 300000); 
      res.json({ success: true, job });
    } catch (err) { res.status(500).json({ error: "Error" }); }
});

// 🟢 1. Job Accept Logic (Blocked Partner check ke saath)
app.post("/api/jobs/accept", authMiddleware, async (req, res) => {
    try {
      const { jobId } = req.body;
      const partner = await User.findById(req.user.id);

      // 🔴 BLOCK CHECK: Agar partner blocked hai toh error bhej do
      if (partner && partner.isBlocked) {
          return res.status(403).json({ error: "Partner blocked by admin plzz topup your wallet to unblock" });
      }

      const job = await Job.findById(jobId);
      if (!job || job.status !== 'requested') return res.status(400).json({ error: "Unavailable" });

      job.partnerId = req.user.id; 
      job.status = "accepted"; 
      await job.save();

      io.to(String(job.userId)).emit("jobAccepted", { jobId: job._id, partnerId: req.user.id, partnerName: partner.fullName });
      res.json({ success: true, job });
    } catch (err) { res.status(500).json({ error: "Error" }); }
});

// 🟢 2. Request Completion Logic (Blocked Partner check ke saath)
app.post("/api/jobs/request-completion", authMiddleware, async (req, res) => {
    try {
        const { jobId } = req.body;
        const partner = await User.findById(req.user.id);

        // 🔴 BLOCK CHECK: Agar partner kaam ke beech mein block ho jaye
        if (partner && partner.isBlocked) {
            return res.status(403).json({ error: "Partner blocked by admin plzz topup your wallet to unblock" });
        }

        const job = await Job.findById(jobId);
        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        job.completionOtp = otp; await job.save();
        io.to(String(job.userId)).emit("showCompletionOtp", { otp });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: "Error" }); }
});

// 🟢 3. Final Completion Logic (Blocked Partner check ke saath)
app.post("/api/jobs/complete", authMiddleware, async (req, res) => {
    try {
      const { jobId, otp } = req.body;
      const partner = await User.findById(req.user.id);

      // 🔴 BLOCK CHECK
      if (partner && partner.isBlocked) {
          return res.status(403).json({ error: "Partner blocked by admin plzz topup your wallet to unblock" });
      }

      const job = await Job.findById(jobId);
      if (job.completionOtp !== otp) return res.status(400).json({ error: "Invalid OTP" });
      
      job.status = "completed"; 
      job.completionOtp = null; 
      await job.save();
      
      const commission = (job.price || 0) * 0.20;
      if (job.paymentMethod === 'Cash') { 
          partner.cashCollected += job.price; 
          partner.walletBalance -= commission; 
      } 
      else { 
          partner.walletBalance += (job.price - commission); 
      }
      await partner.save();

      io.to(String(job.userId)).emit("jobFinished", { message: "Done" });
      res.json({ success: true, walletBalance: partner.walletBalance, cashCollected: partner.cashCollected });
    } catch (err) { res.status(500).json({ error: "Error" }); }
});
// 🟢 CANCEL JOB ON LOGOUT
app.post("/api/user/cancel-job", authMiddleware, async (req, res) => {
    try {
        const job = await Job.findOne({ userId: req.user.id, status: { $in: ['requested', 'accepted'] } });
        if (job) {
            job.status = 'cancelled'; await job.save();
            if (job.partnerId) io.to(String(job.partnerId)).emit("jobCancelled", { message: "User cancelled" });
            return res.json({ success: true });
        }
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: "Error" }); }
});

// 🟢 ADMIN ROUTES
app.get("/api/admin/stats", async (req, res) => {
    try {
        const totalUsers = await User.countDocuments({ role: 'user' });
        const totalPartners = await User.countDocuments({ role: 'partner' });
        const activeJobs = await Job.countDocuments({ status: { $in: ['requested', 'accepted'] } });
        const completed = await Job.find({ status: 'completed' });
        const totalRevenue = completed.reduce((acc, job) => acc + (job.price * 0.20), 0);
        res.json({ success: true, stats: { totalUsers, totalPartners, activeJobs, totalRevenue } });
    } catch (err) { res.status(500).json({ error: "Error" }); }
});

app.get("/api/admin/all-jobs", async (req, res) => {
    try {
        const jobs = await Job.find()
            .populate("userId", "fullName phone") // Customer ka naam aur phone
            .populate("partnerId", "fullName phone partnerType") // Partner ki details
            .sort({ createdAt: -1 }); // Nayi booking sabse upar
        res.json({ success: true, jobs });
    } catch (err) { 
        res.status(500).json({ error: "Booking fetch failed" }); 
    }}),

app.get("/api/admin/users", async (req, res) => {
    try { const users = await User.find(req.query.role ? { role: req.query.role } : {}).sort({ createdAt: -1 }); res.json({ success: true, users }); } 
    catch (err) { res.status(500).json({ error: "Error" }); }
});

app.get("/api/admin/pending-partners", async (req, res) => {
    try { const users = await User.find({ role: 'partner', verificationStatus: 'pending' }); res.json({ success: true, users }); } 
    catch (err) { res.status(500).json({ error: "Error" }); }
});

app.post("/api/admin/verify-user", async (req, res) => {
    try { await User.findByIdAndUpdate(req.body.userId, { verificationStatus: req.body.action }); res.json({ success: true }); } 
    catch (err) { res.status(500).json({ error: "Error" }); }
});

// SOCKET
io.on("connection", (socket) => {
  socket.on("register", (data) => {
    const user = verifyToken(data.token);
    if (user) socket.join(String(user.id));
  });
  socket.on("sendLocation", (data) => { if (data.userId) io.to(data.userId).emit("partnerLocationUpdate", data); });
  socket.on("sendMessage", (data) => { io.to(data.targetId).emit("receiveMessage", data); });
});


// 🟢 FINAL LISTENER SETTINGS (Phone/Emulator connect karne ke liye)
server.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📱 For Emulator/Phone, use your IP instead of localhost`);
});