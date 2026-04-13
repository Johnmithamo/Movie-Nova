// server.js - Part 1
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
require('dotenv').config();
const nodemailer = require('nodemailer');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' })); // Increased limit for base64 uploads

// ---------------------
// Email Transporter
// ---------------------
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS // use App Password
  }
});

// ---------------------
// OTP Store (temporary)
// ---------------------
const otpStore = {}; // { email: { otp, expires } }

// ---------------------
// Cloudinary Config
// ---------------------
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// ---------------------
// MongoDB Connection
// ---------------------
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB connected'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// ---------------------
// User Model
// ---------------------
const { Schema, model } = mongoose;

const userSchema = new Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },
  role: { type: String, default: 'user' },
  profilePic: { type: String, default: "" },
  phone: { type: String, default: "" },
  avatar: { type: String, default: "" },
  notifications: {
    email: { type: Boolean, default: true },
    push: { type: Boolean, default: true },
  },
  payments: [
    {
      cardNumber: String,
      expiry: String,
      default: Boolean,
    },
  ],
});

userSchema.methods.validatePassword = function(password) {
  return bcrypt.compare(password, this.passwordHash);
};

const User = model('User', userSchema);

// ---------------------
// JWT Middleware
// ---------------------
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing token' });

  const token = authHeader.split(' ')[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};
// server.js - Part 2

// ---------------------
// Auth Routes
// ---------------------
app.post('/signup', async (req, res) => {
  const { username, email, password, role } = req.body;

  if (!username || !email || !password)
    return res.status(400).json({ error: 'All fields are required' });

  try {
    const passwordHash = await bcrypt.hash(password, 10);

    const user = await User.create({
      username,
      email,
      passwordHash,
      role: role || "user"
    });

    // 🔥 CREATE TOKEN (MISSING BEFORE)
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      message: "User created",
      token,            // 🔥 ADD THIS
      role: user.role,
      userId: user._id
    });

  } catch (err) {
    console.error("🔥 FULL ERROR:", err);

    if (err.code === 11000) {
      const field = Object.keys(err.keyPattern)[0];
      return res.status(400).json({ error: `${field} already exists` });
    }

    if (err.name === "ValidationError") {
      return res.status(400).json({
        error: Object.values(err.errors).map(e => e.message).join(", ")
      });
    }

    if (err.name === "MongoNetworkError") {
      return res.status(500).json({ error: "Database connection issue" });
    }

    res.status(500).json({ error: err.message });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password required' });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await user.validatePassword(password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------------------
// Send OTP
// ---------------------
app.post('/auth/send-otp', async (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ error: 'Email is required' });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const otp = Math.floor(100000 + Math.random() * 900000);
    otpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000 }; // 5 min expiry

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP Code',
      text: `Your OTP is: ${otp}`
    });

    res.json({ message: 'OTP sent to email' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// ---------------------
// Verify OTP
// ---------------------
app.post('/auth/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  const record = otpStore[email];

  if (!record) return res.status(400).json({ error: 'No OTP found' });
  if (Date.now() > record.expires) return res.status(400).json({ error: 'OTP expired' });
  if (parseInt(otp) !== record.otp) return res.status(400).json({ error: 'Invalid OTP' });

  res.json({ message: 'OTP verified' });
});

// ---------------------
// Reset Password
// ---------------------
app.post('/auth/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  const record = otpStore[email];

  if (!record) return res.status(400).json({ error: 'No OTP found' });
  if (Date.now() > record.expires) return res.status(400).json({ error: 'OTP expired' });
  if (parseInt(otp) !== record.otp) return res.status(400).json({ error: 'Invalid OTP' });

  try {
    const user = await User.findOne({ email });
    const hash = await bcrypt.hash(newPassword, 10);
    user.passwordHash = hash;
    await user.save();

    delete otpStore[email]; // cleanup
    res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Reset failed' });
  }
});

// ---------------------
// Video Route
// ---------------------
app.get('/videos', async (req, res) => {
  try {
    const result = await cloudinary.api.resources({
      type: 'upload',
      resource_type: 'video',
      max_results: 50
    });

    const videos = result.resources.map(v => ({
      public_id: v.public_id,
      format: v.format,
      duration: v.duration,
      url: v.secure_url,
      created_at: v.created_at,
      bytes: v.bytes,
      width: v.width,
      height: v.height
    }));

    res.json({ count: videos.length, videos });
  } catch (err) {
    console.error('❌ Error fetching videos:', err);
    res.status(500).json({ error: 'Failed to fetch video metadata' });
  }
});

// ---------------------
// Profile Schema
// ---------------------
const profileSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', unique: true },
  fullName: String,
  email: String,
  location: String,
  skills: String,
  experience: String,
  portfolio: String,
  photoUrl: String,
  completed: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});
const Profile = model('Profile', profileSchema);
// server.js - Part 3

// ---------------------
// Create or Update Profile
// ---------------------
app.post('/profile/setup', authenticate, async (req, res) => {
  try {
    const {
      fullName,
      email,
      location,
      skills,
      experience,
      portfolio,
      photo // base64 image
    } = req.body;

    let photoUrl = null;

    if (photo) {
      const upload = await cloudinary.uploader.upload(photo, { folder: 'profile_photos' });
      photoUrl = upload.secure_url;
    }

    const profile = await Profile.findOneAndUpdate(
      { userId: req.user.userId },
      { fullName, email, location, skills, experience, portfolio, photoUrl, completed: true },
      { new: true, upsert: true }
    );

    res.json({ message: 'Profile saved successfully', profile });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: 'Failed to save profile',
      details: err.message
    });
  }
});

// ---------------------
// Get Profile
// ---------------------
app.get('/profile', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.user.userId });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });
    res.json({ profile });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// ---------------------
// Update Profile Field
// ---------------------
app.put('/profile/update', authenticate, async (req, res) => {
  try {
    const updates = req.body;
    const profile = await Profile.findOneAndUpdate(
      { userId: req.user.userId },
      updates,
      { new: true, upsert: true }
    );
    res.json({ profile });
  } catch (err) {
    res.status(500).json({ error: 'Update failed' });
  }
});

// ---------------------
// Delete Profile
// ---------------------
app.delete('/profile', authenticate, async (req, res) => {
  try {
    await Profile.findOneAndDelete({ userId: req.user.userId });
    res.json({ message: 'Profile deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete profile' });
  }
});

// ---------------------
// Get Seller Profile
// ---------------------
app.get('/seller/:id', async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.params.id });
    if (!profile) return res.status(404).json({ error: 'Seller not found' });
    res.json({ profile });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch seller' });
  }
});

// ---------------------
// Service Schema
// ---------------------
const serviceSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User' },
  title: String,
  price: Number,
  image: String,
  category: String, // Web, App, AI, Data
  orders: { type: Number, default: 0 },
  rating: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  active: { type: Boolean, default: true }
});

const Service = model('Service', serviceSchema);

// ---------------------
// Get Seller Services
// ---------------------
app.get('/seller/:id/services', async (req, res) => {
  try {
    const services = await Service.find({ userId: req.params.id });
    res.json({ services });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch services' });
  }
});

// ---------------------
// Create Service
// ---------------------
app.post('/services', authenticate, async (req, res) => {
  try {
    const { title, price, category } = req.body;
    let image = req.body.image; // Frontend should send base64 or temporary URL

    let imageUrl = null;

    if (image) {
      // Upload to Cloudinary
      const uploadResult = await cloudinary.uploader.upload(image, {
        folder: "services", // optional folder
      });
      imageUrl = uploadResult.secure_url;
    }

    const service = await Service.create({
      userId: req.user.userId,
      title,
      price,
      category,
      image: imageUrl
    });

    res.json({ service });
  } catch (err) {
    console.error("Create service error:", err);
    res.status(500).json({ error: 'Failed to create service' });
  }
});
// server.js - Part 4

// ---------------------
// Review Schema
// ---------------------
const reviewSchema = new Schema({
  sellerId: { type: Schema.Types.ObjectId, ref: 'User' },
  userId: { type: Schema.Types.ObjectId, ref: 'User' },
  rating: Number,
  comment: String,
  createdAt: { type: Date, default: Date.now }
});

const Review = model('Review', reviewSchema);

// ---------------------
// Get Seller Reviews
// ---------------------
app.get('/seller/:id/reviews', async (req, res) => {
  try {
    const reviews = await Review.find({ sellerId: req.params.id });
    const avgRating = reviews.reduce((acc, r) => acc + r.rating, 0) / (reviews.length || 1);

    res.json({
      reviews,
      average: avgRating.toFixed(1),
      total: reviews.length
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch reviews' });
  }
});

// ---------------------
// Order Schema
// ---------------------
const orderSchema = new Schema({
  buyerId: { type: Schema.Types.ObjectId, ref: 'User' },
  sellerId: { type: Schema.Types.ObjectId, ref: 'User' },
  serviceId: { type: Schema.Types.ObjectId, ref: 'Service' },
  price: Number,
  status: { type: String, default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const Order = model('Order', orderSchema);

// ---------------------
// Hire Seller / Create Order
// ---------------------
app.post('/orders', authenticate, async (req, res) => {
  try {
    const { sellerId, serviceId } = req.body;
    const service = await Service.findById(serviceId);
    if (!service) return res.status(404).json({ error: 'Service not found' });

    const order = await Order.create({
      buyerId: req.user.userId,
      sellerId,
      serviceId,
      price: service.price
    });

    // Increment service order count
    service.orders = (service.orders || 0) + 1;
    await service.save();

    res.json({ message: 'Order created', order });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// ---------------------
// Seller Dashboard Stats
// ---------------------
app.get('/seller/dashboard', authenticate, async (req, res) => {
  try {
    const sellerId = req.user.userId;
    const orders = await Order.find({ sellerId });

    const totalOrders = orders.length;
    const totalSales = orders.reduce((sum, order) => sum + (order.price || 0), 0);

    res.json({ totalOrders, totalSales });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load dashboard' });
  }
});

// ---------------------
// Get My Services
// ---------------------
app.get('/my/services', authenticate, async (req, res) => {
  const services = await Service.find({ userId: req.user.userId });
  res.json({ services });
});

// ---------------------
// Get Seller Orders
// ---------------------
app.get('/my/orders', authenticate, async (req, res) => {
  const orders = await Order.find({ sellerId: req.user.userId });
  res.json({ orders });
});

// ---------------------
// Update Order Status
// ---------------------
app.put('/orders/:id', authenticate, async (req, res) => {
  try {
    const { status } = req.body;
    const order = await Order.findByIdAndUpdate(req.params.id, { status }, { new: true });
    res.json({ order });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update order' });
  }
});

// ---------------------
// Toggle Service Status
// ---------------------
app.put('/services/:id/toggle', authenticate, async (req, res) => {
  try {
    const service = await Service.findById(req.params.id);
    if (!service) return res.status(404).json({ error: 'Service not found' });

    service.active = !service.active;
    await service.save();
    res.json({ service });
  } catch (err) {
    res.status(500).json({ error: 'Failed to toggle service' });
  }
});

// ---------------------
// Seller Earnings
// ---------------------
app.get('/my/earnings', authenticate, async (req, res) => {
  try {
    const orders = await Order.find({ sellerId: req.user.userId, status: 'completed' });
    const transactions = orders.map(o => ({ amount: o.price, date: o.createdAt }));
    const total = transactions.reduce((sum, t) => sum + (t.amount || 0), 0);

    res.json({ total, transactions });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch earnings' });
  }
});

// ---------------------
// Get All Services (Feed)
// ---------------------
app.get('/services', async (req, res) => {
  try {
    const { category, search } = req.query;
    let filter = {};

    if (category && category !== 'All') filter.category = category;
    if (search) filter.title = { $regex: search, $options: 'i' };

    const services = await Service.find(filter).sort({ createdAt: -1 }).limit(20);
    res.json({ services });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch services' });
  }
});

// ---------------------
// Top Services
// ---------------------
app.get('/services/top', async (req, res) => {
  try {
    const services = await Service.find().sort({ orders: -1 }).limit(10);
    res.json({ services });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch top services' });
  }
});

// ---------------------
// Search Services
// ---------------------
app.get('/services/search', async (req, res) => {
  try {
    const { q } = req.query;
    const services = await Service.find({ title: { $regex: q, $options: 'i' } });
    res.json({ services });
  } catch (err) {
    res.status(500).json({ error: 'Failed to search services' });
  }
});

// ---------------------
// Get Single Service
// ---------------------
app.get('/services/:id', async (req, res) => {
  try {
    const service = await Service.findById(req.params.id).populate('userId', 'username profilePic');
    if (!service) return res.status(404).json({ error: 'Service not found' });
    res.json({ service });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch service' });
  }
});
// server.js - Part 
// ---------------------
// User Profile Endpoints
// ---------------------
app.get('/user/profile', authenticate, async (req, res) => {
  const user = await User.findById(req.user.userId).select('-passwordHash');
  res.json(user);
});

app.put('/user/profile', authenticate, async (req, res) => {
  const { username, email, phone, profilePic } = req.body;
  const user = await User.findById(req.user.userId);

  if (username) user.username = username;
  if (email) user.email = email;
  if (phone) user.phone = phone;
  if (profilePic) user.profilePic = profilePic;

  await user.save();
  res.json({ message: 'Profile updated', user });
});

// ---------------------
// Notifications Endpoints
// ---------------------
app.get('/user/notifications', authenticate, async (req, res) => {
  const user = await User.findById(req.user.userId);
  res.json(user.notifications);
});

app.put('/user/notifications', authenticate, async (req, res) => {
  const { email, push } = req.body;
  const user = await User.findById(req.user.userId);

  if (email !== undefined) user.notifications.email = email;
  if (push !== undefined) user.notifications.push = push;

  await user.save();
  res.json({ message: 'Notifications updated', notifications: user.notifications });
});

// ---------------------
// Payments Endpoint
// ---------------------
app.get('/user/payments', authenticate, async (req, res) => {
  const user = await User.findById(req.user.userId);
  res.json(user.payments);
});

// ---------------------
// Help / FAQ Endpoint
// ---------------------
app.get('/help/faq', (req, res) => {
  res.json([
    { question: "How do I reset my password?", answer: "Go to Settings > Privacy" },
    { question: "How do I contact support?", answer: "Use the Help & Support page" },
  ]);
});

// ---------------------
// Chat & Message Models
// ---------------------
const messageSchema = new Schema({
  sender: { type: Schema.Types.ObjectId, ref: "User", required: true },
  text: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const chatSchema = new Schema({
  participants: [{ type: Schema.Types.ObjectId, ref: "User" }],
  messages: [messageSchema],
  lastMessage: { type: String },
  unread: { type: Map, of: Number }, // userId -> unread count
  updatedAt: { type: Date, default: Date.now }
});

const Chat = mongoose.model("Chat", chatSchema);
// server.js - Part 6

// ---------------------
// Chat Endpoints
// ---------------------

// Get all chats for logged-in user
app.get("/chats", authenticate, async (req, res) => {
  try {
    const chats = await Chat.find({ participants: req.user.userId })
      .populate("participants", "username profilePic")
      .sort({ updatedAt: -1 });

    const formatted = chats.map(chat => ({
      _id: chat._id,
      name: chat.participants
        .filter(p => p._id.toString() !== req.user.userId)
        .map(p => p.username)
        .join(", "),
      avatar: chat.participants.find(p => p._id.toString() !== req.user.userId)?.profilePic || "",
      lastMessage: chat.lastMessage,
      time: chat.updatedAt,
      unread: chat.unread.get(req.user.userId) || 0,
      online: true // optional: track online status separately
    }));

    res.json(formatted);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch chats" });
  }
});

// Get messages for a specific chat
app.get("/chats/:chatId/messages", authenticate, async (req, res) => {
  try {
    const chat = await Chat.findById(req.params.chatId).populate("messages.sender", "username profilePic");
    if (!chat) return res.status(404).json({ error: "Chat not found" });

    // Mark messages as read for current user
    chat.unread.set(req.user.userId, 0);
    await chat.save();

    const messages = chat.messages.map(m => ({
      text: m.text,
      sender: m.sender._id.toString() === req.user.userId ? "me" : "them",
      createdAt: m.createdAt
    }));

    res.json(messages);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch messages" });
  }
});

// Send a new message in a chat
app.post("/chats/:chatId/messages", authenticate, async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: "Message text is required" });

  try {
    const chat = await Chat.findById(req.params.chatId);
    if (!chat) return res.status(404).json({ error: "Chat not found" });

    const message = { sender: req.user.userId, text };
    chat.messages.push(message);
    chat.lastMessage = text;

    // Increment unread count for other participants
    chat.participants.forEach(p => {
      if (p.toString() !== req.user.userId) {
        chat.unread.set(p.toString(), (chat.unread.get(p.toString()) || 0) + 1);
      }
    });

    chat.updatedAt = new Date();
    await chat.save();

    res.json({ message: "Message sent" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to send message" });
  }
});

// Mark chat as read
app.post("/chats/:chatId/read", authenticate, async (req, res) => {
  try {
    const chat = await Chat.findById(req.params.chatId);
    if (!chat) return res.status(404).json({ error: "Chat not found" });

    chat.unread.set(req.user.userId, 0);
    await chat.save();

    res.json({ message: "Chat marked as read" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to mark chat as read" });
  }
});

// Start a new chat
app.post("/chats", authenticate, async (req, res) => {
  const { participantId } = req.body;
  if (!participantId) return res.status(400).json({ error: "Participant ID required" });

  try {
    const existing = await Chat.findOne({
      participants: { $all: [req.user.userId, participantId] }
    });

    if (existing) return res.json({ chatId: existing._id, message: "Chat already exists" });

    const chat = await Chat.create({
      participants: [req.user.userId, participantId],
      messages: [],
      unread: { [participantId]: 0, [req.user.userId]: 0 }
    });

    res.json({ chatId: chat._id, message: "New chat created" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to create chat" });
  }
});

// ---------------------
// Start Server
// ---------------------
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
