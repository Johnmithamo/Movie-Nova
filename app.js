// server.js
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

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
  role: { type: String, default: 'user' } // optional roles
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

// ---------------------
// Auth Routes
// ---------------------
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: 'All fields are required' });

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ username, email, passwordHash });
    res.json({ message: 'User created', userId: user._id });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Email or username already exists' });
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
// Video Route (Existing)
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
// Protected Example Route
// ---------------------
app.get('/profile', authenticate, async (req, res) => {
  const user = await User.findById(req.user.userId).select('-passwordHash');
  res.json({ user });
});

// ---------------------
// Start Server
// ---------------------
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
