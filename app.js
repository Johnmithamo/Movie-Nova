const express = require('express');
const cors = require('cors');
const cloudinary = require('cloudinary').v2;

const app = express();
app.use(cors());

// ✅ Configure your Cloudinary credentials
cloudinary.config({
  cloud_name: 'dvvl4i8q9',
  api_key: '356966284533889',
  api_secret: 'B1phMo6M--Cxz4UggvQN6qUxbek'
});

// ✅ Route to get video metadata
app.get('/videos', async (req, res) => {
  try {
    // Fetch all videos (type='upload', resource_type='video')
    const result = await cloudinary.api.resources({
      type: 'upload',
      resource_type: 'video',
      max_results: 50 // you can change this to fetch more
    });

    // Map useful metadata for the client
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

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});