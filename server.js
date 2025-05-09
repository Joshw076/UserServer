require('dotenv').config();

//upgrade definitions
const upgradeDefinitions = {
  fire_rate: {
    displayName: "Fire Rate",
    baseCost: 100,
    costGrowth: 1.5,
    type: "coin" // instant upgrade
  },
  coin_boost: {
    displayName: "Coin Multiplier",
    baseCost: 150,
    costGrowth: 1.75,
    type: "science",
    duration: 86400000 // 1 day in ms
  },
  auto_clicker: {
    displayName: "Auto Collector",
    baseCost: 200,
    costGrowth: 2.0,
    type: "science",
    duration: 43200000 // 12 hours
  }
};

//variables
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const User = require('./models/User');



// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => console.error('❌ MongoDB connection error:', err));
console.log("🧪 Type of User:", typeof User);
console.log("🧪 User object keys:", Object.keys(User));

// Register Endpoint
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    console.log("📩 Incoming Register Request:", req.body);
  
    try {
      if (!email || !password) {
        return res.status(400).json({ error: "Missing email or password" });
      }
  
      const existing = await User.findOne({ email });
      if (existing) return res.status(400).json({ error: 'User already exists' });
  
      const passwordHash = await bcrypt.hash(password, 10);
      const newUser = new User({ email, passwordHash });
      await newUser.save();
  
      res.status(201).json({ message: 'User created successfully' });
    } catch (err) {
      console.error("❌ Registration error:", err);
      res.status(500).json({ error: 'Server error' });
    }
});
  

// Login Endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Protected Profile Endpoint
app.get('/profile', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing token' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-passwordHash');
    if (!user) return res.status(404).json({ error: 'User not found' });

    res.json(user);
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }

});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
