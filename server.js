require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const User = require('./models/User');

function isValidSignature(payload, clientSignature, secret) {
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(JSON.stringify(payload));
  const expected = hmac.digest('hex');
  return expected === clientSignature;
}

function isNewDay(previousDate) {
  if (!previousDate) return true;
  const prev = new Date(previousDate);
  const now = new Date();
  return prev.toDateString() !== now.toDateString();
}


// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// Register Endpoint
app.post('/register', async (req, res) => {
  const { email, password, username } = req.body;
  console.log("📩 Incoming Register Request:", req.body);

  try {
    if (!email || !password || !username) {
      return res.status(400).json({ error: "Missing email, password, or username" });
    }

    const existingEmail = await User.findOne({ email });
    if (existingEmail) return res.status(400).json({ error: 'Email already registered' });

    const existingUsername = await User.findOne({ username });
    if (existingUsername) return res.status(409).json({ error: 'Username already taken' });

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = new User({ email, passwordHash, username });
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

app.get('/profile', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing token' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const now = new Date();
    user.lastLogin = now;

    // 🕓 Reset adsWatchedToday if a new day
    if (isNewDay(user.lastAdWatchedAt)) {
      user.adsWatchedToday = 0;
    }

    // 🎁 Daily login reward logic
    if (!user.lastDailyClaim || isNewDay(user.lastDailyClaim)) {
      const yesterday = new Date(now);
      yesterday.setDate(now.getDate() - 1);

      if (user.lastDailyClaim && user.lastDailyClaim.toDateString() === yesterday.toDateString()) {
        user.dailyLoginStreak = (user.dailyLoginStreak || 0) + 1;
      } else {
        user.dailyLoginStreak = 1;
      }

      user.lastDailyClaim = now;
      user.Cu += 100; // Reward Cu on login
    }

    await user.save();

    res.json({
      username: user.username,
      Cu: user.Cu,
      Ag: user.Ag,
      Au: user.Au,
      totalCUEarned: user.totalCUEarned,
      upgrades: user.upgrades,
      scienceSlots: user.scienceSlots,
      maxScienceSlots: user.maxScienceSlots,
      accountCreatedAt: user.accountCreatedAt,
      lastLogin: user.lastLogin,
      lastDailyClaim: user.lastDailyClaim,
      dailyLoginStreak: user.dailyLoginStreak,
      totalPlayTime: user.totalPlayTime,
      prestigeLevel: user.prestigeLevel,
      adsWatchedToday: user.adsWatchedToday,
      totalAdsWatched: user.totalAdsWatched,
      hasRemovedAds: user.hasRemovedAds,
      purchases: user.purchases,
      serverTime: new Date().toISOString()
    });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Ad Watched Endpoint
app.post('/profile/adWatched', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing token' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (isNewDay(user.lastAdWatchedAt)) {
      user.adsWatchedToday = 0;
    }

    if (!user.hasRemovedAds) {
      user.adsWatchedToday = (user.adsWatchedToday || 0) + 1;
      user.totalAdsWatched = (user.totalAdsWatched || 0) + 1;
      user.lastAdWatchedAt = new Date();
    }

    await user.save();
    res.json({ message: user.hasRemovedAds ? 'Ad skipped (premium)' : 'Ad watch recorded', adsWatchedToday: user.adsWatchedToday });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Purchase Endpoint
app.post('/profile/purchase', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing token' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { productId } = req.body;
    if (!productId) return res.status(400).json({ error: 'Missing productId' });

    user.purchases.push({ productId, purchasedAt: new Date() });

    // Handle ad removal
    if (productId === 'remove_ads' || productId === 'premium_bundle') {
      user.hasRemovedAds = true;
    }

    await user.save();

    res.json({ message: 'Purchase recorded', productId });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token or request' });
  }
});


// Ping Endpoint (server time only)
app.get('/ping', (req, res) => {
  res.json({ serverTime: new Date().toISOString() });
});

// Update Currency PUT
app.put('/profile/currency', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing token' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { Cu, Ag, Au } = req.body;

    if (
      typeof Cu !== 'number' || Cu < 0 ||
      typeof Ag !== 'number' || Ag < 0 ||
      typeof Au !== 'number' || Au < 0
    ) {
      return res.status(400).json({ error: 'Invalid currency values' });
    }

    user.Cu = Cu;
    user.Ag = Ag;
    user.Au = Au;
    await user.save();

    res.json({ message: 'Currency updated', Cu, Ag, Au });
  } catch (err) {
    console.error("❌ Currency update error:", err);
    res.status(401).json({ error: 'Invalid token or request' });
  }
});

// Save All Endpoint
app.put('/profile/saveAll', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing token' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // 🔐 Signature validation
    const clientSig = req.headers['x-payload-signature'];
    const secret = process.env.HMAC_SECRET;
    if (!isValidSignature(req.body, clientSig, secret)) {
      return res.status(403).json({ error: 'Invalid save signature (possible tampering)' });
    }

    const {
      Cu,
      Ag,
      Au,
      totalCUEarned,
      totalPlayTime,
      upgrades,
      prestigeLevel,
      scienceSlots
    } = req.body;

    if (
      typeof Cu !== 'number' || Cu < 0 ||
      typeof Ag !== 'number' || Ag < 0 ||
      typeof Au !== 'number' || Au < 0 ||
      typeof totalCUEarned !== 'number' || totalCUEarned < 0 ||
      typeof totalPlayTime !== 'number' || totalPlayTime < 0 ||
      typeof prestigeLevel !== 'number' || prestigeLevel < 0 ||
      typeof upgrades !== 'object' ||
      !Array.isArray(scienceSlots)
    ) {
      return res.status(400).json({ error: 'Invalid save data' });
    }

    user.Cu = Cu;
    user.Ag = Ag;
    user.Au = Au;
    user.totalCUEarned = totalCUEarned;
    user.totalPlayTime = totalPlayTime;
    user.prestigeLevel = prestigeLevel;
    user.upgrades = upgrades;
    user.scienceSlots = scienceSlots;

    // 🧠 Update Cu/min cache
    user.cuPerMinuteCached = totalPlayTime > 0
      ? totalCUEarned / (totalPlayTime / 60)
      : 0;

    await user.save();
    res.json({ message: 'All data saved successfully' });
  } catch (err) {
    console.error("❌ SaveAll error:", err);
    res.status(401).json({ error: 'Invalid token or request' });
  }
});


// Start a science research (uses 1 science slot if available)
app.post('/profile/science/add', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing token' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { upgradeKey, duration } = req.body;
    if (!upgradeKey || typeof duration !== 'number' || duration <= 0) {
      return res.status(400).json({ error: 'Invalid request data' });
    }

    // Check if user has free science slots
    if (user.scienceSlots.length >= user.maxScienceSlots) {
      return res.status(403).json({ error: 'No available science slots. Upgrade capacity or wait.' });
    }

    user.scienceSlots.push({
      upgradeKey,
      startTime: new Date(), // Use server time
      duration
    });

    await user.save();
    res.json({ message: 'Science research started', serverTime: new Date().toISOString() });
  } catch (err) {
    console.error("❌ Science start error:", err);
    res.status(401).json({ error: 'Invalid token or request' });
  }
});

// Claim a finished science upgrade
app.post('/profile/science/claim', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing token' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // 🔐 Validate HMAC
    const clientSig = req.headers['x-payload-signature'];
    const secret = process.env.HMAC_SECRET;
    if (!isValidSignature(req.body, clientSig, secret)) {
      return res.status(403).json({ error: 'Invalid claim signature (tampering suspected)' });
    }

    const { upgradeKey } = req.body;
    if (!upgradeKey) return res.status(400).json({ error: 'Missing upgrade key' });

    const now = new Date();
    const slotIndex = user.scienceSlots.findIndex(slot =>
      slot.upgradeKey === upgradeKey &&
      new Date(slot.startTime.getTime() + slot.duration) <= now
    );

    if (slotIndex === -1) {
      return res.status(400).json({ error: 'No completed science upgrade with that key to claim' });
    }

    // Unlock upgrade
    const currentLevel = user.upgrades.get(upgradeKey) || 0;
    user.upgrades.set(upgradeKey, currentLevel + 1);

    // Remove science slot
    user.scienceSlots.splice(slotIndex, 1);

    await user.save();
    res.json({ message: `${upgradeKey} unlocked`, newLevel: currentLevel + 1 });
  } catch (err) {
    console.error("❌ Science claim error:", err);
    res.status(401).json({ error: 'Invalid token or request' });
  }
});

// Delete Profile Endpoint
app.delete('/profile', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing token' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findByIdAndDelete(decoded.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    res.json({ message: 'Account deleted successfully' });
  } catch (err) {
    console.error("❌ Account deletion error:", err);
    res.status(401).json({ error: 'Invalid token or request' });
  }
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
