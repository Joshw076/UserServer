const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  // 🔐 Auth
  email: {
    type: String,
    required: true,
    unique: true
  },
  passwordHash: {
    type: String,
    required: true
  },
  username: {
    type: String,
    required: true,
    unique: true
  },

  // 🪙 Currency
  Cu: { type: Number, default: 0 },
  Ag: { type: Number, default: 0 },
  Au: { type: Number, default: 0 },
  totalCUEarned: { type: Number, default: 0 },
  cuPerMinuteCached: { type: Number, default: 0 },

  // ⚙️ Upgrades
  upgrades: {
    type: Map,
    of: Number,
    default: {}
  },

  // 🧪 Science
  scienceSlots: {
    type: [
      {
        upgradeKey: String,
        startTime: Date,
        duration: Number
      }
    ],
    default: []
  },
  maxScienceSlots: {
    type: Number,
    default: 1
  },

  // 📈 Progression
  prestigeLevel: { type: Number, default: 0 },
  totalPlayTime: { type: Number, default: 0 },

  // 🧾 Ads and Monetization
  adsWatchedToday: { type: Number, default: 0 },
  totalAdsWatched: { type: Number, default: 0 },
  lastAdWatchedAt: { type: Date },
  hasRemovedAds: { type: Boolean, default: false },

  purchases: {
    type: [
      {
        productId: String,
        purchasedAt: Date
      }
    ],
    default: []
  },

  // 🗓️ Daily Login Tracking
  lastDailyClaim: { type: Date },
  dailyLoginStreak: { type: Number, default: 0 },

  // 📊 Meta Info
  accountCreatedAt: {
    type: Date,
    default: Date.now
  },
  isDeleted: { type: Boolean, default: false },
  lastLogin: { type: Date },
  platform: { type: String, enum: ['android', 'ios', 'web'], default: 'android' },
  language: { type: String, default: 'en' },
  referrerCode: { type: String },
  abGroup: { type: String }
});

module.exports = mongoose.model('User', UserSchema);
