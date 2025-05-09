const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true
  },
  passwordHash: {
    type: String,
    required: true
  },

  // 💰 Currencies
  coins: {
    type: Number,
    default: 0
  },
  bills: {
    type: Number,
    default: 0
  },
  bars: {
    type: Number,
    default: 0
  },

  // ⚡ Instant upgrades (scaling)
  upgrades: {
    type: Map,
    of: Number,
    default: {}
  },

  // 🧪 Time-based Science upgrades
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

  accountCreatedAt: {
    type: Date,
    default: Date.now
  },

  totalPlayTime: {
    type: Number,
    default: 0
  }
});

module.exports = mongoose.model('User', UserSchema);
