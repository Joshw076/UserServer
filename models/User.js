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

  // 🪙 Currencies
  Cu: { type: Number, default: 0 }, // Copper (replaces coins)
  Ag: { type: Number, default: 0 }, // Silver (replaces bills)
  Au: { type: Number, default: 0 }, // Gold (replaces bars)

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
  },

  prestigeLevel: {
    type: Number,
    default: 0
  }
});

module.exports = mongoose.model('User', UserSchema);
