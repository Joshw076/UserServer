// models/User.js
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
  coins: {
    type: Number,
    default: 0
  },
  upgrades: {
    type: [String],
    default: []
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
