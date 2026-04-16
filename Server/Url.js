const mongoose = require('mongoose');

const UrlSchema = new mongoose.Schema({
  user:        { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  originalUrl: { type: String, required: true },
  shortCode:   { type: String, required: true, unique: true },
  title:       { type: String, default: '' },
  totalClicks: { type: Number, default: 0 },
  clicks: [{
    clickedAt: { type: Date, default: Date.now }
  }],
}, { timestamps: true });

module.exports = mongoose.model('Url', UrlSchema);