const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    googleId: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    picture: { type: String }, // Avatar
    banner: { type: String, default: '' }, // Profile Cover
    bio: { type: String, default: '' }, // User Bio
    isHistoryPublic: { type: Boolean, default: true }, // History Privacy
    role: { type: String, default: 'user', enum: ['user', 'admin', 'contributor'] } // Roles
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

module.exports = User;
