const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    googleId: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    picture: { type: String },
    role: { type: String, default: 'user', enum: ['user', 'admin'] } // إضافة الصلاحيات
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

module.exports = User;
