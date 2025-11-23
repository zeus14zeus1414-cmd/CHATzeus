const mongoose = require('mongoose');

const glossarySchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    key: { type: String, required: true }, // المصطلح الإنجليزي
    value: { type: String, required: true }, // الترجمة العربية
    type: { type: String, enum: ['manual', 'extracted'], default: 'manual' }
}, { timestamps: true });

// هذا السطر مهم جداً: يمنع تكرار نفس المصطلح لنفس المستخدم
glossarySchema.index({ user: 1, key: 1 }, { unique: true });

const Glossary = mongoose.model('Glossary', glossarySchema);
module.exports = Glossary;
