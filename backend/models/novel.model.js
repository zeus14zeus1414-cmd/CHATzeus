const mongoose = require('mongoose');

const chapterSchema = new mongoose.Schema({
    number: { type: Number, required: true },
    title: { type: String, required: true },
    content: { type: String, required: true }, // نص الفصل
    views: { type: Number, default: 0 }
});

const novelSchema = new mongoose.Schema({
    title: { type: String, required: true, index: true },
    titleEn: { type: String },
    author: { type: String, required: true },
    cover: { type: String },
    description: { type: String },
    category: { type: String, index: true }, // xianxia, wuxia, etc.
    tags: [String],
    status: { type: String, default: 'مستمرة' }, // مستمرة, مكتملة
    rating: { type: Number, default: 0 },
    views: { type: Number, default: 0 },
    favorites: { type: Number, default: 0 },
    chapters: [chapterSchema], // تخزين الفصول داخل الرواية للتبسيط
    isRecommended: { type: Boolean, default: false },
    isTrending: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

// فهرس للبحث النصي
novelSchema.index({ title: 'text', author: 'text', description: 'text' });

const Novel = mongoose.model('Novel', novelSchema);
module.exports = Novel;
