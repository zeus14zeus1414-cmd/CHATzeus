const mongoose = require('mongoose');

const chapterSchema = new mongoose.Schema({
    number: { type: Number, required: true },
    title: { type: String, required: true },
    content: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }, // لمعرفة الفصول الجديدة
    views: { type: Number, default: 0 }
});

const novelSchema = new mongoose.Schema({
    title: { type: String, required: true, index: true },
    titleEn: { type: String },
    author: { type: String, required: true },
    cover: { type: String },
    description: { type: String },
    category: { type: String, index: true },
    tags: [String],
    status: { type: String, default: 'مستمرة' },
    rating: { type: Number, default: 0 },
    
    // إحصائيات المشاهدات
    views: { type: Number, default: 0 }, // المشاهدات الكلية
    dailyViews: { type: Number, default: 0 },
    weeklyViews: { type: Number, default: 0 },
    monthlyViews: { type: Number, default: 0 },
    
    favorites: { type: Number, default: 0 },
    chapters: [chapterSchema],
    
    lastChapterUpdate: { type: Date, default: Date.now }, // لترتيب الروايات حسب آخر تحديث
    
    isRecommended: { type: Boolean, default: false },
    isTrending: { type: Boolean, default: false }, // يمكن الاستغناء عنه واستخدام المشاهدات
    createdAt: { type: Date, default: Date.now }
});

// فهرس للبحث والترتيب
novelSchema.index({ title: 'text', author: 'text' });
novelSchema.index({ views: -1 });
novelSchema.index({ lastChapterUpdate: -1 });

const Novel = mongoose.model('Novel', novelSchema);
module.exports = Novel;
