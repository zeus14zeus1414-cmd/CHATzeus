const mongoose = require('mongoose');

// ملاحظة: قمنا بإزالة حقل "content" من هنا.
// المحتوى النصي سيخزن الآن في Firebase Firestore.
const chapterSchema = new mongoose.Schema({
    number: { type: Number, required: true },
    title: { type: String, required: true },
    // content: { type: String },  <-- تم الحذف
    createdAt: { type: Date, default: Date.now }, 
    views: { type: Number, default: 0 }
});

const novelSchema = new mongoose.Schema({
    title: { type: String, required: true, index: true },
    titleEn: { type: String },
    
    // بيانات المؤلف/المترجم
    author: { type: String, required: true }, // الاسم الظاهر
    authorEmail: { type: String, index: true }, // البريد الإلكتروني للتوثيق (جديد)

    cover: { type: String }, 
    description: { type: String },
    category: { type: String, index: true },
    tags: [String],
    status: { type: String, default: 'مستمرة' },
    rating: { type: Number, default: 0 },
    
    // إحصائيات المشاهدات
    views: { type: Number, default: 0 }, 
    // تم التعديل: String بدلاً من ObjectId للسماح بمفاتيح مركبة مثل "userId_ch_1"
    viewedBy: [{ type: String }], 

    dailyViews: { type: Number, default: 0 },
    weeklyViews: { type: Number, default: 0 },
    monthlyViews: { type: Number, default: 0 },
    
    favorites: { type: Number, default: 0 },
    chapters: [chapterSchema],
    
    lastChapterUpdate: { type: Date, default: Date.now },
    
    isRecommended: { type: Boolean, default: false },
    isTrending: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

// فهرس للبحث والترتيب
novelSchema.index({ title: 'text', author: 'text' });
novelSchema.index({ views: -1 });
novelSchema.index({ lastChapterUpdate: -1 });
// فهرس لربط الأعمال بالمستخدم عبر البريد
novelSchema.index({ authorEmail: 1 });

const Novel = mongoose.model('Novel', novelSchema);
module.exports = Novel;
