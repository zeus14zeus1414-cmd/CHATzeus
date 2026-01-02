// =================================================================
// 1. التحميل اليدوي لمتغيرات البيئة
// =================================================================
const fs = require('fs');
const path = require('path');

try {
    const envConfig = fs.readFileSync(path.join(__dirname, '.env'), 'utf8');
    envConfig.split('\n').forEach(line => {
        const [key, value] = line.split('=');
        if (key && value) {
            process.env[key.trim()] = value.trim();
        }
    });
    console.log('✅ Environment variables loaded manually.');
} catch (error) {
    console.warn('⚠️  Could not find .env file. Using platform environment variables instead.');
}

const http = require('http');
const express = require('express');
const { OAuth2Client } = require('google-auth-library');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

// --- Config Imports ---
let firestore, cloudinary;
try {
    const firebaseAdmin = require('./config/firebaseAdmin');
    firestore = firebaseAdmin.db;
    cloudinary = require('./config/cloudinary');
} catch (e) {
    console.warn("⚠️ Config files check failed...");
    // Fallback logic kept minimal for brevity
}

// Models
const User = require('./models/user.model.js');
const Novel = require('./models/novel.model.js');
const NovelLibrary = require('./models/novelLibrary.model.js'); 
const Settings = require('./models/settings.model.js');

const app = express();
const ADMIN_EMAIL = "flaf.aboode@gmail.com"; // الإيميل الأدمن الثابت

const allowedOrigins = [
    'https://chatzeus.vercel.app',
    'https://chatzeusb.vercel.app', 
    'http://localhost:8081',
    'exp://localhost:8081'
];

app.use(cors({
    origin: '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

app.use(express.json({ limit: '50mb' }));

let cachedDb = null;

async function connectToDatabase() {
    if (cachedDb) return cachedDb;
    try {
        const db = await mongoose.connect(process.env.MONGODB_URI, {
            serverSelectionTimeoutMS: 5000,
        });
        cachedDb = db;
        console.log("✅ Connected to MongoDB Atlas");
        return db;
    } catch (error) {
        console.error("❌ MongoDB connection error:", error);
        throw error;
    }
}

app.use(async (req, res, next) => {
    try {
        await connectToDatabase();
        next();
    } catch (error) {
        res.status(500).json({ error: 'Database connection failed' });
    }
});

// Middleware للتحقق من التوكن
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
}

// Middleware للتحقق من الأدمن
async function verifyAdmin(req, res, next) {
    verifyToken(req, res, async () => {
        const user = await User.findById(req.user.id);
        if (user && user.role === 'admin') {
            next();
        } else {
            res.status(403).json({ message: 'Admin access required' });
        }
    });
}

// =========================================================
// 🗑️ ADMIN API: تصفير النظام (Wipe Data)
// =========================================================
app.post('/api/admin/nuke', verifyAdmin, async (req, res) => {
    try {
        console.log("☢️ NUKING DATABASE REQUESTED BY ADMIN");
        
        // 1. مسح جميع الروايات والمكتبات في MongoDB
        await Novel.deleteMany({});
        await NovelLibrary.deleteMany({});
        
        // 2. مسح الكوليكشن من Firestore (عملية معقدة قليلاً، سنحذف الرووت فقط كمرجع)
        // ملاحظة: حذف الكوليكشن في Firestore يتطلب تكراراً، هنا سنكتفي بمسح المونجو
        // والتطبيق لن يرى البيانات القديمة في فايرستور لأن الروابط قطعت.
        
        res.json({ message: "تم تصفير النظام بنجاح. يمكنك الآن البدء برفع بيانات حقيقية." });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =========================================================
// 📝 ADMIN API: إدارة الروايات (Create, Update, Delete)
// =========================================================

// إنشاء رواية جديدة
app.post('/api/admin/novels', verifyAdmin, async (req, res) => {
    try {
        const { title, cover, description, translator, category, tags } = req.body;
        
        const newNovel = new Novel({
            title,
            cover, // رابط الصورة
            description,
            author: translator, // نخزن المترجم في خانة المؤلف
            category,
            tags,
            chapters: [],
            views: 0,
            status: 'مستمرة'
        });

        await newNovel.save();
        res.json(newNovel);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// تحديث رواية
app.put('/api/admin/novels/:id', verifyAdmin, async (req, res) => {
    try {
        const { title, cover, description, translator, category, tags, status } = req.body;
        const updated = await Novel.findByIdAndUpdate(req.params.id, {
            title, cover, description, author: translator, category, tags, status
        }, { new: true });
        res.json(updated);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// حذف رواية (والفصول المرتبطة بها)
app.delete('/api/admin/novels/:id', verifyAdmin, async (req, res) => {
    try {
        await Novel.findByIdAndDelete(req.params.id);
        // تنظيف المكتبات للمستخدمين
        await NovelLibrary.deleteMany({ novelId: req.params.id });
        
        // ملاحظة: يفضل حذف الفصول من Firestore أيضاً، لكن للتبسيط الآن سنحذف الرابط فقط
        res.json({ message: "Deleted successfully" });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =========================================================
// 📖 ADMIN API: إدارة الفصول (Hybrid: Mongo + Firestore)
// =========================================================

// إضافة فصل
app.post('/api/admin/chapters', verifyAdmin, async (req, res) => {
    try {
        const { novelId, number, title, content } = req.body;
        
        const novel = await Novel.findById(novelId);
        if (!novel) return res.status(404).json({ message: "Novel not found" });

        // 1. حفظ المحتوى في Firestore
        if (firestore) {
            await firestore
                .collection('novels')
                .doc(novelId)
                .collection('chapters')
                .doc(number.toString())
                .set({
                    title,
                    content,
                    lastUpdated: new Date()
                });
        }

        // 2. تحديث الميتاداتا في MongoDB
        // تحقق إذا الفصل موجود مسبقاً لتحديثه بدلاً من إضافته
        const existingChapterIndex = novel.chapters.findIndex(c => c.number == number);
        
        const chapterMeta = {
            number: Number(number),
            title,
            createdAt: new Date(),
            views: 0
        };

        if (existingChapterIndex > -1) {
            novel.chapters[existingChapterIndex] = { ...novel.chapters[existingChapterIndex].toObject(), ...chapterMeta };
        } else {
            novel.chapters.push(chapterMeta);
        }
        
        novel.lastChapterUpdate = new Date();
        novel.markModified('chapters'); // مهم لتحديث المصفوفة
        await novel.save();

        res.json({ message: "Chapter saved successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

// حذف فصل
app.delete('/api/admin/chapters/:novelId/:number', verifyAdmin, async (req, res) => {
    try {
        const { novelId, number } = req.params;
        const novel = await Novel.findById(novelId);
        
        // حذف من Mongo
        novel.chapters = novel.chapters.filter(c => c.number != number);
        await novel.save();

        // حذف من Firestore
        if (firestore) {
            await firestore.collection('novels').doc(novelId).collection('chapters').doc(number.toString()).delete();
        }

        res.json({ message: "Chapter deleted" });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =========================================================
// APIs العامة (للمستخدمين)
// =========================================================

app.post('/api/novels/:id/view', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(404).send('Invalid ID');
        await Novel.findByIdAndUpdate(req.params.id, { $inc: { views: 1, dailyViews: 1, weeklyViews: 1, monthlyViews: 1 } });
        res.status(200).send('OK');
    } catch (error) { res.status(500).send('Error'); }
});

// جلب الروايات (تم التعديل لجلب البيانات الحقيقية فقط)
app.get('/api/novels', async (req, res) => {
    try {
        const { filter, search, category } = req.query;
        let query = {};
        let sort = { views: -1 };
        let limit = 20;

        if (search) query.$text = { $search: search };
        if (category && category !== 'all') query.category = category;

        if (filter === 'latest_updates') {
            sort = { lastChapterUpdate: -1 };
        } else if (filter === 'latest_added') {
            sort = { createdAt: -1 };
        }

        const novels = await Novel.find(query).sort(sort).limit(limit);
        res.json(novels);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.get('/api/novels/:id', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(404).json({ message: 'Invalid ID' });
        const novel = await Novel.findById(req.params.id);
        if (!novel) return res.status(404).json({ message: 'Novel not found' });
        res.json(novel);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// جلب محتوى الفصل (Mongo + Firestore)
app.get('/api/novels/:novelId/chapters/:chapterId', async (req, res) => {
    try {
        const { novelId, chapterId } = req.params;
        if (!mongoose.Types.ObjectId.isValid(novelId)) return res.status(404).json({ message: 'Invalid ID' });

        const novel = await Novel.findById(novelId);
        if (!novel) return res.status(404).json({ message: 'Novel not found' });

        // البحث عن الفصل
        let chapterMeta = novel.chapters.find(c => c._id.toString() === chapterId) || 
                          novel.chapters.find(c => c.number == chapterId);

        if (!chapterMeta) return res.status(404).json({ message: 'Chapter metadata not found' });

        let content = "لا يوجد محتوى.";
        
        if (firestore) {
            const docRef = firestore.collection('novels').doc(novelId).collection('chapters').doc(chapterMeta.number.toString());
            const docSnap = await docRef.get();
            if (docSnap.exists) {
                content = docSnap.data().content;
            }
        }

        res.json({
            ...chapterMeta.toObject(),
            content: content
        });

    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Library Routes (Standard)
app.post('/api/novel/update', verifyToken, async (req, res) => {
    try {
        const { novelId, title, cover, author, isFavorite, progress, lastChapterId, lastChapterTitle } = req.body;
        if (!novelId || !mongoose.Types.ObjectId.isValid(novelId)) return res.status(400).json({ message: 'Invalid ID' });

        let libraryItem = await NovelLibrary.findOne({ user: req.user.id, novelId });
        if (!libraryItem) {
            libraryItem = new NovelLibrary({ user: req.user.id, novelId, title, cover, author, isFavorite: isFavorite || false, progress: progress || 0, lastChapterId, lastChapterTitle });
        } else {
            if (title) libraryItem.title = title;
            if (cover) libraryItem.cover = cover;
            if (isFavorite !== undefined) libraryItem.isFavorite = isFavorite;
            if (progress !== undefined) libraryItem.progress = progress;
            if (lastChapterId) {
                libraryItem.lastChapterId = lastChapterId;
                libraryItem.lastChapterTitle = lastChapterTitle;
            }
            libraryItem.lastReadAt = new Date();
        }
        await libraryItem.save();
        res.json(libraryItem);
    } catch (error) { res.status(500).json({ message: 'Failed' }); }
});

app.get('/api/novel/library', verifyToken, async (req, res) => {
    const { type } = req.query; 
    let query = { user: req.user.id };
    if (type === 'favorites') query.isFavorite = true;
    else if (type === 'history') query.progress = { $gt: 0 };
    const items = await NovelLibrary.find(query).sort({ lastReadAt: -1 });
    res.json(items);
});

app.get('/api/novel/status/:novelId', verifyToken, async (req, res) => {
    const item = await NovelLibrary.findOne({ user: req.user.id, novelId: req.params.novelId });
    res.json(item || { isFavorite: false, progress: 0 });
});

// AUTH
const oauth2Client = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    "https://chatzeusb.vercel.app/auth/google/callback" 
);

app.get('/auth/google', (req, res) => {
    const redirectUri = req.query.redirect_uri;
    const platform = req.query.platform;
    let state = redirectUri || (platform === 'mobile' ? 'mobile' : 'web');
    
    const authorizeUrl = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email',
        state: state 
    });
    res.redirect(authorizeUrl);
});

app.get('/auth/google/callback', async (req, res) => {
    try {
        await connectToDatabase();
        const { code, state } = req.query;
        const { tokens } = await oauth2Client.getToken(code);
        oauth2Client.setCredentials(tokens);
        const userInfoResponse = await oauth2Client.request({ url: 'https://www.googleapis.com/oauth2/v3/userinfo' });
        const userInfo = userInfoResponse.data;

        let user = await User.findOne({ googleId: userInfo.sub });
        let role = 'user';
        
        // Auto-assign Admin Role
        if (userInfo.email === ADMIN_EMAIL) {
            role = 'admin';
        }

        if (!user) {
            user = new User({
                googleId: userInfo.sub,
                email: userInfo.email,
                name: userInfo.name,
                picture: userInfo.picture,
                role: role
            });
            await user.save();
            await new Settings({ user: user._id }).save();
        } else if (user.role !== role && userInfo.email === ADMIN_EMAIL) {
            // Update role if changed
            user.role = role;
            await user.save();
        }

        const payload = { id: user._id, googleId: user.googleId, name: user.name, email: user.email, role: user.role };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '365d' });

        if (state && state.startsWith('exp://')) {
            const separator = state.includes('?') ? '&' : '?';
            res.redirect(`${state}${separator}token=${token}`);
        } else if (state === 'mobile' || state.startsWith('aplcionszeus://')) {
            const deepLink = state === 'mobile' ? `aplcionszeus://auth?token=${token}` : `${state}?token=${token}`;
            res.redirect(deepLink);
        } else {
            res.redirect(`https://chatzeusb.vercel.app/?token=${token}`);
        }
    } catch (error) {
        console.error('Auth error:', error);
        res.redirect('https://chatzeusb.vercel.app/?auth_error=true');
    }
});

app.get('/api/user', verifyToken, async (req, res) => {
    // Refresh user data from DB to ensure role is up to date
    const user = await User.findById(req.user.id);
    res.json({ loggedIn: true, user: user });
});

module.exports = app;
