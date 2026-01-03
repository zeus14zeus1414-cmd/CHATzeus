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
const multer = require('multer'); // إضافة Multer لرفع الملفات

// --- Config Imports ---
let firestore, cloudinary;
try {
    const firebaseAdmin = require('./config/firebaseAdmin');
    firestore = firebaseAdmin.db;
    cloudinary = require('./config/cloudinary');
} catch (e) {
    console.warn("⚠️ Config files check failed...");
}

// Models
const User = require('./models/user.model.js');
const Novel = require('./models/novel.model.js');
const NovelLibrary = require('./models/novelLibrary.model.js'); 
const Settings = require('./models/settings.model.js');

const app = express();
const ADMIN_EMAIL = "flaf.aboode@gmail.com"; 

// إعداد Multer للتعامل مع رفع الصور في الذاكرة
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

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

// Helper to check and update status automatically
async function checkNovelStatus(novel) {
    if (novel.status === 'مكتملة') return novel; // المكتملة لا تتغير

    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    // إذا مر 30 يوم والحالة مستمرة، حولها لمتوقفة
    if (novel.lastChapterUpdate < thirtyDaysAgo && novel.status === 'مستمرة') {
        novel.status = 'متوقفة';
        await novel.save();
    }
    return novel;
}

// =========================================================
// 🖼️ UPLOAD API: رفع الصور إلى Cloudinary
// =========================================================
app.post('/api/upload', verifyAdmin, upload.single('image'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ message: "No file uploaded" });

        const b64 = Buffer.from(req.file.buffer).toString('base64');
        let dataURI = "data:" + req.file.mimetype + ";base64," + b64;
        
        const result = await cloudinary.uploader.upload(dataURI, {
            folder: "zeus_novels",
            resource_type: "image"
        });

        res.json({ url: result.secure_url });
    } catch (error) {
        console.error("Upload Error:", error);
        res.status(500).json({ error: error.message });
    }
});

// =========================================================
// 🗑️ ADMIN API
// =========================================================
app.post('/api/admin/nuke', verifyAdmin, async (req, res) => {
    try {
        await Novel.deleteMany({});
        await NovelLibrary.deleteMany({});
        res.json({ message: "تم تصفير النظام بنجاح." });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =========================================================
// 📝 ADMIN API: الروايات
// =========================================================
app.post('/api/admin/novels', verifyAdmin, async (req, res) => {
    try {
        const { title, cover, description, translator, category, tags, status } = req.body;
        
        const newNovel = new Novel({
            title, cover, description, author: translator, category, tags,
            chapters: [], views: 0, 
            status: status || 'مستمرة'
        });

        await newNovel.save();
        res.json(newNovel);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

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

app.delete('/api/admin/novels/:id', verifyAdmin, async (req, res) => {
    try {
        await Novel.findByIdAndDelete(req.params.id);
        await NovelLibrary.deleteMany({ novelId: req.params.id });
        res.json({ message: "Deleted successfully" });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =========================================================
// 📖 ADMIN API: الفصول
// =========================================================
app.post('/api/admin/chapters', verifyAdmin, async (req, res) => {
    try {
        const { novelId, number, title, content } = req.body;
        
        const novel = await Novel.findById(novelId);
        if (!novel) return res.status(404).json({ message: "Novel not found" });

        if (firestore) {
            await firestore.collection('novels').doc(novelId).collection('chapters').doc(number.toString()).set({
                title, content, lastUpdated: new Date()
            });
        }

        const existingChapterIndex = novel.chapters.findIndex(c => c.number == number);
        const chapterMeta = { number: Number(number), title, createdAt: new Date(), views: 0 };

        if (existingChapterIndex > -1) {
            novel.chapters[existingChapterIndex] = { ...novel.chapters[existingChapterIndex].toObject(), ...chapterMeta };
        } else {
            novel.chapters.push(chapterMeta);
        }
        
        // تحديث تاريخ آخر فصل
        novel.lastChapterUpdate = new Date();
        
        // منطق تحديث الحالة: إذا كانت متوقفة وتم نشر فصل، تصبح مستمرة
        if (novel.status === 'متوقفة') {
            novel.status = 'مستمرة';
        }

        novel.markModified('chapters');
        await novel.save();

        res.json({ message: "Chapter saved successfully" });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/admin/chapters/:novelId/:number', verifyAdmin, async (req, res) => {
    try {
        const { novelId, number } = req.params;
        const { title, content } = req.body;

        const novel = await Novel.findById(novelId);
        if (!novel) return res.status(404).json({ message: "Novel not found" });

        if (firestore) {
            await firestore.collection('novels').doc(novelId).collection('chapters').doc(number.toString()).update({
                title, content, lastUpdated: new Date()
            });
        }

        const chapterIndex = novel.chapters.findIndex(c => c.number == number);
        if (chapterIndex > -1) {
            novel.chapters[chapterIndex].title = title;
            novel.markModified('chapters');
            await novel.save();
        }

        res.json({ message: "Chapter updated successfully" });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/chapters/:novelId/:number', verifyAdmin, async (req, res) => {
    try {
        const { novelId, number } = req.params;
        const novel = await Novel.findById(novelId);
        
        novel.chapters = novel.chapters.filter(c => c.number != number);
        await novel.save();

        if (firestore) {
            await firestore.collection('novels').doc(novelId).collection('chapters').doc(number.toString()).delete();
        }

        res.json({ message: "Chapter deleted" });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =========================================================
// APIs العامة
// =========================================================

app.post('/api/novels/:id/view', verifyToken, async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(404).send('Invalid ID');
        
        const { chapterNumber } = req.body; 
        
        if (!chapterNumber) {
            return res.status(200).json({ message: 'Chapter number required for view count' });
        }

        const novel = await Novel.findById(req.params.id);
        if (!novel) return res.status(404).send('Novel not found');

        const userId = req.user.id;
        const viewKey = `${userId}_ch_${chapterNumber}`;
        const alreadyViewed = novel.viewedBy.includes(viewKey);

        if (!alreadyViewed) {
            novel.viewedBy.push(viewKey);
            novel.views += 1;
            novel.dailyViews += 1;
            novel.weeklyViews += 1;
            novel.monthlyViews += 1;
            await novel.save();
            return res.status(200).json({ viewed: true, total: novel.views });
        } else {
            return res.status(200).json({ viewed: false, message: 'Already viewed this chapter', total: novel.views });
        }
    } catch (error) { 
        console.error("View Count Error:", error);
        res.status(500).send('Error'); 
    }
});

app.get('/api/novels', async (req, res) => {
    try {
        const { filter, search, category, timeRange, limit: queryLimit } = req.query;
        let query = {};
        let sort = { views: -1 };
        let limit = parseInt(queryLimit) || 20;

        if (search) query.$text = { $search: search };
        
        // تحديث منطق الفلترة: البحث في التصنيف الرئيسي أو العلامات
        if (category && category !== 'all') {
            query.$or = [
                { category: category },
                { tags: category }
            ];
        }

        if (filter === 'latest_updates') {
            query["chapters.0"] = { $exists: true };
            sort = { lastChapterUpdate: -1 };
            limit = 24;
        } else if (filter === 'latest_added') {
            sort = { createdAt: -1 };
        } else if (filter === 'featured') {
            sort = { views: -1 };
            limit = 3;
        } else if (filter === 'trending') {
            if (timeRange === 'day') sort = { dailyViews: -1 };
            else if (timeRange === 'week') sort = { weeklyViews: -1 };
            else if (timeRange === 'month') sort = { monthlyViews: -1 };
            else sort = { views: -1 };
        }

        const novels = await Novel.find(query).sort(sort).limit(limit);
        
        // تحويل الوثائق إلى كائنات عادية وإضافة البيانات المحسوبة
        const novelsWithDetails = await Promise.all(novels.map(async (novelDoc) => {
            // التحقق من حالة الرواية وتحديثها إذا لزم الأمر
            const updatedNovel = await checkNovelStatus(novelDoc);
            const novel = updatedNovel.toObject(); // تحويل إلى JSON
            
            const chapters = novel.chapters || [];
            return {
                ...novel,
                chaptersCount: chapters.length,
                lastChapterUpdate: novel.lastChapterUpdate || novel.createdAt
            };
        }));

        res.json(novelsWithDetails);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.get('/api/novels/:id', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(404).json({ message: 'Invalid ID' });
        
        let novelDoc = await Novel.findById(req.params.id);
        if (!novelDoc) return res.status(404).json({ message: 'Novel not found' });
        
        // تحديث الحالة عند طلب التفاصيل
        novelDoc = await checkNovelStatus(novelDoc);
        
        const novel = novelDoc.toObject();
        novel.chaptersCount = novel.chapters ? novel.chapters.length : 0;
        
        res.json(novel);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.get('/api/novels/:novelId/chapters/:chapterId', async (req, res) => {
    try {
        const { novelId, chapterId } = req.params;
        if (!mongoose.Types.ObjectId.isValid(novelId)) return res.status(404).json({ message: 'Invalid ID' });

        const novel = await Novel.findById(novelId);
        if (!novel) return res.status(404).json({ message: 'Novel not found' });

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
            content: content,
            totalChapters: novel.chapters.length
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Library Logic...
// (باقي الكود كما هو بدون تغييرات جوهرية)
app.post('/api/novel/update', verifyToken, async (req, res) => {
    try {
        const { novelId, title, cover, author, isFavorite, lastChapterId, lastChapterTitle } = req.body;
        if (!novelId || !mongoose.Types.ObjectId.isValid(novelId)) return res.status(400).json({ message: 'Invalid ID' });

        const originalNovel = await Novel.findById(novelId);
        const totalChapters = originalNovel ? (originalNovel.chapters.length || 1) : 1;

        let libraryItem = await NovelLibrary.findOne({ user: req.user.id, novelId });
        let isNewFavorite = false;
        let isRemovedFavorite = false;

        if (!libraryItem) {
            libraryItem = new NovelLibrary({ 
                user: req.user.id, novelId, title, cover, author, 
                isFavorite: isFavorite || false, 
                lastChapterId: lastChapterId || 0,
                maxReadChapterId: lastChapterId || 0,
                lastChapterTitle,
                progress: lastChapterId ? Math.round((lastChapterId / totalChapters) * 100) : 0
            });
            if (isFavorite) isNewFavorite = true;
        } else {
            if (isFavorite !== undefined) {
                if (isFavorite && !libraryItem.isFavorite) isNewFavorite = true;
                if (!isFavorite && libraryItem.isFavorite) isRemovedFavorite = true;
                libraryItem.isFavorite = isFavorite;
            }
            if (title) libraryItem.title = title;
            if (cover) libraryItem.cover = cover;
            
            if (lastChapterId) {
                libraryItem.lastChapterId = lastChapterId;
                libraryItem.lastChapterTitle = lastChapterTitle;
                const currentMax = libraryItem.maxReadChapterId || 0;
                if (lastChapterId > currentMax) {
                    libraryItem.maxReadChapterId = lastChapterId;
                }
                const calculatedProgress = Math.min(100, Math.round((libraryItem.maxReadChapterId / totalChapters) * 100));
                libraryItem.progress = calculatedProgress;
            }
            libraryItem.lastReadAt = new Date();
        }
        await libraryItem.save();

        if (isNewFavorite) {
            await Novel.findByIdAndUpdate(novelId, { $inc: { favorites: 1 } });
        } else if (isRemovedFavorite) {
            await Novel.findByIdAndUpdate(novelId, { $inc: { favorites: -1 } });
        }

        res.json(libraryItem);
    } catch (error) { 
        console.error(error);
        res.status(500).json({ message: 'Failed' }); 
    }
});

app.get('/api/novel/library', verifyToken, async (req, res) => {
    try {
        const { type } = req.query; 
        let query = { user: req.user.id };
        if (type === 'favorites') query.isFavorite = true;
        else if (type === 'history') query.progress = { $gt: 0 };
        const items = await NovelLibrary.find(query).sort({ lastReadAt: -1 });
        res.json(items);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.get('/api/novel/status/:novelId', verifyToken, async (req, res) => {
    const item = await NovelLibrary.findOne({ user: req.user.id, novelId: req.params.novelId });
    res.json(item || { isFavorite: false, progress: 0, lastChapterId: 0, maxReadChapterId: 0 });
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
    const user = await User.findById(req.user.id);
    res.json({ loggedIn: true, user: user });
});

module.exports = app;
