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
        if (user && (user.role === 'admin' || user.role === 'contributor')) {
             // السماح للداعمين والمشرفين بالوصول لنقاط النهاية هذه
             next();
        } else {
            res.status(403).json({ message: 'Admin/Contributor access required' });
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
app.post('/api/upload', verifyToken, upload.single('image'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ message: "No file uploaded" });

        const b64 = Buffer.from(req.file.buffer).toString('base64');
        let dataURI = "data:" + req.file.mimetype + ";base64," + b64;
        
        const result = await cloudinary.uploader.upload(dataURI, {
            folder: "zeus_user_uploads",
            resource_type: "image"
        });

        res.json({ url: result.secure_url });
    } catch (error) {
        console.error("Upload Error:", error);
        res.status(500).json({ error: error.message });
    }
});

// =========================================================
// 👤 USER PROFILE API
// =========================================================

// Update Profile Info (Name, Bio, Banner, Avatar, Privacy)
app.put('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const { name, bio, banner, picture, isHistoryPublic } = req.body;
        
        const updates = {};
        if (name) updates.name = name;
        if (bio !== undefined) updates.bio = bio;
        if (banner) updates.banner = banner;
        if (picture) updates.picture = picture;
        if (isHistoryPublic !== undefined) updates.isHistoryPublic = isHistoryPublic;

        const updatedUser = await User.findByIdAndUpdate(
            req.user.id,
            { $set: updates },
            { new: true }
        );

        res.json(updatedUser);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get User Profile with Stats (Aggregation)
app.get('/api/user/stats', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const user = await User.findById(userId);

        if (!user) return res.status(404).json({ message: "User not found" });

        // 1. Calculate Read Chapters
        const libraryStats = await NovelLibrary.aggregate([
            { $match: { user: new mongoose.Types.ObjectId(userId) } },
            { $group: { _id: null, totalRead: { $sum: "$maxReadChapterId" } } }
        ]);
        const totalReadChapters = libraryStats[0] ? libraryStats[0].totalRead : 0;

        let addedChapters = 0;
        let totalViews = 0;
        let myWorks = [];

        // 2. Calculate Contributor Stats (If Contributor/Admin)
        if (user.role === 'admin' || user.role === 'contributor') {
            // ✨✨✨ التعديل هنا: البحث باستخدام البريد الإلكتروني ✨✨✨
            // إذا كانت الرواية تحتوي على authorEmail، نستخدمه. إذا لا (روايات قديمة)، نحاول بالاسم.
            myWorks = await Novel.find({ 
                $or: [
                    { authorEmail: user.email },
                    { author: { $regex: new RegExp(`^${user.name}$`, 'i') } } // Fallback for old data
                ]
            });
            
            myWorks.forEach(novel => {
                addedChapters += (novel.chapters ? novel.chapters.length : 0);
                totalViews += (novel.views || 0);
            });
        }

        res.json({
            readChapters: totalReadChapters,
            addedChapters,
            totalViews,
            myWorks
        });

    } catch (error) {
        console.error("Stats Error:", error);
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
            title, 
            cover, 
            description, 
            author: translator, // الاسم الظاهر
            authorEmail: req.user.email, // ✨✨✨ الحفظ السحابي بالبريد الإلكتروني ✨✨✨
            category, 
            tags,
            chapters: [], 
            views: 0, 
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
        // عند التحديث، لا نغير authorEmail إلا إذا كنا نريد نقل الملكية (وهو غير متاح هنا حالياً)
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
        
        // تحقق إضافي: هل المستخدم هو صاحب الرواية؟ (اختياري لكن مفضل)
        // if (novel.authorEmail && novel.authorEmail !== req.user.email && req.user.role !== 'admin') {
        //    return res.status(403).json({ message: "Unauthorized" });
        // }

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
// (باقي الكود كما هو بدون تغيير)
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
        const { filter, search, category, status, sort, page = 1, limit = 20, timeRange } = req.query;
        
        const pageNum = parseInt(page);
        const limitNum = parseInt(limit);
        const skip = (pageNum - 1) * limitNum;

        let matchStage = {};

        // البحث
        if (search) {
             matchStage.$or = [
                 { title: { $regex: search, $options: 'i' } },
                 { author: { $regex: search, $options: 'i' } }
             ];
        }
        
        // التصنيف
        if (category && category !== 'all') {
            matchStage.$or = [
                { category: category },
                { tags: category }
            ];
        }

        // الحالة (جديد)
        if (status && status !== 'all') {
            matchStage.status = status;
        }

        if (filter === 'latest_updates') {
            matchStage["chapters.0"] = { $exists: true };
        }

        let pipeline = [
            { $match: matchStage },
            { $addFields: { chaptersCount: { $size: { $ifNull: ["$chapters", []] } } } }
        ];

        let sortStage = {};
        if (sort === 'chapters_desc') {
            sortStage = { chaptersCount: -1 };
        } else if (sort === 'chapters_asc') {
            sortStage = { chaptersCount: 1 };
        } else if (sort === 'title_asc') {
            sortStage = { title: 1 };
        } else if (sort === 'title_desc') {
            sortStage = { title: -1 };
        } else if (filter === 'latest_updates') {
            sortStage = { lastChapterUpdate: -1 };
        } else if (filter === 'latest_added') {
            sortStage = { createdAt: -1 };
        } else if (filter === 'featured' || filter === 'trending') {
             if (timeRange === 'day') sortStage = { dailyViews: -1 };
             else if (timeRange === 'week') sortStage = { weeklyViews: -1 };
             else if (timeRange === 'month') sortStage = { monthlyViews: -1 };
             else sortStage = { views: -1 };
        } else {
             sortStage = { chaptersCount: -1 };
        }

        pipeline.push({ $sort: sortStage });

        const result = await Novel.aggregate([
            { $match: matchStage },
            { $addFields: { chaptersCount: { $size: { $ifNull: ["$chapters", []] } } } },
            { $sort: sortStage },
            {
                $facet: {
                    metadata: [{ $count: "total" }],
                    data: [{ $skip: skip }, { $limit: limitNum }]
                }
            }
        ]);

        const novelsData = result[0].data;
        const totalCount = result[0].metadata[0] ? result[0].metadata[0].total : 0;
        const totalPages = Math.ceil(totalCount / limitNum);

        res.json({
            novels: novelsData,
            currentPage: pageNum,
            totalPages: totalPages,
            totalNovels: totalCount
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: error.message });
    }
});

app.get('/api/novels/:id', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(404).json({ message: 'Invalid ID' });
        
        let novelDoc = await Novel.findById(req.params.id);
        if (!novelDoc) return res.status(404).json({ message: 'Novel not found' });
        
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
