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

// Models
const User = require('./models/user.model.js');
const Novel = require('./models/novel.model.js'); // النموذج الجديد
const NovelLibrary = require('./models/novelLibrary.model.js'); 
const Settings = require('./models/settings.model.js');

const app = express();

// إعدادات CORS
const allowedOrigins = [
    'https://chatzeus.vercel.app',
    'https://chatzeusb.vercel.app', 
    'http://localhost:8081',
    'exp://localhost:8081'
];

app.use(cors({
    origin: '*', // السماح للجميع مؤقتاً لتجنب مشاكل التطوير
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

app.use(express.json({ limit: '50mb' }));

// ---------------------------------------------------------
// 🔌 Database Connection (Optimized for Serverless)
// ---------------------------------------------------------
let cachedDb = null;

async function connectToDatabase() {
    if (cachedDb) {
        return cachedDb;
    }
    console.log("⏳ Connecting to MongoDB...");
    try {
        const db = await mongoose.connect(process.env.MONGODB_URI, {
            serverSelectionTimeoutMS: 5000, // مهلة 5 ثواني
            socketTimeoutMS: 45000,
        });
        cachedDb = db;
        console.log("✅ Connected to MongoDB");
        return db;
    } catch (error) {
        console.error("❌ MongoDB connection error:", error);
        throw error;
    }
}

// Middleware لضمان الاتصال بقاعدة البيانات قبل كل طلب
app.use(async (req, res, next) => {
    try {
        await connectToDatabase();
        next();
    } catch (error) {
        res.status(500).json({ error: 'Database connection failed' });
    }
});

// ---------------------------------------------------------
// 📚 Seeding Data (تعبئة البيانات تلقائياً)
// ---------------------------------------------------------
const seedDataIfEmpty = async () => {
    try {
        const count = await Novel.countDocuments();
        if (count === 0) {
            console.log("Seeding initial novels...");
            // بيانات تجريبية حقيقية
            const initialNovels = [
                {
                    title: 'إمبراطور السيوف الإلهية',
                    author: 'تانغ جيا سان شاو',
                    cover: 'https://images.unsplash.com/photo-1518709268805-4e9042af9f23?w=400&h=600&fit=crop',
                    description: 'في عالم تحكمه فنون القتال القديمة، يسعى بطلنا لإتقان سيف السماوات التسع.',
                    category: 'شيانشيا',
                    tags: ['شيانشيا', 'فنون قتال', 'قوة'],
                    isTrending: true,
                    rating: 4.8,
                    chapters: Array.from({length: 50}, (_, i) => ({
                        number: i + 1,
                        title: `الفصل ${i + 1}`,
                        content: `هذا هو نص الفصل ${i + 1} من الرواية. يحتوي على سرد للأحداث وتطور الشخصية. في يوم من الأيام...`
                    }))
                },
                {
                    title: 'سيد الفوضى الأبدية',
                    author: 'آي ير',
                    cover: 'https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=400&h=600&fit=crop',
                    description: 'بعد أن خانه أقرب أصدقائه، يعود للحياة بقوة غامضة.',
                    category: 'شوانهوان',
                    isTrending: true,
                    rating: 4.9,
                    chapters: Array.from({length: 20}, (_, i) => ({
                        number: i + 1,
                        title: `الفصل ${i + 1}`,
                        content: `محتوى تجريبي للفصل ${i + 1}...`
                    }))
                },
                {
                    title: 'عودة الإمبراطور الشيطاني',
                    author: 'لي هو',
                    cover: 'https://images.unsplash.com/photo-1569003339405-ea396a5a8a90?w=400&h=600&fit=crop',
                    description: 'بعد 10000 سنة من السجن، يعود الإمبراطور.',
                    category: 'شوانهوان',
                    isTrending: false,
                    isRecommended: true,
                    rating: 4.7,
                    chapters: Array.from({length: 10}, (_, i) => ({
                        number: i + 1,
                        title: `الفصل ${i + 1}`,
                        content: `محتوى تجريبي للفصل ${i + 1}...`
                    }))
                }
            ];
            await Novel.insertMany(initialNovels);
            console.log("✅ Seeded successfully");
        }
    } catch (e) {
        console.error("Seeding error:", e);
    }
};
// تشغيل الـ Seed مرة واحدة عند بدء الخادم (أو عند أول طلب)
// يمكن استدعاؤه يدوياً عبر endpoint للتأكد
app.post('/api/seed', async (req, res) => {
    await seedDataIfEmpty();
    res.json({ message: "Seeding check complete" });
});


// ---------------------------------------------------------
// 🔍 Novel APIs (Real Data)
// ---------------------------------------------------------

// جلب الروايات (فلترة: مميز، جديد، بحث)
app.get('/api/novels', async (req, res) => {
    try {
        const { filter, search, category } = req.query;
        let query = {};

        if (search) {
            query.$text = { $search: search };
        }
        if (category && category !== 'all') {
            query.category = category;
        }

        let novels;
        if (filter === 'trending') {
            novels = await Novel.find({ isTrending: true }).limit(5);
        } else if (filter === 'latest') {
            novels = await Novel.find(query).sort({ createdAt: -1 }).limit(10);
        } else if (filter === 'recommended') {
            novels = await Novel.find({ isRecommended: true }).limit(5);
        } else {
            novels = await Novel.find(query).limit(20);
        }

        res.json(novels);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// جلب تفاصيل رواية مع قائمة الفصول
app.get('/api/novels/:id', async (req, res) => {
    try {
        const novel = await Novel.findById(req.params.id);
        if (!novel) return res.status(404).json({ message: 'Novel not found' });
        
        // نعيد الرواية لكن الفصول نعيد عناوينها فقط لتخفيف الحمل
        const result = novel.toObject();
        result.chapters = result.chapters.map(c => ({
            _id: c._id,
            number: c.number,
            title: c.title,
            // لا نرسل المحتوى هنا
        }));
        
        res.json(result);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// جلب محتوى فصل معين
app.get('/api/novels/:novelId/chapters/:chapterId', async (req, res) => {
    try {
        const novel = await Novel.findById(req.params.novelId);
        if (!novel) return res.status(404).json({ message: 'Novel not found' });

        // البحث عن الفصل داخل المصفوفة
        // ملاحظة: chapterId هنا قد يكون الـ ID أو الرقم، سنفترض أنه الـ ID الفرعي أو الرقم
        let chapter = novel.chapters.find(c => c._id.toString() === req.params.chapterId) || 
                      novel.chapters.find(c => c.number == req.params.chapterId);

        if (!chapter) return res.status(404).json({ message: 'Chapter not found' });

        res.json(chapter);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});


// ---------------------------------------------------------
// 👤 User Library APIs
// ---------------------------------------------------------

app.get('/api/novel/library', verifyToken, async (req, res) => {
    try {
        const { type } = req.query; 
        let query = { user: req.user.id };
        
        if (type === 'favorites') {
            query.isFavorite = true;
        } else if (type === 'history') {
            query.progress = { $gt: 0 };
        }

        const items = await NovelLibrary.find(query).sort({ lastReadAt: -1 });
        res.json(items);
    } catch (error) {
        console.error('Library fetch error:', error);
        res.status(500).json({ message: 'Failed to fetch library' });
    }
});

app.get('/api/novel/status/:novelId', verifyToken, async (req, res) => {
    try {
        const item = await NovelLibrary.findOne({ 
            user: req.user.id, 
            novelId: req.params.novelId 
        });
        res.json(item || { isFavorite: false, progress: 0 });
    } catch (error) {
        res.status(500).json({ message: 'Error checking status' });
    }
});

app.post('/api/novel/update', verifyToken, async (req, res) => {
    try {
        const { novelId, title, cover, author, isFavorite, progress, lastChapterId, lastChapterTitle } = req.body;
        
        const updateData = { 
            title, cover, author, lastReadAt: new Date() 
        };

        if (isFavorite !== undefined) updateData.isFavorite = isFavorite;
        if (progress !== undefined) updateData.progress = progress;
        if (lastChapterId !== undefined) updateData.lastChapterId = lastChapterId;
        if (lastChapterTitle !== undefined) updateData.lastChapterTitle = lastChapterTitle;

        const updated = await NovelLibrary.findOneAndUpdate(
            { user: req.user.id, novelId },
            { $set: updateData },
            { new: true, upsert: true }
        );

        res.json(updated);
    } catch (error) {
        console.error('Library update error:', error);
        res.status(500).json({ message: 'Failed to update library' });
    }
});

// ---------------------------------------------------------
// 🔐 Auth System
// ---------------------------------------------------------
const oauth2Client = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    "https://chatzeusb.vercel.app/auth/google/callback" 
);

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

app.get('/auth/google', (req, res) => {
    const redirectUri = req.query.redirect_uri;
    const platform = req.query.platform;

    let state = 'web';
    if (redirectUri) {
        state = redirectUri;
    } else if (platform === 'mobile') {
        state = 'mobile';
    }
    
    console.log('Login initiated with state:', state);
    const authorizeUrl = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email',
        state: state 
    });
    res.redirect(authorizeUrl);
});

app.get('/auth/google/callback', async (req, res) => {
    try {
        // تأكد من الاتصال بقاعدة البيانات أولاً لتجنب timeouts
        await connectToDatabase();

        const { code, state } = req.query;
        const { tokens } = await oauth2Client.getToken(code);
        oauth2Client.setCredentials(tokens);
        const userInfoResponse = await oauth2Client.request({ url: 'https://www.googleapis.com/oauth2/v3/userinfo' });
        const userInfo = userInfoResponse.data;

        let user = await User.findOne({ googleId: userInfo.sub });

        if (!user) {
            user = new User({
                googleId: userInfo.sub,
                email: userInfo.email,
                name: userInfo.name,
                picture: userInfo.picture,
            });
            await user.save();
            await new Settings({ user: user._id }).save();
        }

        const payload = {
            id: user._id,
            googleId: user.googleId,
            name: user.name,
            email: user.email,
        };

        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '30d' });

        // Trigger auto-seed on login just in case DB is empty
        seedDataIfEmpty();

        if (state && state.startsWith('exp://')) {
            const separator = state.includes('?') ? '&' : '?';
            res.redirect(`${state}${separator}token=${token}`);
        } else if (state === 'mobile' || state.startsWith('aplcionszeus://')) {
            const deepLink = state === 'mobile' 
                ? `aplcionszeus://auth?token=${token}`
                : `${state}?token=${token}`;
            res.redirect(deepLink);
        } else {
            res.redirect(`https://chatzeusb.vercel.app/?token=${token}`);
        }

    } catch (error) {
        console.error('Authentication callback error:', error);
        res.redirect('https://chatzeusb.vercel.app/?auth_error=true');
    }
});

app.get('/api/user', verifyToken, (req, res) => {
    res.json({ loggedIn: true, user: req.user });
});

// Root
app.get('/', (req, res) => {
    res.send('Server is running. DB Connection optimized.');
});

module.exports = app;
