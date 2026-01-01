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
const Novel = require('./models/novel.model.js');
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
    origin: '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

app.use(express.json({ limit: '50mb' }));

// ---------------------------------------------------------
// 🔌 Database Connection
// ---------------------------------------------------------
let cachedDb = null;

async function connectToDatabase() {
    if (cachedDb) {
        return cachedDb;
    }
    console.log("⏳ Connecting to MongoDB...");
    try {
        const db = await mongoose.connect(process.env.MONGODB_URI, {
            serverSelectionTimeoutMS: 5000,
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

app.use(async (req, res, next) => {
    try {
        await connectToDatabase();
        next();
    } catch (error) {
        res.status(500).json({ error: 'Database connection failed' });
    }
});

// ---------------------------------------------------------
// 📚 Seeding Data (20 Real Novels with Logic)
// ---------------------------------------------------------
const seedDataIfEmpty = async () => {
    try {
        const count = await Novel.countDocuments();
        
        // إذا كان العدد قليل (بيانات قديمة)، نحذف ونعيد الملء لضمان التجربة
        if (count < 10) {
            console.log("Cleaning old data and seeding 20 diverse novels...");
            await Novel.deleteMany({}); // تنظيف القديم
            
            const categories = ['شيانشيا', 'شوانهوان', 'وشيا', 'رعب', 'نظام', 'خيال علمي'];
            const generateChapters = (count) => Array.from({length: count}, (_, i) => ({
                number: i + 1,
                title: `الفصل ${i + 1}`,
                content: `هذا نص تجريبي للفصل ${i + 1}. في عالم تحكمه القوة...`,
                createdAt: new Date(Date.now() - (count - i) * 86400000)
            }));

            // 1. Top 3 All Time (High Views, Low Daily/Weekly - Old Classics)
            // 2. Trending Now (High Daily/Weekly, Mid Total Views)
            // 3. Just Added (Low Views, High Recency)

            const novelsList = [
                // --- Top 3 All Time Kings ---
                {
                    title: 'إمبراطور السيوف الإلهية',
                    author: 'تانغ جيا',
                    cover: 'https://images.unsplash.com/photo-1518709268805-4e9042af9f23?w=400&h=600&fit=crop',
                    description: 'الملك المطلق للروايات.',
                    category: 'شيانشيا',
                    views: 5000000, dailyViews: 1000, weeklyViews: 5000, monthlyViews: 20000,
                    chapters: generateChapters(100)
                },
                {
                    title: 'سيد الفوضى',
                    author: 'آي ير',
                    cover: 'https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=400&h=600&fit=crop',
                    description: 'المركز الثاني تاريخياً.',
                    category: 'شوانهوان',
                    views: 4500000, dailyViews: 800, weeklyViews: 4000, monthlyViews: 18000,
                    chapters: generateChapters(80)
                },
                {
                    title: 'ظل النينجا الأخير',
                    author: 'ماساشي',
                    cover: 'https://images.unsplash.com/photo-1514539079130-25950c84af65?w=400&h=600&fit=crop',
                    description: 'المركز الثالث تاريخياً.',
                    category: 'أكشن',
                    views: 3000000, dailyViews: 500, weeklyViews: 3000, monthlyViews: 15000,
                    chapters: generateChapters(60)
                },

                // --- Trending Today (Viral) ---
                {
                    title: 'نظام المستوى الفائق',
                    author: 'لي تشاو',
                    cover: 'https://images.unsplash.com/photo-1534447677768-be436bb09401?w=400&h=600&fit=crop',
                    description: 'تريند اليوم! مشاهدات يومية عالية.',
                    category: 'نظام',
                    views: 50000, dailyViews: 5000, weeklyViews: 15000, monthlyViews: 30000, // Viral Today
                    chapters: generateChapters(20)
                },
                {
                    title: 'أميرة الجليد والنار',
                    author: 'جورج م.',
                    cover: 'https://images.unsplash.com/photo-1518806118471-f28b20a1d79d?w=400&h=600&fit=crop',
                    description: 'تريند الأسبوع.',
                    category: 'فانتازيا',
                    views: 100000, dailyViews: 200, weeklyViews: 8000, monthlyViews: 20000, // Viral Week
                    chapters: generateChapters(30)
                },

                // --- More Novels to fill up to 20 ---
                ...Array.from({length: 15}, (_, i) => ({
                    title: `الرواية رقم ${i + 6}`,
                    author: `مؤلف ${i + 1}`,
                    cover: `https://images.unsplash.com/photo-${1510000000000 + (i * 12345)}?w=400&h=600&fit=crop`,
                    description: `وصف لرواية ${i + 6}`,
                    category: categories[i % categories.length],
                    views: Math.floor(Math.random() * 20000),
                    dailyViews: Math.floor(Math.random() * 300),
                    weeklyViews: Math.floor(Math.random() * 1000),
                    monthlyViews: Math.floor(Math.random() * 5000),
                    rating: (3 + Math.random() * 2).toFixed(1),
                    chapters: generateChapters(10 + i),
                    lastChapterUpdate: new Date(Date.now() - Math.floor(Math.random() * 100000000))
                }))
            ];

            await Novel.insertMany(novelsList);
            console.log("✅ Seeded 20 novels successfully with logic.");
        }
    } catch (e) {
        console.error("Seeding error:", e);
    }
};

app.post('/api/seed', async (req, res) => {
    await seedDataIfEmpty();
    res.json({ message: "Seeding check complete" });
});

// ---------------------------------------------------------
// 🔍 Novel APIs
// ---------------------------------------------------------

app.post('/api/novels/:id/view', async (req, res) => {
    try {
        await Novel.findByIdAndUpdate(req.params.id, {
            $inc: { 
                views: 1, 
                dailyViews: 1, 
                weeklyViews: 1, 
                monthlyViews: 1 
            }
        });
        res.status(200).send('View counted');
    } catch (error) {
        console.error(error);
        res.status(500).send('Error');
    }
});

app.get('/api/novels', async (req, res) => {
    try {
        const { filter, search, category, timeRange } = req.query;
        let query = {};
        let sort = {};
        let limit = 20;

        if (search) query.$text = { $search: search };
        if (category && category !== 'all') query.category = category;

        if (filter === 'featured') {
            // المميز: أعلى 3 روايات قراءة على الإطلاق (All Time)
            sort = { views: -1 };
            limit = 3;
        } else if (filter === 'trending') {
            // الأكثر قراءة حسب الفلتر الزمني
            if (timeRange === 'day') sort = { dailyViews: -1 };
            else if (timeRange === 'week') sort = { weeklyViews: -1 };
            else if (timeRange === 'month') sort = { monthlyViews: -1 };
            else sort = { views: -1 }; 
            limit = 10;
        } else if (filter === 'latest_updates') {
            sort = { lastChapterUpdate: -1 };
            limit = 15;
        } else if (filter === 'latest_added') {
            sort = { createdAt: -1 };
            limit = 12;
        } else {
            sort = { views: -1 };
        }

        const novels = await Novel.find(query).sort(sort).limit(limit);

        if (filter === 'latest_updates') {
            const result = novels.map(novel => {
                const n = novel.toObject();
                n.recentChapters = n.chapters
                    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
                    .slice(0, 3)
                    .map(c => ({ number: c.number, createdAt: c.createdAt }));
                
                const remaining = Math.max(0, n.chapters.length - 3);
                n.remainingChaptersCount = remaining;
                delete n.chapters;
                return n;
            });
            return res.json(result);
        }

        const result = novels.map(n => {
            const obj = n.toObject();
            obj.chaptersCount = obj.chapters ? obj.chapters.length : 0;
            delete obj.chapters;
            return obj;
        });

        res.json(result);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.get('/api/novels/:id', async (req, res) => {
    try {
        const novel = await Novel.findById(req.params.id);
        if (!novel) return res.status(404).json({ message: 'Novel not found' });
        
        const result = novel.toObject();
        result.chapters = result.chapters.map(c => ({
            _id: c._id,
            number: c.number,
            title: c.title,
            createdAt: c.createdAt
        }));
        
        res.json(result);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.get('/api/novels/:novelId/chapters/:chapterId', async (req, res) => {
    try {
        const novel = await Novel.findById(req.params.novelId);
        if (!novel) return res.status(404).json({ message: 'Novel not found' });

        let chapter = novel.chapters.find(c => c._id.toString() === req.params.chapterId) || 
                      novel.chapters.find(c => c.number == req.params.chapterId);

        if (!chapter) return res.status(404).json({ message: 'Chapter not found' });

        res.json(chapter);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Library APIs
app.post('/api/novel/update', verifyToken, async (req, res) => {
    try {
        const { novelId, title, cover, author, isFavorite, progress, lastChapterId, lastChapterTitle } = req.body;
        
        let libraryItem = await NovelLibrary.findOne({ user: req.user.id, novelId });

        if (!libraryItem) {
            libraryItem = new NovelLibrary({
                user: req.user.id,
                novelId,
                title,
                cover,
                author,
                isFavorite: isFavorite || false,
                progress: progress || 0,
                lastChapterId,
                lastChapterTitle
            });
        } else {
            if (title) libraryItem.title = title;
            if (cover) libraryItem.cover = cover;
            if (author) libraryItem.author = author;
            if (isFavorite !== undefined) libraryItem.isFavorite = isFavorite;
            if (progress !== undefined) libraryItem.progress = progress;
            if (lastChapterId !== undefined) libraryItem.lastChapterId = lastChapterId;
            if (lastChapterTitle !== undefined) libraryItem.lastChapterTitle = lastChapterTitle;
            libraryItem.lastReadAt = new Date();
        }

        await libraryItem.save();
        res.json(libraryItem);
    } catch (error) {
        console.error('Library update error:', error);
        res.status(500).json({ message: 'Failed to update library' });
    }
});

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

// Auth
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

        const payload = { id: user._id, googleId: user.googleId, name: user.name, email: user.email };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '365d' });

        seedDataIfEmpty();

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

app.get('/api/user', verifyToken, (req, res) => {
    res.json({ loggedIn: true, user: req.user });
});

module.exports = app;
