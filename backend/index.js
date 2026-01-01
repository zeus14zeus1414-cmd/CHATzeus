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
// ☢️ Real Data Seeding (Low Stats for Testing)
// ---------------------------------------------------------
const seedDataForce = async () => {
    try {
        // Only seed if empty to preserve user's manual increments, 
        // OR uncomment deleteMany to force reset.
        const count = await Novel.countDocuments();
        if (count > 0) return; 

        // await Novel.deleteMany({}); // Uncomment if you want to wipe DB
        
        console.log("🌱 Seeding fresh data...");

        const generateChapters = (count) => Array.from({length: count}, (_, i) => ({
            number: i + 1,
            title: `الفصل ${i + 1}`,
            content: `هذا هو محتوى الفصل رقم ${i + 1}.\n\nيمكنك الآن تجربة قراءة هذا الفصل وسيتم احتساب المشاهدة بشكل حقيقي.`,
            createdAt: new Date()
        }));

        const novelsList = [
            {
                title: 'إمبراطور السيوف',
                author: 'تانغ',
                cover: 'https://images.unsplash.com/photo-1518709268805-4e9042af9f23?w=400&h=600&fit=crop',
                category: 'شيانشيا',
                views: 10, // Start low
                dailyViews: 0,
                weeklyViews: 2,
                monthlyViews: 5,
                chapters: generateChapters(50)
            },
            {
                title: 'عالم الفوضى',
                author: 'خالد',
                cover: 'https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=400&h=600&fit=crop',
                category: 'شوانهوان',
                views: 5,
                dailyViews: 0,
                chapters: generateChapters(30)
            },
            {
                title: 'الظل القاتل',
                author: 'ماساشي',
                cover: 'https://images.unsplash.com/photo-1514539079130-25950c84af65?w=400&h=600&fit=crop',
                category: 'أكشن',
                views: 0,
                dailyViews: 0,
                chapters: generateChapters(20)
            },
            // Filler novels
            ...Array.from({length: 17}, (_, i) => ({
                title: `رواية تجريبية ${i + 1}`,
                author: `مؤلف ${i + 1}`,
                cover: `https://images.unsplash.com/photo-${1500000000000 + (i * 1000)}?w=400&h=600&fit=crop`,
                category: 'مغامرات',
                views: 0,
                dailyViews: 0,
                chapters: generateChapters(10)
            }))
        ];

        await Novel.insertMany(novelsList);
        console.log("✅ Seeded 20 novels with LOW stats for testing.");
    } catch (e) {
        console.error("Seeding error:", e);
    }
};

app.post('/api/seed', async (req, res) => {
    // This endpoint allows you to manually trigger a reset if needed
    await Novel.deleteMany({});
    await seedDataForce();
    res.json({ message: "Database Wiped and Re-seeded with fresh data" });
});

// ---------------------------------------------------------
// 🔍 Novel APIs
// ---------------------------------------------------------

app.post('/api/novels/:id/view', async (req, res) => {
    try {
        // Increment all counters atomically
        const updated = await Novel.findByIdAndUpdate(req.params.id, {
            $inc: { 
                views: 1, 
                dailyViews: 1, 
                weeklyViews: 1, 
                monthlyViews: 1 
            }
        }, { new: true });
        
        if (!updated) return res.status(404).send('Novel not found');
        
        console.log(`View counted for ${updated.title}. Total: ${updated.views}`);
        res.status(200).json({ views: updated.views });
    } catch (error) {
        console.error("View increment error:", error);
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
            sort = { views: -1 };
            limit = 3;
        } else if (filter === 'trending') {
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

        const result = novels.map(n => {
            const obj = n.toObject();
            if (filter === 'latest_updates') {
                obj.recentChapters = obj.chapters
                    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
                    .slice(0, 3)
                    .map(c => ({ number: c.number, createdAt: c.createdAt }));
                obj.remainingChaptersCount = Math.max(0, obj.chapters.length - 3);
            }
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
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
             return res.status(400).json({ message: 'Invalid ID' });
        }
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

        // Find chapter by ID (if passed as string ID) OR by number
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
                user: req.user.id, novelId, title, cover, author,
                isFavorite: isFavorite || false, progress: progress || 0,
                lastChapterId, lastChapterTitle
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
        res.status(500).json({ message: 'Failed to update library' });
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
        res.status(500).json({ message: 'Failed to fetch library' });
    }
});

app.get('/api/novel/status/:novelId', verifyToken, async (req, res) => {
    try {
        const item = await NovelLibrary.findOne({ user: req.user.id, novelId: req.params.novelId });
        res.json(item || { isFavorite: false, progress: 0 });
    } catch (error) {
        res.status(500).json({ message: 'Error checking status' });
    }
});

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

        // Initial seed check on login
        seedDataForce();

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
