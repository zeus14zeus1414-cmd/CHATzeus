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
// 📚 Seeding Data (20 Real Novels)
// ---------------------------------------------------------
const seedDataIfEmpty = async () => {
    try {
        const count = await Novel.countDocuments();
        if (count === 0) {
            console.log("Seeding 20 novels...");
            
            const categories = ['شيانشيا', 'شوانهوان', 'وشيا', 'رعب', 'نظام', 'خيال علمي'];
            const generateChapters = (count) => Array.from({length: count}, (_, i) => ({
                number: i + 1,
                title: `الفصل ${i + 1}: ${['البداية', 'الصحوة', 'المعركة', 'الخيانة', 'النهاية'][i % 5]}`,
                content: `هذا نص تجريبي للفصل ${i + 1}. في عالم تحكمه القوة، وقف البطل أمام خصمه وقال: "لن أستسلم!". اشتعلت المعركة وتطايرت الشرارة... (يمكن استبدال هذا بنص طويل لاحقاً).`,
                createdAt: new Date(Date.now() - (count - i) * 86400000) // تواريخ متدرجة
            }));

            const novelsList = [
                {
                    title: 'إمبراطور السيوف الإلهية',
                    author: 'تانغ جيا',
                    cover: 'https://images.unsplash.com/photo-1518709268805-4e9042af9f23?w=400&h=600&fit=crop',
                    description: 'في عالم تحكمه فنون القتال، يسعى بطلنا لإتقان سيف السماوات.',
                    category: 'شيانشيا',
                    views: 150000, dailyViews: 500, weeklyViews: 3000, monthlyViews: 12000,
                    isTrending: true, rating: 4.9, chapters: generateChapters(50)
                },
                {
                    title: 'سيد الفوضى',
                    author: 'آي ير',
                    cover: 'https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=400&h=600&fit=crop',
                    description: 'عاد من الموت لينتقم ممن خانوه.',
                    category: 'شوانهوان',
                    views: 98000, dailyViews: 300, weeklyViews: 2000, monthlyViews: 8000,
                    isTrending: true, rating: 4.7, chapters: generateChapters(30)
                },
                {
                    title: 'ظل النينجا الأخير',
                    author: 'ماساشي',
                    cover: 'https://images.unsplash.com/photo-1514539079130-25950c84af65?w=400&h=600&fit=crop',
                    description: 'في عصر التكنولوجيا، يحاول آخر نينجا حماية تقاليده.',
                    category: 'أكشن',
                    views: 45000, dailyViews: 100, weeklyViews: 700, monthlyViews: 2500,
                    rating: 4.5, chapters: generateChapters(20)
                },
                {
                    title: 'مكتبة الأرواح',
                    author: 'سارة ج.',
                    cover: 'https://images.unsplash.com/photo-1507842217121-9d59754baebc?w=400&h=600&fit=crop',
                    description: 'مكتبة غامضة تحتوي على كتب تحكي قصص الموتى.',
                    category: 'رعب',
                    views: 32000, dailyViews: 80, weeklyViews: 500, monthlyViews: 1800,
                    rating: 4.6, chapters: generateChapters(15)
                },
                {
                    title: 'نظام المستوى الفائق',
                    author: 'لي تشاو',
                    cover: 'https://images.unsplash.com/photo-1534447677768-be436bb09401?w=400&h=600&fit=crop',
                    description: 'طالب فاشل يحصل على نظام يجعله عبقرياً في كل شيء.',
                    category: 'نظام',
                    views: 210000, dailyViews: 1200, weeklyViews: 8000, monthlyViews: 30000,
                    isTrending: true, rating: 4.8, chapters: generateChapters(100)
                },
                {
                    title: 'أميرة الجليد والنار',
                    author: 'جورج م.',
                    cover: 'https://images.unsplash.com/photo-1518806118471-f28b20a1d79d?w=400&h=600&fit=crop',
                    description: 'صراع بين ممالك الجليد والنار من أجل العرش.',
                    category: 'فانتازيا',
                    views: 89000, dailyViews: 200, weeklyViews: 1500, monthlyViews: 6000,
                    rating: 4.7, chapters: generateChapters(40)
                },
                {
                    title: 'الخيميائي المفقود',
                    author: 'باولو',
                    cover: 'https://images.unsplash.com/photo-1515536765-9b2a740fa331?w=400&h=600&fit=crop',
                    description: 'رحلة البحث عن حجر الفلاسفة والخلود.',
                    category: 'فانتازيا',
                    views: 12000, dailyViews: 20, weeklyViews: 100, monthlyViews: 400,
                    rating: 4.2, chapters: generateChapters(10)
                },
                {
                    title: 'غزو الفضاء',
                    author: 'إسحاق',
                    cover: 'https://images.unsplash.com/photo-1451187580459-43490279c0fa?w=400&h=600&fit=crop',
                    description: 'حرب بين البشر وكائنات فضائية متطورة.',
                    category: 'خيال علمي',
                    views: 67000, dailyViews: 150, weeklyViews: 900, monthlyViews: 3500,
                    rating: 4.4, chapters: generateChapters(25)
                },
                {
                    title: 'مصاص الدماء الأخير',
                    author: 'آن رايس',
                    cover: 'https://images.unsplash.com/photo-1614853316476-de00d14cb1fc?w=400&h=600&fit=crop',
                    description: 'قصة حب وحرب في عالم مصاصي الدماء.',
                    category: 'رعب',
                    views: 150000, dailyViews: 400, weeklyViews: 2500, monthlyViews: 10000,
                    rating: 4.8, chapters: generateChapters(60)
                },
                {
                    title: 'التنين الأزرق',
                    author: 'إيراغون',
                    cover: 'https://images.unsplash.com/photo-1577493340887-b7bfff550145?w=400&h=600&fit=crop',
                    description: 'فتى قروي يجد بيضة تنين وتتغير حياته.',
                    category: 'فانتازيا',
                    views: 40000, dailyViews: 90, weeklyViews: 600, monthlyViews: 2000,
                    rating: 4.3, chapters: generateChapters(18)
                },
                // إضافة 10 روايات أخرى لتكملة العدد 20
                ...Array.from({length: 10}, (_, i) => ({
                    title: `الرواية الإضافية ${i + 1}`,
                    author: `مؤلف ${i + 1}`,
                    cover: `https://images.unsplash.com/photo-${1500000000000 + i}?w=400&h=600&fit=crop`, // صور عشوائية
                    description: `وصف تجريبي للرواية رقم ${i + 11}`,
                    category: categories[i % categories.length],
                    views: Math.floor(Math.random() * 50000),
                    dailyViews: Math.floor(Math.random() * 500),
                    rating: (3 + Math.random() * 2).toFixed(1),
                    chapters: generateChapters(5 + i)
                }))
            ];

            await Novel.insertMany(novelsList);
            console.log("✅ Seeded 20 novels successfully");
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
// 🔍 Novel APIs (Updated Logic)
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

        if (filter === 'latest_updates') {
            const result = novels.map(novel => {
                const n = novel.toObject();
                // Get latest 3 chapters
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
        // Return full chapters for detail to know count and titles
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

        // Try seeding on login
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
