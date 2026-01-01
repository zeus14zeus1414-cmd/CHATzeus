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
const https = require('https');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const express = require('express');
const { OAuth2Client } = require('google-auth-library');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
// Models
const User = require('./models/user.model.js');
const Chat = require('./models/chat.model.js');
const Settings = require('./models/settings.model.js');
const Glossary = require('./models/glossary.model.js');
const TranslationChapter = require('./models/translationChapter.model.js');
const NovelLibrary = require('./models/novelLibrary.model.js'); 
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const cloudinary = require('cloudinary').v2;

const app = express();
const server = http.createServer(app);

// إعدادات CORS
const allowedOrigins = [
    'https://chatzeus.vercel.app',
    'https://chatzeusb.vercel.app', // Added correct domain
    'https://dashporddd.vercel.app',
    'https://tranzeus.vercel.app',
    'http://localhost:5500',
    'http://127.0.0.1:5500'
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(null, true); 
    }
  },
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// إعدادات Google OAuth
const oauth2Client = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    "https://chatzeusb.vercel.app/auth/google/callback" 
);

app.use(express.json({ limit: '50mb' }));

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true
});

// Middleware للتحقق من التوكن
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ loggedIn: false, message: 'No token provided.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ loggedIn: false, message: 'Token is not valid.' });
        }
        req.user = user;
        next();
    });
}

// Root Route (Health Check)
app.get('/', (req, res) => {
    res.send('Server is running correctly. Use /auth/google to login.');
});

// ---------------------------------------------------------
// 🚀 نقاط النهاية الخاصة بتطبيق الروايات (Novel App API)
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
// 🔐 نظام المصادقة (Auth System) - معدل للموبايل بشكل صحيح
// ---------------------------------------------------------

app.get('/auth/google', (req, res) => {
    // 1. استقبال رابط العودة من التطبيق
    const redirectUri = req.query.redirect_uri;
    
    // 2. نخزن هذا الرابط في الـ state
    // إذا لم يصلنا رابط، نعتبره 'web'
    const state = redirectUri && redirectUri !== 'undefined' ? redirectUri : 'web';
    
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
        const { code, state } = req.query;
        console.log('Callback received. Code:', !!code, 'State:', state);

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
            picture: user.picture,
        };

        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '30d' });

        // ✅ التحقق والتوجيه
        if (state && state !== 'web' && state !== 'undefined') {
            console.log("📱 Redirecting to Mobile App:", state);
            
            // إصلاح محتمل: بعض الروابط قد تحتوي بالفعل على query params
            const separator = state.includes('?') ? '&' : '?';
            const finalRedirect = `${state}${separator}token=${token}`;
            
            res.redirect(finalRedirect);
            return;
        }

        // Web Fallback (تم تصحيح الرابط هنا بإضافة حرف b الناقص)
        console.log("💻 Redirecting to Web Fallback");
        res.redirect(`https://chatzeusb.vercel.app/?token=${token}`);

    } catch (error) {
        console.error('Authentication callback error:', error);
        // تصحيح رابط الخطأ أيضاً
        res.redirect('https://chatzeusb.vercel.app/?auth_error=true');
    }
});

app.get('/api/user', verifyToken, (req, res) => {
    res.json({ loggedIn: true, user: req.user });
});

// Database Connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ Successfully connected to MongoDB Atlas.'))
    .catch(err => {
        console.error('❌ Could not connect to MongoDB Atlas.', err);
    });

module.exports = app;
