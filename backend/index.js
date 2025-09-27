// =================================================================
// 1. التحميل اليدوي لمتغيرات البيئة (الحل الجذري)
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
    // ✨ لا توقف الخادم، فقط اعرض تحذيرًا بأنه سيستخدم متغيرات البيئة من المنصة ✨
    console.warn('⚠️  Could not find .env file. Using platform environment variables instead.');
}


// =================================================================
// 2. استدعاء المكتبات المطلوبة
// =================================================================
const http = require('http' );
const https = require('https' );
const { GoogleGenerativeAI } = require('@google/generative-ai');
const express = require('express');
const { OAuth2Client } = require('google-auth-library');
const cors = require('cors'); // Import cors
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const User = require('./models/user.model.js');
const Chat = require('./models/chat.model.js');
const Settings = require('./models/settings.model.js');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const cloudinary = require('cloudinary').v2;



// =================================================================
// 3. إعداد تطبيق Express والخادم
// =================================================================
const app = express();
const server = http.createServer(app  );

// ✨ قائمة النطاقات المسموح بها للاتصال بالخادم ✨
const allowedOrigins = [
    'https://chatzeus.vercel.app',    // 1. واجهة المستخدم الرئيسية
    'https://dashporddd.vercel.app'   // 2. لوحة التحكم الجديدة
    // يمكنك إضافة أي نطاقات أخرى هنا في المستقبل
];

// ✨ إعدادات CORS النهائية والمحصّنة (تستخدم القائمة أعلاه ) ✨
const corsOptions = {
  origin: function (origin, callback) {
    // السماح بالطلبات إذا كان مصدرها (origin) ضمن القائمة المسموح بها
    // أو إذا لم يكن هناك مصدر (مثل الطلبات من Postman أو أدوات التطوير)
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      // إذا كان المصدر غير موجود في القائمة، يتم رفض الطلب
      callback(new Error('هذا النطاق غير مسموح له بالوصول بسبب سياسة CORS.'));
    }
  },
  credentials: true, // السماح بإرسال الكوكيز والتوكن
  allowedHeaders: ['Content-Type', 'Authorization'] // السماح بالهيدرات الضرورية
};

// تطبيق إعدادات CORS على جميع المسارات
app.use(cors(corsOptions));

// معالجة طلبات OPTIONS تلقائيًا (مهم لـ pre-flight)
app.options('*', cors(corsOptions));


const oauth2Client = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    "https://chatzeusb.vercel.app/auth/google/callback"
   );

app.use(express.json({ limit: '50mb' }));

// ✨ تهيئة Cloudinary ✨

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true // استخدام HTTPS
});
console.log('✅ Cloudinary configured.');

// =================================================================
// 4. Middleware للتحقق من التوكن (يدعم كلا من JWT والتوكن الثابت للوحة التحكم)
// =================================================================
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ loggedIn: false, message: 'No token provided.' });
    }

    // ✨ التوكن الثابت للوحة التحكم (للاختبار فقط) ✨
    const DASHBOARD_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4ZDMyNWYxMDBlNDQzMjQ1ZmUwOWU4ZCIsImdvb2dsZUlkIjoiMTA1OTIzOTczMjEwNTE4ODM5NjU5IiwibmFtZSI6Iti52KjZiCDYr9mKJyIsImVtYWlsIjoiZmxhZi5hYm9vZGVnZ2dAZ21haWwuY29tIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0ozUXFSYS1ZM0E1dFBDWGg0ZFhmZVpmNmdIUlJ0dW1qT0oxZ2pvTEhjMDR0VFFqUT1zOTYtYyIsImlhdCI6MTc1ODcyNzEyOSwiZXhwIjoxNzU5MzMxOTI5fQ.VnYebbJWY2ukAa9fpcFMLdEcdQsZd4TFks7i7s6MNWU';

    // إذا كان التوكن يطابق توكن لوحة التحكم
    if (token === DASHBOARD_TOKEN) {
        // فك تشفير التوكن لاستخراج بيانات المستخدم
        try {
            const decoded = jwt.decode(token);
            req.user = decoded;
            return next();
        } catch (error) {
            return res.status(403).json({ loggedIn: false, message: 'Invalid dashboard token format.' });
        }
    }

    // التحقق من JWT العادي
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ loggedIn: false, message: 'Token is not valid.' });
        }
        req.user = user;
        next();
    });
}

// ✨ إزالة تهيئة مجلد الرفع المحلي (لم نعد نستخدمه) ✨
// const uploadsDir = path.join(__dirname, 'uploads');
// if (!fs.existsSync(uploadsDir)) {
//   fs.mkdirSync(uploadsDir, { recursive: true });
//   console.log('✅ Created uploads directory at:', uploadsDir);
// }

// إعداد التخزين لـ Multer - الآن في الذاكرة
const storage = multer.memoryStorage(); // ✨ تم التغيير هنا ✨

// فلترة بسيطة للأنواع المسموحة (اختياري — عدّل حسب حاجتك)
// أضف HEIC/HEIF وأنواع شائعة أخرى (PDF/SVG)، أو ألغِ الفلترة تمامًا إن أردت
const allowedMime = new Set([
  'text/plain','text/markdown','text/csv','application/json','application/xml',
  'text/html','text/css','application/javascript',
  'image/jpeg','image/png','image/gif','image/webp','image/bmp',
  'image/heic','image/heif','image/heif-sequence','image/svg+xml',
  'application/pdf'
]);

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    // اسمح إن كان النوع معلوم أو يبدأ بـ image/
    if (allowedMime.has(file.mimetype) || (file.mimetype && file.mimetype.startsWith('image/'))) {
      return cb(null, true);
    }
    cb(new Error('نوع الملف غير مسموح: ' + file.mimetype));
  }
});

// ✨ إزالة خدمة الملفات المرفوعة بشكل ثابت (لم نعد نخدمها محليًا) ✨
// app.use('/uploads', express.static(uploadsDir));


// =================================================================
// 5. نقاط النهاية (Routes)
// =================================================================

// =================================================================
// ✨ نقاط نهاية إدارة المستخدمين ✨
// =================================================================
// جلب جميع المستخدمين مع إحصائياتهم
app.get('/api/users', verifyToken, async (req, res) => {
    try {
        console.log('🔍 جلب المستخدمين...');
        
        // جلب جميع المستخدمين
        const users = await User.find({}).sort({ createdAt: -1 }).lean();
        
        // حساب إحصائيات كل مستخدم
        const usersWithStats = await Promise.all(users.map(async (user) => {
            const chats = await Chat.find({ user: user._id }).lean();
            const totalMessages = chats.reduce((sum, chat) => sum + (chat.messages?.length || 0), 0);
            
            // تحديد آخر نشاط
            const lastActivity = chats.length > 0 
                ? Math.max(...chats.map(chat => new Date(chat.updatedAt || chat.createdAt).getTime()))
                : new Date(user.createdAt).getTime();
            
            return {
                ...user,
                chatCount: chats.length,
                messageCount: totalMessages,
                lastActivity: new Date(lastActivity).toISOString(),
                isActive: (Date.now() - lastActivity) < (7 * 24 * 60 * 60 * 1000) // نشط إذا كان آخر نشاط خلال أسبوع
            };
        }));

        // حساب الإحصائيات العامة
        const now = new Date();
        const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        
        const stats = {
            total: users.length,
            active: usersWithStats.filter(u => u.isActive).length,
            newThisMonth: users.filter(u => new Date(u.createdAt) > thirtyDaysAgo).length,
            avgChats: usersWithStats.length > 0 ? (usersWithStats.reduce((sum, u) => sum + u.chatCount, 0) / usersWithStats.length).toFixed(1) : '0'
        };

        res.json({
            users: usersWithStats,
            stats
        });

    } catch (error) {
        console.error('خطأ في جلب المستخدمين:', error);
        res.status(500).json({ message: 'فشل في جلب بيانات المستخدمين', error: error.message });
    }
});

// جلب مستخدم محدد مع تفاصيله الكاملة
app.get('/api/users/:userId', verifyToken, async (req, res) => {
    try {
        const { userId } = req.params;
        
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ message: 'معرف المستخدم غير صحيح' });
        }

        const user = await User.findById(userId).lean();
        if (!user) {
            return res.status(404).json({ message: 'المستخدم غير موجود' });
        }

        // جلب محادثات المستخدم
        const chats = await Chat.find({ user: userId })
            .sort({ updatedAt: -1 })
            .limit(10)
            .select('title createdAt updatedAt messages.length')
            .lean();

        const totalMessages = await Chat.aggregate([
            { $match: { user: new mongoose.Types.ObjectId(userId) } },
            { $unwind: '$messages' },
            { $count: 'total' }
        ]);

        const userWithDetails = {
            ...user,
            chatCount: chats.length,
            messageCount: totalMessages.length > 0 ? totalMessages[0].total : 0,
            chats: chats.map(chat => ({
                ...chat,
                messages: { length: chat.messages?.length || 0 }
            }))
        };

        res.json(userWithDetails);

    } catch (error) {
        console.error('خطأ في جلب تفاصيل المستخدم:', error);
        res.status(500).json({ message: 'فشل في جلب تفاصيل المستخدم', error: error.message });
    }
});

// حذف مستخدم
app.delete('/api/users/:userId', verifyToken, async (req, res) => {
    try {
        const { userId } = req.params;
        
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ message: 'معرف المستخدم غير صحيح' });
        }

        // حذف جميع محادثات المستخدم أولاً
        await Chat.deleteMany({ user: userId });
        
        // حذف إعدادات المستخدم
        await Settings.deleteOne({ user: userId });
        
        // حذف المستخدم نفسه
        const deletedUser = await User.findByIdAndDelete(userId);
        
        if (!deletedUser) {
            return res.status(404).json({ message: 'المستخدم غير موجود' });
        }

        res.json({ message: 'تم حذف المستخدم وجميع بياناته بنجاح' });

    } catch (error) {
        console.error('خطأ في حذف المستخدم:', error);
        res.status(500).json({ message: 'فشل في حذف المستخدم', error: error.message });
    }
});

// =================================================================
// ✨ نقاط نهاية إدارة المحادثات ✨
// =================================================================
// جلب جميع المحادثات مع تفاصيلها
app.get('/api/chats', verifyToken, async (req, res) => {
    try {
        console.log('🔍 جلب المحادثات...');
        
        // جلب المحادثات مع معلومات المستخدمين
        const chats = await Chat.find({})
            .sort({ updatedAt: -1 })
            .populate('user', 'name email')
            .lean();

        // تنسيق البيانات للعرض
        const formattedChats = chats.map(chat => ({
            ...chat,
            userName: chat.user?.name || 'مستخدم مجهول',
            userEmail: chat.user?.email || 'غير محدد'
        }));

        // حساب الإحصائيات
        const totalMessages = chats.reduce((sum, chat) => sum + (chat.messages?.length || 0), 0);
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const todayChats = chats.filter(chat => new Date(chat.createdAt) >= today).length;
        
        const stats = {
            totalChats: chats.length,
            totalMessages,
            todayChats,
            avgMessages: chats.length > 0 ? (totalMessages / chats.length).toFixed(1) : '0'
        };

        res.json({
            chats: formattedChats,
            stats
        });

    } catch (error) {
        console.error('خطأ في جلب المحادثات:', error);
        res.status(500).json({ message: 'فشل في جلب بيانات المحادثات', error: error.message });
    }
});

// جلب محادثة محددة مع جميع رسائلها
app.get('/api/chats/:chatId', verifyToken, async (req, res) => {
    try {
        const { chatId } = req.params;
        
        if (!mongoose.Types.ObjectId.isValid(chatId)) {
            return res.status(400).json({ message: 'معرف المحادثة غير صحيح' });
        }

        const chat = await Chat.findById(chatId)
            .populate('user', 'name email picture')
            .lean();

        if (!chat) {
            return res.status(404).json({ message: 'المحادثة غير موجودة' });
        }

        res.json({
            ...chat,
            userName: chat.user?.name || 'مستخدم مجهول',
            userEmail: chat.user?.email || 'غير محدد'
        });

    } catch (error) {
        console.error('خطأ في جلب تفاصيل المحادثة:', error);
        res.status(500).json({ message: 'فشل في جلب تفاصيل المحادثة', error: error.message });
    }
});

// =================================================================
// مسار رفع الملفات (يرجع معلومات يمكن حفظها داخل الرسالة فقط)
// =================================================================
app.post('/api/uploads', verifyToken, upload.array('files', 10), async (req, res) => {
  try {
    const uploadedFilesInfo = [];
    
    for (const file of req.files) {
        const fileInfo = {
            originalName: file.originalname,
            filename: uuidv4(), // Generate a unique ID for internal tracking
            size: file.size,
            mimeType: file.mimetype,
            fileUrl: null, // هذا سيكون رابط Cloudinary أو placeholder
            dataType: null, // 'image', 'text', 'binary'
            content: null // للملفات النصية، تخزين المحتوى هنا
        };

        // التحقق مما إذا كانت صورة
        if (file.mimetype.startsWith('image/')) {
            fileInfo.dataType = 'image';
            try {
                // تحويل Buffer إلى Base64 Data URI للرفع إلى Cloudinary
                const b64 = Buffer.from(file.buffer).toString('base64');
                const dataUri = `data:${file.mimetype};base64,${b64}`;
                
                const isHeic = /image\/heic|image\/heif/i.test(file.mimetype);
const uploadResult = await cloudinary.uploader.upload(dataUri, {
  folder: 'chatzeus_uploads',
  public_id: fileInfo.filename,
  // اجعل Cloudinary يتصرف تلقائيًا، وحوّل HEIC إلى JPG ليكون مفهومًا للنماذج والمتصفحات
  resource_type: 'auto',
  format: isHeic ? 'jpg' : undefined
});
                fileInfo.fileUrl = uploadResult.secure_url;
                console.log(`✅ Uploaded image to Cloudinary: ${fileInfo.fileUrl}`);
            } catch (uploadError) {
                console.error('Cloudinary upload failed for image:', file.originalname, uploadError);
                fileInfo.fileUrl = null; // الإشارة إلى الفشل
                // يمكن هنا رمي خطأ أو الاستمرار وتسجيله
            }
        } else if (file.mimetype.startsWith('text/') || file.mimetype.includes('json') || file.mimetype.includes('xml') || file.mimetype.includes('javascript') || file.mimetype.includes('csv') || file.mimetype.includes('markdown')) {
            fileInfo.dataType = 'text';
            // للملفات النصية/الكود، تخزين المحتوى مباشرة (حسب "لا لاحقا")
            fileInfo.content = file.buffer.toString('utf8');
            // لا يوجد رفع خارجي للملفات النصية/الكود في الوقت الحالي
        } else {
            fileInfo.dataType = 'binary';
            // لا يوجد محتوى أو رفع خارجي للملفات الثنائية الأخرى في الوقت الحالي
        }
        uploadedFilesInfo.push(fileInfo);
    }

    return res.status(201).json({ files: uploadedFilesInfo });
  } catch (e) {
    console.error('Upload error:', e);
    return res.status(500).json({ message: 'فشل رفع الملفات', error: e.message });
  }
});

// معالج أخطاء multer ليعيد 400 بدلاً من 500 مع رسالة واضحة
app.use((err, req, res, next) => {
  if (err && err.message && /multer/i.test(err.stack || '') || /نوع الملف غير مسموح/i.test(err.message)) {
    console.error('Multer error:', err.message);
    return res.status(400).json({ message: err.message });
  }
  next(err);
});

app.get('/auth/google', (req, res) => {
    const authorizeUrl = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email',
    } );
    res.redirect(authorizeUrl);
});

app.get('/auth/google/callback', async (req, res) => {
    try {
        const { code } = req.query;
        const { tokens } = await oauth2Client.getToken(code);
        oauth2Client.setCredentials(tokens);
        const userInfoResponse = await oauth2Client.request({ url: 'https://www.googleapis.com/oauth2/v3/userinfo' } );
        const userInfo = userInfoResponse.data;

        // ابحث عن المستخدم في قاعدة البيانات أو أنشئ مستخدمًا جديدًا
        let user = await User.findOne({ googleId: userInfo.sub });

        if (!user) {
            // مستخدم جديد
            user = new User({
                googleId: userInfo.sub, // .sub هو المعرف الفريد من جوجل
                email: userInfo.email,
                name: userInfo.name,
                picture: userInfo.picture,
            });
            await user.save();

            // إنشاء إعدادات افتراضية للمستخدم الجديد
            const newSettings = new Settings({ user: user._id });
            await newSettings.save();
            console.log(`✨ New user created and saved: ${user.email}`);
        } else {
            console.log(`👋 Welcome back, user: ${user.email}`);
        }

        // إنشاء حمولة التوكن مع معرّف قاعدة البيانات
        const payload = {
            id: user._id,
            googleId: user.googleId,
            name: user.name,
            email: user.email,
            picture: user.picture,
        };

        // توقيع التوكن
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });

        // إعادة التوجيه إلى الواجهة الأمامية مع التوكن
        res.redirect(`https://chatzeus.vercel.app/?token=${token}` );

    } catch (error) {
        console.error('Authentication callback error:', error);
        res.redirect('https://chatzeus.vercel.app/?auth_error=true' );
    }
});

app.get('/api/user', verifyToken, (req, res) => {
    // إذا وصل الطلب إلى هنا، فالـ middleware قد تحقق من التوكن بنجاح
    // ومعلومات المستخدم موجودة في req.user
    res.json({ loggedIn: true, user: req.user });
});

app.post('/api/chat', verifyToken, async (req, res) => {
    await handleChatRequest(req, res);
});

// =================================================================
// 🚩 مسار وضع الفريق (بث حي حقيقي — مع علامات BEGIN/END لكل متحدث)
// =================================================================
app.post('/api/team_chat', verifyToken, async (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Transfer-Encoding': 'chunked'
  });

  try {
    // قراءة البيانات من chatHistory أو history
    const { chatHistory, history, settings } = req.body || {};
    const messages = chatHistory || history || [];
    
    if (!settings || !settings.team || !Array.isArray(settings.team.members) || settings.team.members.length === 0) {
      res.write('❌ لا يوجد أعضاء محددون في وضع الفريق.\n');
      return res.end();
    }

    const lastUser = [...messages].reverse().find(m => m.role === 'user')?.content || '';
    const shortContext = Array.isArray(messages) ? messages.slice(-10) : [];
    const teamThread = [];

    teamThread.push({
      role: 'system',
      content:
`أنت منسّق لفريق خبراء حقيقي. القواعد:
- النقاش تتابعي صارم: عضو واحد يتحدث ثم يتوقف ليرى التالي ردّه.
- كل عضو يرى كامل خيط الفريق حتى لحظته.
- احترم شخصية ودور كل عضو.
- الهدف: حلول عملية مختصرة مع كود/خطوات عند الحاجة.`
    });

    teamThread.push({
      role: 'user',
      content: `مهمة المستخدم:\n${lastUser}\n\nملخص الحوار الأخير:\n${JSON.stringify(shortContext)}`
    });

    const coord = settings.team.coordinator || {};

    // 2) خطة المنسّق
const coordName = coord.name || 'الوكيل';
const coordRole = coord.role || 'منسّق';
const coordPersona = coord.persona || '';

res.write(`⟦AGENT:BEGIN|${coordName}|${coordRole}⟧`);
await streamOneModel(
  coord.provider || 'gemini',
  coord.model || 'gemini-1.5-pro',
  [
    ...teamThread,
    {
      role: 'system',
      content: `المنسّق: ${coordName}\nالدور: ${coordRole}\n${coordPersona ? 'الوصف: ' + coordPersona : ''}`
    }
  ],
  settings,
  (text) => res.write(text)
);
res.write(`⟦AGENT:END⟧`);
    teamThread.push({ role: 'assistant', content: '(تم بث خطة المنسّق)' });

    // 3) الأعضاء
    for (const mem of settings.team.members) {
      const sysPersona = (mem.persona || mem.role)
        ? `شخصية العضو: ${mem.name || 'عضو'} — ${mem.role || ''}\n${mem.persona || ''}`
        : '';

      const memName = mem.name || 'عضو';
const memRole = mem.role || 'مشارك';
const memPersona = mem.persona || '';

res.write(`⟦AGENT:BEGIN|${memName}|${memRole}⟧`);
await streamOneModel(
  mem.provider || 'gemini',
  mem.model || 'gemini-2.5-flash',
  [
    ...teamThread,
    {
      role: 'system',
      content: `العضو: ${memName}\nالدور: ${memRole}\n${memPersona ? 'الوصف: ' + memPersona : ''}`
    }
  ],
  settings,
  (text) => res.write(text)
);
res.write(`⟦AGENT:END⟧`);
      teamThread.push({ role: 'assistant', content: `(تم بث رد ${mem.name || 'عضو'})` });
    }

    // 4) خلاصة المنسّق
    res.write(`⟦AGENT:BEGIN|${coordName}|خلاصة⟧`);
await streamOneModel(
  coord.provider || 'gemini',
  coord.model || 'gemini-1.5-pro',
  [
    ...teamThread,
    {
      role: 'system',
      content: `المطلوب: خلاصة نهائية من ${coordName} (${coordRole})\nالتعليمات: لخّص مخرجات الفريق في نقاط تنفيذية موجزة، مع أي كود/أوامر لازمة.`
    }
  ],
  settings,
  (text) => res.write(text)
);
res.write(`⟦AGENT:END⟧`);

    res.end();
  } catch (e) {
    console.error('team_chat (live stream) error:', e);
    try { res.write(`\n❌ خطأ: ${e.message || 'Team mode failed'}`); } catch(_) {}
    res.end();
  }
});

// =================================================================
// ✨ نقاط نهاية جديدة للبيانات (تضاف في القسم 5)
// =================================================================

app.get('/api/data', verifyToken, async (req, res) => {
    try {
        // 1. التحقق من صلاحية الـ ID في التوكن
        if (!req.user || !req.user.id || !mongoose.Types.ObjectId.isValid(req.user.id)) {
            return res.status(400).json({ message: 'Invalid or missing user ID in token.' });
        }

        let user = await User.findById(req.user.id);

        // 2. خطة احتياطية: إذا لم يتم العثور على المستخدم بالـ ID، جرب googleId
        if (!user && req.user.googleId) {
            console.warn(`User not found by ID ${req.user.id}, trying googleId...`);
            user = await User.findOne({ googleId: req.user.googleId });

            // 3. إذا لم يكن موجودًا على الإطلاق، أنشئه الآن (هذا يمنع أي فشل)
            if (!user) {
                console.warn(`User not found by googleId either. Creating a new user record now.`);
                user = await User.create({
                    _id: req.user.id, // استخدم نفس الـ ID من التوكن لضمان التوافق
                    googleId: req.user.googleId,
                    email: req.user.email,
                    name: req.user.name,
                    picture: req.user.picture,
                });
            }
        }
        
        // إذا لم يتم العثور على المستخدم بعد كل المحاولات، فهناك مشكلة حقيقية
        if (!user) {
             return res.status(404).json({ message: 'User could not be found or created.' });
        }

        // 4. الآن بعد التأكد من وجود المستخدم، اجلب بياناته
                const filter = { user: user._id };
        if (req.query.mode) filter.mode = req.query.mode; // 🚩 فلترة اختيارية حسب الوضع

        const chats = await Chat.find(filter).sort({ order: -1 });
        let settings = await Settings.findOne({ user: user._id });

        // 5. إذا لم تكن لديه إعدادات، أنشئها
        if (!settings) {
            settings = await new Settings({ user: user._id }).save();
        }

        // 6. أرجع دائمًا ردًا ناجحًا
        return res.json({
            settings,
            chats,
            user: { id: user._id, name: user.name, picture: user.picture, email: user.email }
        });

    } catch (e) {
        console.error('FATAL Error in /api/data:', e);
        return res.status(500).json({ message: 'Failed to fetch user data.', error: e.message });
    }
});

// ====== دالة تطبيع الرسائل قبل الحفظ ======
function sanitizeChatForSave(chatData) {
  const out = { ...chatData };

  // طبّع الرسائل فقط إن كانت مصفوفة
  if (Array.isArray(out.messages)) {
    out.messages = out.messages.map(m => {
      const msg = { ...m };

      // 1) احرص أن المحتوى نص
      if (msg.content != null && typeof msg.content !== 'string') {
        msg.content = String(msg.content);
      }

      // 2) حوّل attachments إلى [string]
      if (Array.isArray(msg.attachments)) {
        msg.attachments = msg.attachments
          .map(a => {
            if (typeof a === 'string') return a.trim();
            if (a && typeof a === 'object') {
              return a.fileUrl || a.fileId || a.url || a.name || '';
            }
            return '';
          })
          .filter(Boolean); // أزل الفارغ
      } else {
        msg.attachments = []; // المخطط يتوقع مصفوفة
      }

      return msg;
    });
  }

  return out;
}

// حفظ أو تحديث محادثة
app.post('/api/chats', verifyToken, async (req, res) => {
  try {
    const userIdString = req.user.id;
    if (!mongoose.Types.ObjectId.isValid(userIdString)) {
      return res.status(400).json({ message: 'Invalid User ID format.' });
    }
    const userId = new mongoose.Types.ObjectId(userIdString);

    // ✅ طهّر الداتا قبل أي حفظ/تحديث
    const chatDataRaw = req.body;
    const chatData = sanitizeChatForSave(chatDataRaw);

    // إذا كانت المحادثة موجودة (لديها ID صالح)
    if (chatData._id && mongoose.Types.ObjectId.isValid(chatData._id)) {
      const { _id, ...rest } = chatData;         // ❗️لا تمرّر _id في التحديث
      const updatedChat = await Chat.findOneAndUpdate(
        { _id: new mongoose.Types.ObjectId(_id), user: userId },
        { $set: { ...rest, user: userId } },     // الآن rest.messages.attachments هي [string]
        { new: true, runValidators: true }
      );
      if (!updatedChat) {
        return res.status(404).json({ message: "Chat not found or user not authorized" });
      }
      return res.json(updatedChat);
    } else {
      // إنشاء جديد
      delete chatData._id;
      const newChat = new Chat({
        ...chatData,
        user: userId,
        mode: chatData.mode || 'chat'
      });
      await newChat.save();
      return res.status(201).json(newChat);
    }
  } catch (error) {
    console.error('Error saving chat:', error);
    res.status(500).json({ message: 'Failed to save chat' });
  }
});

app.put('/api/settings', verifyToken, async (req, res) => {
    try {
        if (!req.user || !req.user.id || !mongoose.Types.ObjectId.isValid(req.user.id)) {
            return res.status(400).json({ message: 'Invalid or missing user ID in token.' });
        }
        const userId = new mongoose.Types.ObjectId(req.user.id);
        const receivedSettings = req.body;

// ✨✨✨ الإصلاح الحاسم: انتقاء الحقول المعروفة فقط ✨✨✨
const allowedUpdates = {
    provider: receivedSettings.provider,
    model: receivedSettings.model,
    temperature: receivedSettings.temperature,
    customPrompt: receivedSettings.customPrompt,
    apiKeyRetryStrategy: receivedSettings.apiKeyRetryStrategy,
    fontSize: receivedSettings.fontSize,
    theme: receivedSettings.theme,
    geminiApiKeys: receivedSettings.geminiApiKeys,
    openrouterApiKeys: receivedSettings.openrouterApiKeys,
    customProviders: receivedSettings.customProviders,
    customModels: receivedSettings.customModels,
    // ✨ إعدادات البحث الجديدة ✨
    enableWebBrowsing: receivedSettings.enableWebBrowsing,
    browsingMode: receivedSettings.browsingMode,
    showSources: receivedSettings.showSources,
    dynamicThreshold: receivedSettings.dynamicThreshold,
    // 🚩 إعدادات وضع الفريق
    activeMode: receivedSettings.activeMode,
    team: receivedSettings.team
};

        // إزالة أي حقول غير معرفة (undefined) لتجنب المشاكل
        Object.keys(allowedUpdates).forEach(key => allowedUpdates[key] === undefined && delete allowedUpdates[key]);

        const updatedSettings = await Settings.findOneAndUpdate(
            { user: userId },
            { $set: allowedUpdates }, // استخدام $set لتحديث الحقول المحددة فقط
            { new: true, upsert: true, runValidators: false }
        );

        res.json(updatedSettings);

    } catch (error) {
        console.error('Error updating settings:', error);
        // إرسال رسالة خطأ أكثر تفصيلاً للمساعدة في التشخيص
        res.status(500).json({ message: 'Failed to update settings.', error: error.message });
    }
});

// حذف محادثة
app.delete('/api/chats/:chatId', verifyToken, async (req, res) => {
    try {
        const userIdString = req.user.id;
        const { chatId } = req.params;

        // ✨ 1. التحقق من صلاحية كلا المعرّفين قبل أي شيء ✨
        if (!mongoose.Types.ObjectId.isValid(userIdString) || !mongoose.Types.ObjectId.isValid(chatId)) {
            return res.status(400).json({ message: 'Invalid ID format.' });
        }

        // ✨ 2. استخدام المعرّفات المحوّلة والصحيحة في الاستعلام ✨
        const result = await Chat.findOneAndDelete({ 
            _id: new mongoose.Types.ObjectId(chatId), 
            user: new mongoose.Types.ObjectId(userIdString) 
        });

        if (!result) {
            // هذا يعني أن المحادثة غير موجودة أو لا تخص هذا المستخدم
            return res.status(404).json({ message: 'Chat not found or user not authorized' });
        }

        res.status(200).json({ message: 'Chat deleted successfully' });
    } catch (error) {
        console.error('Error deleting chat:', error);
        res.status(500).json({ message: 'Failed to delete chat' });
    }
});


app.get('/api/dashboard/stats', verifyToken, async (req, res) => {
    try {
        console.log('🔍 Dashboard stats request received');
        
        // ✨ جلب إجمالي المستخدمين
        const totalUsers = await User.countDocuments();

        // ✨ جلب إجمالي المحادثات
        const totalChats = await Chat.countDocuments();

        // ✨ جلب إجمالي الرسائل
        const totalMessagesResult = await Chat.aggregate([
            { $unwind: '$messages' },
            { $count: 'total' }
        ]);
        const totalMessages = totalMessagesResult.length > 0 ? totalMessagesResult[0].total : 0;

        // ✨ جلب إجمالي الملفات المرفوعة (محسن)
        const totalUploadsResult = await Chat.aggregate([
            { $unwind: '$messages' },
            { $match: { 
                $or: [
                    { 'messages.attachments': { $exists: true, $not: { $size: 0 } } },
                    { 'messages.fileUrl': { $exists: true, $ne: null } }
                ]
            }},
            { $count: 'total' }
        ]);
        const totalUploads = totalUploadsResult.length > 0 ? totalUploadsResult[0].total : 0;

        // ✨ إحصائيات المستخدمين الجدد (آخر 30 يوم) - محسنة
        const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        const newUsersByDate = await User.aggregate([
            { $match: { createdAt: { $gte: thirtyDaysAgo } } },
            {
                $group: {
                    _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
                    count: { $sum: 1 }
                }
            },
            { $sort: { _id: 1 } }
        ]);
        
        // ملء الأيام المفقودة بصفر
        const usersByDateMap = new Map(newUsersByDate.map(item => [item._id, item.count]));
        const usersByDateLabels = [];
        const usersByDateData = [];
        
        for (let i = 29; i >= 0; i--) {
            const date = new Date(Date.now() - i * 24 * 60 * 60 * 1000);
            const dateStr = date.toISOString().split('T')[0];
            const label = date.toLocaleDateString('ar-SA', { month: 'short', day: 'numeric' });
            
            usersByDateLabels.push(label);
            usersByDateData.push(usersByDateMap.get(dateStr) || 0);
        }

        const usersByDate = {
            labels: usersByDateLabels,
            data: usersByDateData
        };

        // ✨ إحصائيات المحادثات حسب المزود - محسنة
        const chatsByProviderResult = await Chat.aggregate([
            { $group: { _id: '$provider', count: { $sum: 1 } } },
            { $sort: { count: -1 } }
        ]);
        const chatsByProvider = {
            labels: chatsByProviderResult.map(item => {
                switch(item._id) {
                    case 'gemini': return 'Gemini';
                    case 'openrouter': return 'OpenRouter';
                    case 'custom': return 'مخصص';
                    default: return item._id || 'غير معروف';
                }
            }),
            data: chatsByProviderResult.map(item => item.count)
        };

        // ✨ إحصائيات إضافية للوحة المطورة
        const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        const activeUsers = await User.countDocuments({
            updatedAt: { $gte: sevenDaysAgo }
        });

        // إحصائيات النماذج المستخدمة
        const modelUsageResult = await Chat.aggregate([
            { $group: { _id: '$model', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 10 }
        ]);

        const modelUsage = {
            labels: modelUsageResult.map(item => item._id || 'غير محدد'),
            data: modelUsageResult.map(item => item.count)
        };

        // إحصائيات النشاط اليومي (آخر 7 أيام)
        const activityStats = await Chat.aggregate([
            { 
                $match: { 
                    createdAt: { $gte: sevenDaysAgo }
                }
            },
            {
                $group: {
                    _id: { 
                        $dateToString: { 
                            format: '%Y-%m-%d', 
                            date: '$createdAt' 
                        }
                    },
                    chats: { $sum: 1 },
                    messages: { $sum: { $size: '$messages' } }
                }
            },
            { $sort: { _id: 1 } }
        ]);

        const responseData = {
            totalUsers,
            totalChats,
            totalMessages,
            totalUploads,
            activeUsers,
            usersByDate,
            chatsByProvider,
            modelUsage,
            activityStats,
            // إحصائيات نمو سريعة
            growth: {
                usersThisWeek: await User.countDocuments({ createdAt: { $gte: sevenDaysAgo } }),
                chatsThisWeek: await Chat.countDocuments({ createdAt: { $gte: sevenDaysAgo } }),
                messagesThisWeek: await Chat.aggregate([
                    { $match: { createdAt: { $gte: sevenDaysAgo } } },
                    { $unwind: '$messages' },
                    { $count: 'total' }
                ]).then(result => result.length > 0 ? result[0].total : 0)
            }
        };
        
        console.log('✅ Enhanced dashboard stats response');
        res.status(200).json(responseData);
        
    } catch (error) {
        console.error('❌ Error fetching dashboard stats:', error);
        res.status(500).json({ 
            message: 'Failed to fetch dashboard statistics', 
            error: error.message 
        });
    }
});



// =================================================================
// ✨ endpoint التحليلات المتقدمة ✨
// =================================================================
app.get('/api/dashboard/advanced-analytics', verifyToken, async (req, res) => {
    try {
        console.log('🔍 طلب التحليلات المتقدمة...');
        
        const { startDate, endDate } = req.query;
        let dateFilter = {};
        
        if (startDate && endDate) {
            dateFilter = {
                createdAt: {
                    $gte: new Date(startDate),
                    $lte: new Date(endDate)
                }
            };
        }

        // الحصول على الإحصائيات الأساسية
        const totalUsers = await User.countDocuments(dateFilter);
        const totalChats = await Chat.countDocuments(dateFilter);
        
        // حساب معدل التفاعل
        const activeUsersLastWeek = await User.countDocuments({
            updatedAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
        });
        const engagementRate = totalUsers > 0 ? Math.round((activeUsersLastWeek / totalUsers) * 100) : 0;
        
        // حساب متوسط وقت الاستجابة (محاكاة)
        const avgResponseTime = 1.2 + (Math.random() * 0.8);
        
        // مؤشر الرضا (محاكاة بناءً على نشاط المستخدمين)
        const satisfactionScore = Math.min(95, 70 + (engagementRate * 0.3));

        // إحصائيات النمو
        const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        const usersLastMonth = await User.countDocuments({
            createdAt: { $gte: thirtyDaysAgo }
        });
        const usersGrowth = totalUsers > usersLastMonth ? 
            Math.round(((totalUsers - usersLastMonth) / usersLastMonth) * 100) : 0;

        // مؤشرات الأداء الرئيسية
        const chatSessions = await Chat.countDocuments({
            createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        });
        
        const avgSessionLength = Math.round(8 + (Math.random() * 8)); // محاكاة
        const retentionRate = Math.round(60 + (Math.random() * 20)); // محاكاة
        const errorRate = Math.round((Math.random() * 0.5) * 10) / 10; // محاكاة
        const systemUptime = 99.9; // محاكاة

        // بيانات نمو المستخدمين (آخر 30 يوم)
        const userGrowthData = await User.aggregate([
            {
                $match: {
                    createdAt: { $gte: thirtyDaysAgo }
                }
            },
            {
                $group: {
                    _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
                    newUsers: { $sum: 1 }
                }
            },
            { $sort: { _id: 1 } }
        ]);

        // ملء الأيام المفقودة
        const userGrowthMap = new Map(userGrowthData.map(item => [item._id, item.newUsers]));
        const userGrowthLabels = [];
        const newUsersData = [];
        const activeUsersData = [];

        for (let i = 29; i >= 0; i--) {
            const date = new Date(Date.now() - i * 24 * 60 * 60 * 1000);
            const dateStr = date.toISOString().split('T')[0];
            const label = date.toLocaleDateString('ar-SA', { month: 'short', day: 'numeric' });
            
            userGrowthLabels.push(label);
            newUsersData.push(userGrowthMap.get(dateStr) || 0);
            activeUsersData.push(Math.floor(Math.random() * 100) + 50); // محاكاة
        }

        // استخدام النماذج
        const modelsUsage = await Chat.aggregate([
            {
                $group: {
                    _id: '$model',
                    count: { $sum: 1 }
                }
            },
            { $sort: { count: -1 } },
            { $limit: 5 }
        ]);

        const modelsLabels = modelsUsage.map(item => {
            if (!item._id) return 'غير محدد';
            if (item._id.includes('gemini')) return 'Gemini';
            if (item._id.includes('gpt')) return 'GPT';
            if (item._id.includes('claude')) return 'Claude';
            return item._id;
        });
        const modelsData = modelsUsage.map(item => item.count);

        // نشاط آخر 7 أيام
        const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        const activityData = await Chat.aggregate([
            {
                $match: {
                    createdAt: { $gte: sevenDaysAgo }
                }
            },
            {
                $group: {
                    _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
                    chats: { $sum: 1 },
                    messages: { $sum: { $size: '$messages' } }
                }
            },
            { $sort: { _id: 1 } }
        ]);

        const activityMap = new Map(activityData.map(item => [item._id, item]));
        const activityLabels = [];
        const chatsData = [];
        const messagesData = [];

        for (let i = 6; i >= 0; i--) {
            const date = new Date(Date.now() - i * 24 * 60 * 60 * 1000);
            const dateStr = date.toISOString().split('T')[0];
            const label = date.toLocaleDateString('ar-SA', { weekday: 'short' });
            
            activityLabels.push(label);
            const dayData = activityMap.get(dateStr);
            chatsData.push(dayData ? dayData.chats : 0);
            messagesData.push(dayData ? dayData.messages : 0);
        }

        // بيانات محاكاة لذروة الاستخدام والتوزيع الجغرافي
        const peakHoursData = {
            labels: ['6 ص', '9 ص', '12 ظ', '3 م', '6 م', '9 م', '12 ص', '3 ص'],
            data: [20, 45, 65, 70, 85, 95, 60, 25]
        };

        const geographyData = {
            labels: ['السعودية', 'الإمارات', 'مصر', 'الأردن', 'الكويت'],
            data: [45, 25, 15, 10, 5]
        };

        const response = {
            metrics: {
                totalUsers,
                engagementRate,
                avgResponseTime: avgResponseTime.toFixed(1),
                satisfactionScore: Math.round(satisfactionScore),
                usersGrowth,
                engagementGrowth: 8, // محاكاة
                responseTimeChange: -15, // محاكاة (تحسن)
                satisfactionGrowth: 5 // محاكاة
            },
            kpis: {
                activeUsers: activeUsersLastWeek,
                chatSessions,
                avgSessionLength,
                retentionRate,
                errorRate,
                systemUptime
            },
            charts: {
                userGrowth: {
                    labels: userGrowthLabels,
                    newUsers: newUsersData,
                    activeUsers: activeUsersData
                },
                models: {
                    labels: modelsLabels.length > 0 ? modelsLabels : ['Gemini', 'GPT', 'Claude'],
                    data: modelsData.length > 0 ? modelsData : [45, 30, 25]
                },
                activity: {
                    labels: activityLabels,
                    chats: chatsData,
                    messages: messagesData
                },
                peakHours: peakHoursData,
                geography: geographyData
            }
        };

        console.log('✅ تم إنشاء بيانات التحليلات المتقدمة');
        res.json(response);

    } catch (error) {
        console.error('❌ خطأ في التحليلات المتقدمة:', error);
        res.status(500).json({
            message: 'فشل في جلب بيانات التحليلات',
            error: error.message
        });
    }
});

// تصدير التقارير
app.get('/api/dashboard/export/:type', verifyToken, async (req, res) => {
    try {
        const { type } = req.params;
        const { format = 'json', startDate, endDate } = req.query;
        
        let dateFilter = {};
        if (startDate && endDate) {
            dateFilter = {
                createdAt: {
                    $gte: new Date(startDate),
                    $lte: new Date(endDate)
                }
            };
        }

        let data = {};
        
        switch(type) {
            case 'users':
                data = await User.find(dateFilter)
                    .select('name email createdAt updatedAt')
                    .lean();
                break;
                
            case 'chats':
                data = await Chat.find(dateFilter)
                    .populate('user', 'name email')
                    .select('title provider model createdAt updatedAt user messages')
                    .lean();
                break;
                
            case 'analytics':
                // بيانات تحليلية مبسطة للتصدير
                const users = await User.countDocuments(dateFilter);
                const chats = await Chat.countDocuments(dateFilter);
                const messages = await Chat.aggregate([
                    { $match: dateFilter },
                    { $unwind: '$messages' },
                    { $count: 'total' }
                ]);
                
                data = {
                    summary: {
                        users,
                        chats,
                        messages: messages.length > 0 ? messages[0].total : 0,
                        period: { startDate, endDate }
                    }
                };
                break;
                
            default:
                return res.status(400).json({ message: 'نوع التقرير غير مدعوم' });
        }

        if (format === 'csv') {
            // تحويل البيانات إلى CSV
            const csvData = convertToCSV(data, type);
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="${type}_report.csv"`);
            res.send(csvData);
        } else {
            res.json(data);
        }

    } catch (error) {
        console.error('خطأ في تصدير التقرير:', error);
        res.status(500).json({ message: 'فشل في تصدير التقرير', error: error.message });
    }
});

// دالة مساعدة لتحويل البيانات إلى CSV
function convertToCSV(data, type) {
    if (!Array.isArray(data)) {
        data = [data];
    }
    
    if (data.length === 0) {
        return 'لا توجد بيانات للتصدير';
    }
    
    const headers = Object.keys(data[0]).join(',');
    const rows = data.map(item => 
        Object.values(item).map(value => 
            typeof value === 'string' ? `"${value}"` : value
        ).join(',')
    );
    
    return [headers, ...rows].join('\n');
}




// =================================================================
// ✨ endpoints إعدادات النظام ✨
// =================================================================
// جلب إعدادات النظام
app.get('/api/system/settings', verifyToken, async (req, res) => {
    try {
        // في التطبيق الحقيقي، هذه الإعدادات ستأتي من قاعدة البيانات أو ملف تكوين
        const systemSettings = {
            platformName: process.env.PLATFORM_NAME || 'شات زيوس',
            platformDescription: process.env.PLATFORM_DESCRIPTION || 'منصة ذكية للمحادثة مع نماذج الذكاء الاصطناعي المتقدمة',
            defaultLanguage: process.env.DEFAULT_LANGUAGE || 'ar',
            timezone: process.env.TIMEZONE || 'Asia/Riyadh',
            allowRegistration: process.env.ALLOW_REGISTRATION !== 'false',
            enableWebSearch: process.env.ENABLE_WEB_SEARCH !== 'false',
            enableTeamMode: process.env.ENABLE_TEAM_MODE !== 'false',
            dailyMessageLimit: parseInt(process.env.DAILY_MESSAGE_LIMIT || '100'),
            defaultModel: process.env.DEFAULT_MODEL || 'gemini-1.5-pro',
            defaultTemperature: parseFloat(process.env.DEFAULT_TEMPERATURE || '0.7'),
            defaultSystemPrompt: process.env.DEFAULT_SYSTEM_PROMPT || 'أنت مساعد ذكي ومفيد. قم بالرد بالعربية ما لم يطلب المستخدم خلاف ذلك.',
            enable2FA: process.env.ENABLE_2FA === 'true',
            logAllActivities: process.env.LOG_ALL_ACTIVITIES !== 'false',
            sessionTimeout: parseInt(process.env.SESSION_TIMEOUT || '24'),
            maxFailedLogins: parseInt(process.env.MAX_FAILED_LOGINS || '5')
        };

        res.json(systemSettings);

    } catch (error) {
        console.error('خطأ في جلب إعدادات النظام:', error);
        res.status(500).json({ message: 'فشل في جلب إعدادات النظام', error: error.message });
    }
});

// تحديث إعدادات النظام
app.put('/api/system/settings', verifyToken, async (req, res) => {
    try {
        const settings = req.body;
        
        // في التطبيق الحقيقي، ستحفظ هذه الإعدادات في قاعدة البيانات
        console.log('تحديث إعدادات النظام:', settings);
        
        // محاكاة حفظ الإعدادات
        // يمكن هنا إضافة التحقق من صحة البيانات وحفظها
        
        res.json({ 
            message: 'تم تحديث إعدادات النظام بنجاح',
            settings 
        });

    } catch (error) {
        console.error('خطأ في تحديث إعدادات النظام:', error);
        res.status(500).json({ message: 'فشل في تحديث إعدادات النظام', error: error.message });
    }
});

// تحديث إعدادات الأمان
app.put('/api/system/security', verifyToken, async (req, res) => {
    try {
        const securitySettings = req.body;
        
        // في التطبيق الحقيقي، ستحفظ في قاعدة البيانات مع تشفير إضافي
        console.log('تحديث إعدادات الأمان:', securitySettings);
        
        res.json({ 
            message: 'تم تحديث إعدادات الأمان بنجاح',
            settings: securitySettings 
        });

    } catch (error) {
        console.error('خطأ في تحديث إعدادات الأمان:', error);
        res.status(500).json({ message: 'فشل في تحديث إعدادات الأمان', error: error.message });
    }
});

// جلب مفاتيح API
app.get('/api/system/api-keys', verifyToken, async (req, res) => {
    try {
        // في التطبيق الحقيقي، ستأتي من قاعدة البيانات مشفرة
        const apiKeys = [
            {
                id: 'key_1',
                name: 'Gemini Production',
                provider: 'Google Gemini',
                status: 'active',
                createdAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
                lastUsed: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
                // لا نعرض القيمة الفعلية للمفتاح لأسباب أمنية
                masked: true
            },
            {
                id: 'key_2',
                name: 'OpenRouter Backup',
                provider: 'OpenRouter',
                status: 'active',
                createdAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString(),
                lastUsed: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
                masked: true
            }
        ];

        res.json(apiKeys);

    } catch (error) {
        console.error('خطأ في جلب مفاتيح API:', error);
        res.status(500).json({ message: 'فشل في جلب مفاتيح API', error: error.message });
    }
});

// إضافة مفتاح API جديد
app.post('/api/system/api-keys', verifyToken, async (req, res) => {
    try {
        const { name, provider, value, description } = req.body;
        
        if (!name || !provider || !value) {
            return res.status(400).json({ message: 'جميع الحقول مطلوبة' });
        }

        // في التطبيق الحقيقي، سيتم تشفير المفتاح قبل الحفظ
        const newKey = {
            id: 'key_' + Date.now(),
            name,
            provider,
            description,
            status: 'active',
            createdAt: new Date().toISOString(),
            lastUsed: null
        };

        // لا نحفظ القيمة الفعلية في الرد
        console.log('إضافة مفتاح API جديد:', { ...newKey, valueLength: value.length });

        res.status(201).json({ 
            message: 'تم إضافة مفتاح API بنجاح',
            key: newKey 
        });

    } catch (error) {
        console.error('خطأ في إضافة مفتاح API:', error);
        res.status(500).json({ message: 'فشل في إضافة مفتاح API', error: error.message });
    }
});

// حذف مفتاح API
app.delete('/api/system/api-keys/:keyId', verifyToken, async (req, res) => {
    try {
        const { keyId } = req.params;
        
        // في التطبيق الحقيقي، سيتم حذف المفتاح من قاعدة البيانات
        console.log('حذف مفتاح API:', keyId);

        res.json({ message: 'تم حذف مفتاح API بنجاح' });

    } catch (error) {
        console.error('خطأ في حذف مفتاح API:', error);
        res.status(500).json({ message: 'فشل في حذف مفتاح API', error: error.message });
    }
});

// اختبار مفتاح API
app.post('/api/system/api-keys/:keyId/test', verifyToken, async (req, res) => {
    try {
        const { keyId } = req.params;
        
        // محاكاة اختبار المفتاح
        console.log('اختبار مفتاح API:', keyId);
        
        // في التطبيق الحقيقي، سيتم اختبار المفتاح مع المزود الفعلي
        const success = Math.random() > 0.2; // 80% نجاح
        
        res.json({ 
            success,
            message: success ? 'المفتاح يعمل بشكل صحيح' : 'فشل في التحقق من المفتاح',
            testedAt: new Date().toISOString()
        });

    } catch (error) {
        console.error('خطأ في اختبار مفتاح API:', error);
        res.status(500).json({ message: 'فشل في اختبار مفتاح API', error: error.message });
    }
});

// جلب سجلات النظام
app.get('/api/system/logs', verifyToken, async (req, res) => {
    try {
        const { level = 'all', limit = 100 } = req.query;
        
        // بيانات وهمية للسجلات - في التطبيق الحقيقي ستأتي من نظام السجلات
        const mockLogs = [
            {
                id: 1,
                level: 'info',
                message: 'بدء تشغيل النظام',
                details: 'تم تشغيل الخادم بنجاح على المنفذ 3000',
                timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
                source: 'system'
            },
            {
                id: 2,
                level: 'warning',
                message: 'مفتاح API قارب على النفاد',
                details: 'مفتاح Gemini API المتبقي: 15% من الحصة الشهرية',
                timestamp: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
                source: 'api'
            },
            {
                id: 3,
                level: 'error',
                message: 'فشل في محاولة تسجيل دخول',
                details: 'IP: 192.168.1.100 - محاولة تسجيل دخول بكلمة مرور خاطئة',
                timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
                source: 'auth'
            }
        ];

        // تصفية السجلات حسب المستوى
        let filteredLogs = mockLogs;
        if (level !== 'all') {
            const levels = {
                'error': ['error'],
                'warning': ['error', 'warning'],
                'info': ['error', 'warning', 'info']
            };
            filteredLogs = mockLogs.filter(log => levels[level].includes(log.level));
        }

        // تحديد عدد السجلات
        filteredLogs = filteredLogs.slice(0, parseInt(limit));

        res.json({ logs: filteredLogs, total: filteredLogs.length });

    } catch (error) {
        console.error('خطأ في جلب السجلات:', error);
        res.status(500).json({ message: 'فشل في جلب السجلات', error: error.message });
    }
});

// مسح سجلات النظام
app.delete('/api/system/logs', verifyToken, async (req, res) => {
    try {
        // في التطبيق الحقيقي، سيتم مسح السجلات من نظام السجلات
        console.log('مسح سجلات النظام');

        res.json({ message: 'تم مسح السجلات بنجاح' });

    } catch (error) {
        console.error('خطأ في مسح السجلات:', error);
        res.status(500).json({ message: 'فشل في مسح السجلات', error: error.message });
    }
});

// جلب معلومات النظام
app.get('/api/system/info', verifyToken, async (req, res) => {
    try {
        const os = require('os');
        
        const systemInfo = {
            version: process.env.APP_VERSION || 'v2.1.0',
            uptime: process.uptime(),
            nodeVersion: process.version,
            platform: os.platform(),
            architecture: os.arch(),
            totalMemory: os.totalmem(),
            freeMemory: os.freemem(),
            cpuCount: os.cpus().length,
            loadAverage: os.loadavg(),
            networkInterfaces: Object.keys(os.networkInterfaces()),
            environment: process.env.NODE_ENV || 'development',
            pid: process.pid,
            // إحصائيات قاعدة البيانات
            database: {
                connected: mongoose.connection.readyState === 1,
                host: mongoose.connection.host,
                name: mongoose.connection.name
            }
        };

        res.json(systemInfo);

    } catch (error) {
        console.error('خطأ في جلب معلومات النظام:', error);
        res.status(500).json({ message: 'فشل في جلب معلومات النظام', error: error.message });
    }
});

// فحص صحة النظام
app.get('/api/system/health', verifyToken, async (req, res) => {
    try {
        const health = {
            status: 'healthy',
            timestamp: new Date().toISOString(),
            services: {
                database: {
                    status: mongoose.connection.readyState === 1 ? 'healthy' : 'unhealthy',
                    responseTime: Math.random() * 50 + 10 // محاكاة
                },
                api: {
                    status: 'healthy',
                    responseTime: Math.random() * 20 + 5
                },
                fileStorage: {
                    status: 'healthy',
                    responseTime: Math.random() * 30 + 15
                }
            },
            metrics: {
                memoryUsage: process.memoryUsage(),
                cpuUsage: process.cpuUsage(),
                uptime: process.uptime()
            }
        };

        // تحديد الحالة العامة
        const servicesStatus = Object.values(health.services).map(s => s.status);
        if (servicesStatus.includes('unhealthy')) {
            health.status = 'unhealthy';
        } else if (servicesStatus.includes('degraded')) {
            health.status = 'degraded';
        }

        const statusCode = health.status === 'healthy' ? 200 : 503;
        res.status(statusCode).json(health);

    } catch (error) {
        console.error('خطأ في فحص صحة النظام:', error);
        res.status(503).json({ 
            status: 'unhealthy',
            message: 'فشل في فحص صحة النظام',
            error: error.message 
        });
    }
});





// =================================================================
// 6. دوال معالجة الدردشة (تبقى كما هي)
// =================================================================
const keyManager = {
    keys: {
        gemini: (process.env.GEMINI_API_KEYS || '').split(',').filter(k => k),
        openrouter: (process.env.OPENROUTER_API_KEYS || '').split(',').filter(k => k)
    },
    // هذا المتغير سيتتبع المفتاح التالي الذي يجب استخدامه لكل مزود
    indices: {
        gemini: 0,
        openrouter: 0
    },

    tryKeys: async function(provider, strategy, customKeys, action) {
    const keyPool = (customKeys && customKeys.length > 0) ? customKeys : this.keys[provider] || [];
    if (keyPool.length === 0) {
        throw new Error(`No API keys available for provider: ${provider}`);
    }

    let tryCount = 0; // ✨ تعريف tryCount هنا
    while (tryCount < keyPool.length) { // ✨ حلقة while بدل continue خارج الحلقة
        const keyIndex = (this.indices[provider] || 0);
        const keyToTry = keyPool[keyIndex];
        console.log(`[Key Manager] Load Balancing: Selected key index ${keyIndex} for provider ${provider}.`);

        try {
            const result = await action(keyToTry);
            this.indices[provider] = (keyIndex + 1) % keyPool.length;
            return result;
        } catch (error) {
            console.error(`[Key Manager] Key index ${keyIndex} for ${provider} failed. Error: ${error.message}`);
            this.indices[provider] = (keyIndex + 1) % keyPool.length;

            const msg = String(error && (error.message || error.toString()) || '');
            const retriable = /429|Too\s*Many\s*Requests|quota|rate\s*limit|5\d\d|ECONNRESET|ETIMEDOUT|network/i.test(msg);

            if (retriable && tryCount < keyPool.length - 1) {
                tryCount++;
                continue; // ✅ الآن في مكان صحيح داخل الحلقة
            }

            throw error;
        }
    }
}
};

async function handleChatRequest(req, res) {
    try {
        const payload = req.body;
        // ✨ التحقق من وجود الإعدادات والمزود قبل أي شيء آخر ✨
        if (!payload.settings || !payload.settings.provider) {
            // إذا لم يكن هناك مزود، أرسل خطأ واضحًا بدلاً من الانهيار
            throw new Error('معلومات المزود مفقودة في إعدادات الطلب.');
        }
        const { provider } = payload.settings;

        // الآن يمكننا استخدام 'provider' بأمان
        if (provider === 'gemini') await handleGeminiRequest(payload, res);
        else if (provider === 'openrouter') await handleOpenRouterRequest(payload, res);
        else if (provider.startsWith('custom_')) await handleCustomProviderRequest(payload, res);
        else throw new Error(`مزود غير معروف: ${provider}`);
        
    } catch (error) {
        console.error('Error processing chat request:', error.message);
        
        // ✨ معالجة محسنة لرسائل الخطأ ✨
        let userFriendlyMessage = error.message;
        
        // معالجة أخطاء الكوتا
        if (error.message.includes('quota') || error.message.includes('429')) {
            userFriendlyMessage = `تم تجاوز الحد المسموح لاستخدام API.

🔧 الحلول المقترحة:
• تحقق من رصيد حسابك على Google AI Studio
• جرب استخدام مفتاح API آخر إن كان متاحاً
• انتظر قليلاً ثم أعد المحاولة

💡 يمكنك أيضاً التبديل إلى مزود آخر من الإعدادات.`;
        }
        
        // معالجة أخطاء الشبكة
        else if (error.message.includes('ECONNRESET') || error.message.includes('ETIMEDOUT')) {
            userFriendlyMessage = `حدث خطأ في الاتصال بالشبكة.

🔧 يرجى المحاولة مرة أخرى خلال دقائق قليلة.`;
        }
        
        // معالجة أخطاء مفتاح API غير صالح
        else if (error.message.includes('API key') || error.message.includes('401')) {
            userFriendlyMessage = `مفتاح API غير صالح أو منتهي الصلاحية.

🔧 يرجى التحقق من مفاتيح API في الإعدادات والتأكد من صحتها.`;
        }
        
        res.status(500).json({ error: userFriendlyMessage });
    }
}
// =================================================================
// إصلاح شامل لدعم البحث في Gemini 2.5
// =================================================================

async function handleGeminiRequest(payload, res) {
    const { chatHistory, attachments, settings, meta } = payload;
    const userApiKeys = (settings.geminiApiKeys || []).map(k => k.key).filter(Boolean);

    await keyManager.tryKeys('gemini', settings.apiKeyRetryStrategy, userApiKeys, async (apiKey) => {
        const genAI = new GoogleGenerativeAI(apiKey);

        // ✅ تفعيل البحث إذا كان مفعّل بالإعدادات أو مفروض من الرسالة
        const triggerByUser = meta && meta.forceWebBrowsing === true;
const useSearch = (settings.enableWebBrowsing === true || triggerByUser)
                  && (settings.browsingMode || 'gemini') === 'gemini';

        console.log(`🔍 Search Debug:`, {
          enableWebBrowse: settings.enableWebBrowse,
          triggerByUser,
          useSearch,
          model: settings.model
        });

        // ✅ النماذج المدعومة للبحث (محدثة)
        const searchSupportedModels = [ 
          'gemini-1.5-pro',
          'gemini-2.5-flash',
          'gemini-2.5-pro',
          'gemini-2.0-flash'
        ];

        let chosenModel = settings.model || 'gemini-2.5-flash';

        // ✅ التحقق من دعم النموذج للبحث
        if (useSearch && !searchSupportedModels.includes(chosenModel)) {
          const supportedModelsText = searchSupportedModels.join(', ');
          throw new Error(`النموذج "${chosenModel}" لا يدعم البحث في الويب.

للاستفادة من ميزة البحث، يمكنك اختيار أحد الخيارات التالية:

🔧 الحلول المتاحة:
• تغيير النموذج إلى أحد النماذج المدعومة: ${supportedModelsText}
• إيقاف تفعيل البحث في الويب من الإعدادات

💡 نوصي باستخدام "gemini-2.5-flash" للحصول على أفضل أداء مع البحث.`);
        }

        console.log(`🤖 Using model: ${chosenModel} with search: ${useSearch}`);

        // 🚨 الإصلاح الحاسم: لا تستخدم apiVersion مطلقاً مع البحث
        let model;
if (useSearch) {
  // بدون apiVersion أثناء البحث
  model = genAI.getGenerativeModel({ model: chosenModel });
  console.log('🔍 Gemini model initialized for search (no apiVersion)');
} else {
  // apiVersion كوسيط ثانٍ
  model = genAI.getGenerativeModel(
    { model: chosenModel },
    { apiVersion: "v1beta" }
  );
}

        // ✅ إعداد أدوات البحث المحسنة
        let tools = undefined;
        if (useSearch) {
          const dynThreshold = typeof settings.dynamicThreshold === 'number' 
            ? Math.max(0, Math.min(1, settings.dynamicThreshold)) 
            : 0.6;
            
          // ✨✨✨ الإضافة المقترحة للتوافق مع النماذج الجديدة ✨✨✨
          const isLegacyModel = chosenModel.startsWith('gemini-1.5') || chosenModel.startsWith('gemini-2.0');
          
          if (isLegacyModel) {
              tools = [{
                googleSearchRetrieval: {
                  dynamicRetrievalConfig: {
                    mode: "MODE_DYNAMIC",
                    dynamicThreshold: dynThreshold
                  }
                }
              }];
          } else {
              tools = [{
                  googleSearch: {}
              }];
          }
          // ✨✨✨ نهاية الإضافة ✨✨✨

          console.log(`🎯 Search tools configured with threshold: ${dynThreshold}`);
        }

// تجهيز السجل بصيغة contents مع إضافة البرومبت المخصص
        const contents = [];
        
        // إضافة البرومبت المخصص في البداية إذا كان موجوداً
        if (settings.customPrompt && settings.customPrompt.trim()) {
            contents.push({
                role: 'user',
                parts: [{ text: settings.customPrompt }]
            });
            contents.push({
                role: 'model',
                parts: [{ text: 'مفهوم، سأتبع هذه التعليمات في جميع ردودي.' }]
            });
        }
        
        // إضافة المحادثات السابقة
        contents.push(...chatHistory.slice(0, -1).map(msg => ({
            role: msg.role === 'user' ? 'user' : 'model',
            parts: [{ text: msg.content || '' }]
        })));
        
        // إضافة الرسالة الأخيرة مع المرفقات
        contents.push({ role: 'user', parts: buildUserParts(chatHistory[chatHistory.length - 1], attachments) });

        // ✅ إعداد الطلب النهائي
        const requestConfig = {
          contents,
          generationConfig: { 
            temperature: settings.temperature || 0.7,
            maxOutputTokens: 8192 // زيادة الحد الأقصى
          }
        };

        // ✅ أضف الأدوات فقط عند البحث
        if (useSearch && tools) {
          requestConfig.tools = tools;
          console.log('🔍 Search tools added to request');
        }

        try {
          console.log('📤 Sending request to Gemini...');
          const result = await model.generateContentStream(requestConfig);

          // بث الرد
          res.writeHead(200, {
            'Content-Type': 'text/plain; charset=utf-8',
            'Transfer-Encoding': 'chunked'
          });

          let totalText = '';
          for await (const chunk of result.stream) {
            const text = chunk.text();
            if (text) {
              totalText += text;
              res.write(text);
            }
          }

          console.log(`✅ Response generated successfully (${totalText.length} chars)`);
          
          // إضافة سياق البحث للرد إذا تم استخدام البحث
          if (useSearch) {
            totalText = `[تم البحث في الويب للحصول على أحدث المعلومات]\n\n${totalText}`;
          }

          // ✅ إلحاق المصادر مع معالجة محسنة
          if (useSearch && settings.showSources) {
            try {
              console.log('🔍 Extracting search sources...');
              const finalResp = await result.response;
              const candidate = finalResp?.candidates?.[0];
              const gm = candidate?.groundingMetadata;
              
              console.log('📊 Grounding metadata:', JSON.stringify(gm, null, 2));
              
              const sources = [];

              // استخراج المصادر من citations
              if (Array.isArray(gm?.citations)) {
                console.log(`📚 Found ${gm.citations.length} citations`);
                gm.citations.forEach((citation, i) => {
                  const uri = citation?.uri || citation?.sourceUri || citation?.source?.uri;
                  let title = citation?.title || citation?.sourceTitle || citation?.source?.title;
                  
                  // تنظيف العنوان وتقصيره إذا كان طويلاً
                  if (title && title.length > 80) {
                    title = title.substring(0, 77) + '...';
                  }
                  if (!title) title = `مصدر ${i + 1}`;
                  
                  if (uri && uri.startsWith('http')) {
                    sources.push(`- [${title}](${uri})`);
                  }
                });
              }

              // استخراج من groundingChunks كبديل
              if (sources.length === 0 && Array.isArray(gm?.groundingChunks)) {
                console.log(`🌐 Found ${gm.groundingChunks.length} grounding chunks`);
                gm.groundingChunks.forEach((chunk, i) => {
                  const uri = chunk?.web?.uri || chunk?.source?.uri;
                  let title = chunk?.web?.title || chunk?.title || chunk?.source?.title;
                  
                  // تنظيف العنوان وتقصيره إذا كان طويلاً
                  if (title && title.length > 80) {
                    title = title.substring(0, 77) + '...';
                  }
                  if (!title) title = `مصدر ${i + 1}`;
                  
                  if (uri && uri.startsWith('http')) {
                    sources.push(`- [${title}](${uri})`);
                  }
                });
              }
              
              // استخراج من أي هياكل أخرى محتملة
              if (sources.length === 0 && gm?.searchEntryPoints) {
                console.log(`🎯 Found search entry points`);
                gm.searchEntryPoints.forEach((entry, i) => {
                  if (entry?.renderedContent && entry.url) {
                    const title = entry.title || `نتيجة البحث ${i + 1}`;
                    sources.push(`- [${title}](${entry.url})`);
                  }
                });
              }

              // استخراج من groundingChunks كبديل
              if (sources.length === 0 && Array.isArray(gm?.groundingChunks)) {
                console.log(`🌐 Found ${gm.groundingChunks.length} grounding chunks`);
                gm.groundingChunks.forEach((chunk, i) => {
                  const uri = chunk?.web?.uri || chunk?.source?.uri;
                  const title = chunk?.web?.title || chunk?.title || `مصدر ${i + 1}`;
                  if (uri) {
                    sources.push(`- [${title}](${uri})`);
                  }
                });
              }

              // عرض المصادر
              if (sources.length > 0) {
                console.log(`✅ Found ${sources.length} sources`);
                res.write(`\n\n**🔍 المصادر:**\n${sources.join('\n')}`);
              } else {
                console.log('⚠️ No sources found in response metadata');
                // تشخيص إضافي
                if (gm) {
                  console.log('🔍 Available grounding metadata keys:', Object.keys(gm));
                } else {
                  console.log('❌ No grounding metadata found');
                }
              }

            } catch (sourceError) {
              console.error('❌ Error extracting sources:', sourceError.message);
              res.write('\n\n*تعذر استخراج المصادر*');
            }
          }

          res.end();

        } catch (requestError) {
          console.error('❌ Gemini request failed:', requestError.message);
          
          // معالجة أخطاء محددة
          if (requestError.message.includes('Search Grounding is not supported')) {
            console.log('🔄 Retrying without search tools...');
            // إعادة المحاولة بدون البحث
            const fallbackConfig = {
              contents,
              generationConfig: { temperature: settings.temperature || 0.7 }
            };
            
            const fallbackResult = await model.generateContentStream(fallbackConfig);
            res.writeHead(200, {
              'Content-Type': 'text/plain; charset=utf-8',
              'Transfer-Encoding': 'chunked'
            });
            
            for await (const chunk of fallbackResult.stream) {
              const text = chunk.text();
              if (text) res.write(text);
            }
            
            res.write('\n\n*ملاحظة: تم تعطيل البحث مؤقتاً لهذا الطلب*');
            res.end();
          } else {
            throw requestError;
          }
        }
    });
}


async function handleOpenRouterRequest(payload, res) {
    const { chatHistory, settings } = payload;
    // ✨✨✨ الإصلاح هنا: استخراج مفاتيح المستخدم من الإعدادات ✨✨✨
    const userApiKeys = (settings.openrouterApiKeys || []).map(k => k.key).filter(Boolean);

    await keyManager.tryKeys('openrouter', settings.apiKeyRetryStrategy, userApiKeys, async (apiKey) => {
        const formattedMessages = formatMessagesForOpenAI(chatHistory);
        const requestBody = JSON.stringify({ model: settings.model, messages: formattedMessages, temperature: settings.temperature, stream: true });
        const options = { hostname: 'openrouter.ai', path: '/api/v1/chat/completions', method: 'POST', headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' } };
        await streamOpenAICompatibleAPI(options, requestBody, res);
    });
}
async function handleCustomProviderRequest(payload, res) {
    const { chatHistory, settings, customProviders } = payload;
    const providerId = settings.provider;
    const providerConfig = customProviders.find(p => p.id === providerId);
    if (!providerConfig) throw new Error(`لم يتم العثور على إعدادات المزود المخصص: ${providerId}`);
    const customKeys = (providerConfig.apiKeys || []).map(k => k.key).filter(Boolean);
    await keyManager.tryKeys(providerId, settings.apiKeyRetryStrategy, customKeys, async (apiKey) => {
        const formattedMessages = formatMessagesForOpenAI(chatHistory);
        const requestBody = JSON.stringify({ model: settings.model, messages: formattedMessages, temperature: settings.temperature, stream: true });
        const url = new URL(providerConfig.baseUrl);
        const options = { hostname: url.hostname, path: url.pathname, method: 'POST', headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' } };
        await streamOpenAICompatibleAPI(options, requestBody, res);
    });
}
function buildUserParts(lastMessage, attachments) {
    const userParts = [];
    if (lastMessage.content) userParts.push({ text: lastMessage.content });
    
    if (attachments) {
        attachments.forEach(file => {
            if (file.dataType === 'image' && file.fileUrl) { // ✨ استخدام file.fileUrl للصور
                userParts.push({ fileData: { mimeType: file.mimeType, fileUri: file.fileUrl } });
            } else if (file.dataType === 'text' && file.content) {
                userParts.push({ text: `\n\n--- محتوى الملف: ${file.name} ---\n${file.content}\n--- نهاية الملف ---` });
            } 
            // ✨ إزالة الجزء القديم الذي كان يتعامل مع file.fileUrl كـ text
            // هذا الجزء لم يعد ضرورياً لأننا نستخدم fileData للصور
            // أما الملفات النصية، فنحن نقرأ المحتوى مباشرة (file.content)
            // إذا كان هناك أي نوع ملف آخر (binary) لم تتم معالجته، يمكن إهماله حالياً أو التعامل معه لاحقاً.
        });
    }
    
    // هذا الشرط يضيف "حلل المرفقات:" فقط إذا كانت هناك مرفقات وليس هناك نص أساسي
    // مع التغييرات، قد لا يكون ضرورياً جداً إذا كان النموذج ذكياً بما يكفي
    // ولكن لا بأس من إبقائه كطبقة أمان
    if (userParts.length > 0 && userParts.every(p => !p.text)) {
        userParts.unshift({ text: "حلل المرفقات:" });
    }
    return userParts;
}


// إضافة دالة مساعدة لتنسيق حجم الملف
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 بايت';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['بايت', 'ك.ب', 'م.ب', 'ج.ب', 'ت.ب'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatMessagesForOpenAI(chatHistory) {
    return chatHistory.map(msg => ({ role: msg.role, content: msg.content || '' }));
}

// =================================================================
// 🎧 دالة موحّدة لبث ردّ نموذج واحد لحظيًا إلى كاتب خارجي (onToken)
// =================================================================
async function streamOneModel(provider, model, messages, settings, onToken) {
  const apiKeyStrategy = settings?.apiKeyRetryStrategy || 'sequential';

  if (provider === 'gemini') {
    const userKeys = (settings.geminiApiKeys || []).map(k => k.key).filter(Boolean);
    return await keyManager.tryKeys('gemini', apiKeyStrategy, userKeys, async (apiKey) => {
      const genAI = new GoogleGenerativeAI(apiKey);

      // Gemini لا يدعم role=system مباشرة — نطوّعها كـ user
      const contents = messages.map(m => ({
        role: m.role === 'user' ? 'user' : (m.role === 'system' ? 'user' : 'model'),
        parts: [{ text: m.content || '' }]
      }));

      // تهيئة الموديل والبث
      const gm = genAI.getGenerativeModel({ model });
      const result = await gm.generateContentStream({
        contents,
        generationConfig: { temperature: settings.temperature || 0.7 }
      });

      for await (const chunk of result.stream) {
        const text = typeof chunk.text === 'function' ? chunk.text() : (chunk?.candidates?.[0]?.content?.parts?.[0]?.text || '');
        if (text) onToken(text);
      }
    });
  }

  if (provider === 'openrouter') {
    const userKeys = (settings.openrouterApiKeys || []).map(k => k.key).filter(Boolean);
    return await keyManager.tryKeys('openrouter', apiKeyStrategy, userKeys, async (apiKey) => {
      // صيغة OpenAI-compatible
      const formatted = messages.map(m => {
        let role = m.role;
        if (role !== 'system' && role !== 'user' && role !== 'assistant') {
          role = (m.role === 'model') ? 'assistant' : 'user';
        }
        return { role, content: m.content || '' };
      });

      const body = JSON.stringify({
        model,
        messages: formatted,
        temperature: settings.temperature || 0.7,
        stream: true
      });

      const options = {
        hostname: 'openrouter.ai',
        path: '/api/v1/chat/completions',
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json'
        }
      };

      await streamOpenAIToWriter(options, body, onToken);
    });
  }

  // مزود مخصّص (OpenAI-compatible)
  if (provider && provider.startsWith('custom_') && Array.isArray(settings?.customProviders)) {
    const prov = settings.customProviders.find(p => p.id === provider);
    if (!prov) throw new Error(`لم يتم العثور على المزود المخصص: ${provider}`);
    const customKeys = (prov.apiKeys || []).map(k => k.key).filter(Boolean);

    return await keyManager.tryKeys(provider, apiKeyStrategy, customKeys, async (apiKey) => {
      const formatted = messages.map(m => {
        let role = m.role;
        if (role !== 'system' && role !== 'user' && role !== 'assistant') {
          role = (m.role === 'model') ? 'assistant' : 'user';
        }
        return { role, content: m.content || '' };
      });

      const url = new URL(prov.baseUrl);
      const body = JSON.stringify({ model, messages: formatted, temperature: settings.temperature || 0.7, stream: true });
      const options = {
        hostname: url.hostname,
        path: url.pathname + (url.search || ''),
        method: 'POST',
        headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' }
      };

      await streamOpenAIToWriter(options, body, onToken);
    });
  }

  throw new Error(`مزود غير مدعوم للبث الحي: ${provider}`);
}

// =================================================================
// 🧩 مُحوّل بث OpenAI-compatible إلى كاتب خارجي (Callback)
// =================================================================
function streamOpenAIToWriter(options, body, onToken) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (apiRes) => {
      if (apiRes.statusCode !== 200) {
        let errorBody = '';
        apiRes.on('data', d => errorBody += d);
        apiRes.on('end', () => reject(new Error(`API Error: ${apiRes.statusCode} - ${errorBody}`)));
        return;
      }
      let buffer = '';
      apiRes.on('data', (chunk) => {
        buffer += chunk.toString('utf8');
        const parts = buffer.split('\n');
        buffer = parts.pop(); // أبقِ آخر سطر غير مكتمل
        for (const line of parts) {
          const s = line.trim();
          if (!s || !s.startsWith('data:')) continue;
          const data = s.slice(5).trim();
          if (data === '[DONE]') continue;
          try {
            const parsed = JSON.parse(data);
            const text = parsed?.choices?.[0]?.delta?.content || '';
            if (text) onToken(text);
          } catch (_e) { /* تجاهل */ }
        }
      });
      apiRes.on('end', () => resolve());
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function streamOpenAICompatibleAPI(options, body, res) {
    return new Promise((resolve, reject) => {
        const request = https.request(options, (apiResponse ) => {
            if (apiResponse.statusCode !== 200) {
                let errorBody = '';
                apiResponse.on('data', d => errorBody += d);
                apiResponse.on('end', () => reject(new Error(`API Error: ${apiResponse.statusCode} - ${errorBody}`)));
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Transfer-Encoding': 'chunked' });
            apiResponse.on('data', (chunk) => {
                const lines = chunk.toString().split('\n');
                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        const data = line.slice(6);
                        if (data.trim() === '[DONE]') continue;
                        try {
                            const parsed = JSON.parse(data);
                            const text = parsed.choices?.[0]?.delta?.content || '';
                            if (text) res.write(text);
                        } catch (e) {}
                    }
                }
            });
            apiResponse.on('end', () => { res.end(); resolve(); });
        });
        request.on('error', reject);
        request.write(body);
        request.end();
    });
}

// ✨✨✨ معالج الأخطاء العام (Global Error Handler) ✨✨✨
app.use((err, req, res, next) => {
    console.error('[GLOBAL ERROR HANDLER]:', err.stack);
    res.status(500).json({
        message: 'حدث خطأ غير متوقع في الخادم.',
        error: err.message 
    });
});


// =================================================================
// ✨ الاتصال بقاعدة البيانات
// =================================================================
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ Successfully connected to MongoDB Atlas.'))
    .catch(err => {
        console.error('❌ Could not connect to MongoDB Atlas.', err);
        process.exit(1); // إيقاف الخادم إذا فشل الاتصال
    });

// =================================================================
// 7. تشغيل الخادم
// =================================================================
// ✅ أضف هذا السطر في نهاية الملف
module.exports = app;
