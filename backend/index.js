
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
const AdmZip = require('adm-zip'); // إضافة مكتبة فك الضغط

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
// 🧪 TEST AUTH API (للاختبار فقط)
// =========================================================
app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email) return res.status(400).json({ message: "البريد الإلكتروني مطلوب" });

        // بما أن هذا للاختبار، سنبحث عن المستخدم أو ننشئه إذا لم يكن موجوداً
        // كلمة المرور لا يتم التحقق منها فعلياً هنا لتسريع الاختبار
        
        let user = await User.findOne({ email });
        let role = 'user';
        
        // منح صلاحيات الأدمن لهذا الإيميل تلقائياً للاختبار
        if (email === ADMIN_EMAIL) {
            role = 'admin';
        }

        if (!user) {
            // إنشاء مستخدم جديد للاختبار
            user = new User({
                googleId: `test_${Date.now()}`, // Fake ID
                email: email,
                name: email.split('@')[0], // الاسم من الإيميل
                picture: '',
                role: role,
                createdAt: new Date()
            });
            await user.save();
            await new Settings({ user: user._id }).save();
        }

        // إنشاء التوكن
        const payload = { id: user._id, googleId: user.googleId, name: user.name, email: user.email, role: user.role };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '365d' });

        res.json({ token, user });
    } catch (error) {
        console.error("Test Login Error:", error);
        res.status(500).json({ error: error.message });
    }
});

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
// 🚀 BULK UPLOAD API (النشر المتعدد)
// =========================================================
app.post('/api/admin/chapters/bulk-upload', verifyAdmin, upload.single('zip'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ message: "No ZIP file uploaded" });
        const { novelId } = req.body;
        
        if (!novelId) return res.status(400).json({ message: "Novel ID required" });

        const novel = await Novel.findById(novelId);
        if (!novel) return res.status(404).json({ message: "Novel not found" });

        // التحقق من الصلاحية
        if (req.user.role !== 'admin') {
            if (novel.authorEmail !== req.user.email) {
                return res.status(403).json({ message: "لا تملك صلاحية النشر لهذه الرواية" });
            }
        }

        // فك الضغط
        const zip = new AdmZip(req.file.buffer);
        const zipEntries = zip.getEntries(); // an array of ZipEntry records
        
        let successCount = 0;
        let errors = [];
        
        // استخدام Batch للكتابة في Firebase لتحسين الأداء (أو حلقة متتابعة)
        // سنستخدم حلقة متتابعة لضمان التحديث الصحيح في Mongo
        
        for (const entry of zipEntries) {
            if (entry.isDirectory || !entry.entryName.endsWith('.txt')) continue;

            try {
                // 1. استخراج رقم الفصل من اسم الملف (مثال: 10.txt)
                const fileName = path.basename(entry.entryName, '.txt');
                const chapterNumber = parseInt(fileName);

                if (isNaN(chapterNumber)) {
                    errors.push(`تخطي الملف ${entry.entryName}: الاسم ليس رقماً`);
                    continue;
                }

                // 2. قراءة المحتوى
                const fullText = zip.readAsText(entry, 'utf8'); // تأكد من استخدام UTF8
                const lines = fullText.split('\n');
                
                if (lines.length === 0) continue;

                // 3. استخراج العنوان (السطر الأول بعد النقطتين)
                const firstLine = lines[0].trim();
                let chapterTitle = firstLine;
                
                // البحث عن أول نقطتين (:) وأخذ ما بعدها
                const colonIndex = firstLine.indexOf(':');
                if (colonIndex > -1) {
                    chapterTitle = firstLine.substring(colonIndex + 1).trim();
                }
                
                // إذا كان العنوان فارغاً بعد القص، استخدم السطر كاملاً كاحتياط
                if (!chapterTitle) chapterTitle = firstLine;

                // باقي النص هو المحتوى
                const content = lines.slice(1).join('\n').trim();

                // 4. الحفظ في Firebase Firestore (المحتوى فقط)
                if (firestore) {
                    await firestore.collection('novels').doc(novelId).collection('chapters').doc(chapterNumber.toString()).set({
                        title: chapterTitle,
                        content: content,
                        lastUpdated: new Date()
                    });
                } else {
                    throw new Error("Firebase not configured");
                }

                // 5. تحديث الميتا داتا في MongoDB (بدون المحتوى)
                const chapterMeta = { 
                    number: chapterNumber, 
                    title: chapterTitle, 
                    createdAt: new Date(), 
                    views: 0 
                };

                const existingIndex = novel.chapters.findIndex(c => c.number === chapterNumber);
                if (existingIndex > -1) {
                    // تحديث الفصل الموجود
                    novel.chapters[existingIndex].title = chapterTitle;
                } else {
                    // إضافة فصل جديد
                    novel.chapters.push(chapterMeta);
                }

                successCount++;

            } catch (err) {
                console.error(`Error processing ${entry.entryName}:`, err);
                errors.push(`خطأ في ملف ${entry.entryName}`);
            }
        }

        if (successCount > 0) {
            // ترتيب الفصول بعد الإضافة
            novel.chapters.sort((a, b) => a.number - b.number);
            
            novel.lastChapterUpdate = new Date();
            if (novel.status === 'متوقفة') novel.status = 'مستمرة';
            
            await novel.save();
        }

        res.json({ 
            message: `تمت المعالجة. نجح: ${successCount}، فشل: ${errors.length}`,
            errors: errors,
            successCount
        });

    } catch (error) {
        console.error("Bulk Upload Error:", error);
        res.status(500).json({ error: error.message });
    }
});


// =========================================================
// 👤 USER PROFILE API
// =========================================================

// Update Profile Info
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

// Get User Profile with Stats
app.get('/api/user/stats', verifyToken, async (req, res) => {
    try {
        // Determine target user (Current user OR requested public profile)
        let targetUserId = req.user.id;
        let targetUser = null;

        if (req.query.userId) {
            targetUserId = req.query.userId;
            targetUser = await User.findById(targetUserId);
        } else if (req.query.email) {
            targetUser = await User.findOne({ email: req.query.email });
            if (targetUser) targetUserId = targetUser._id;
        } else {
            targetUser = await User.findById(targetUserId);
        }

        if (!targetUser) return res.status(404).json({ message: "User not found" });

        // 1. Calculate Read Chapters
        const libraryStats = await NovelLibrary.aggregate([
            { $match: { user: new mongoose.Types.ObjectId(targetUserId) } },
            { $group: { _id: null, totalRead: { $sum: "$maxReadChapterId" } } }
        ]);
        const totalReadChapters = libraryStats[0] ? libraryStats[0].totalRead : 0;

        let addedChapters = 0;
        let totalViews = 0;
        let myWorks = [];

        // 2. Calculate Contributor Stats (If Contributor/Admin)
        // Check works by Email (Preferred) or Name
        myWorks = await Novel.find({ 
            $or: [
                { authorEmail: targetUser.email },
                { author: { $regex: new RegExp(`^${targetUser.name}$`, 'i') } } 
            ]
        });
        
        myWorks.forEach(novel => {
            addedChapters += (novel.chapters ? novel.chapters.length : 0);
            totalViews += (novel.views || 0);
        });
        
        // Return Public Data Structure
        res.json({
            user: {
                _id: targetUser._id,
                name: targetUser.name,
                email: targetUser.email, // Added Email for Admin View
                picture: targetUser.picture,
                banner: targetUser.banner,
                bio: targetUser.bio,
                role: targetUser.role,
                createdAt: targetUser.createdAt,
                isHistoryPublic: targetUser.isHistoryPublic
            },
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
// 👑 USERS MANAGEMENT API (ADMIN ONLY)
// =========================================================

// Get All Users
app.get('/api/admin/users', verifyAdmin, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Access Denied" });
    try {
        const users = await User.find({}).sort({ createdAt: -1 });
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update User Role
app.put('/api/admin/users/:id/role', verifyAdmin, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Access Denied" });
    try {
        const { role } = req.body;
        if (!['user', 'contributor', 'admin'].includes(role)) return res.status(400).json({message: "Invalid role"});
        
        const user = await User.findByIdAndUpdate(req.params.id, { role }, { new: true });
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete User
app.delete('/api/admin/users/:id', verifyAdmin, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Access Denied" });
    try {
        // Prevent deleting self
        if (req.params.id === req.user.id) return res.status(400).json({message: "Cannot delete yourself"});

        await User.findByIdAndDelete(req.params.id);
        // Optional: Clean up user data like library, etc.
        await NovelLibrary.deleteMany({ user: req.params.id });
        await Settings.deleteMany({ user: req.params.id });
        
        res.json({ message: "User deleted" });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =========================================================
// 🗑️ ADMIN API
// =========================================================
app.post('/api/admin/nuke', verifyAdmin, async (req, res) => {
    // SECURITY CHECK: Only Admin can nuke
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: "Access Denied: Admins Only" });
    }

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
        const { title, cover, description, category, tags, status } = req.body;
        
        // Use logged-in user details for author
        const authorName = req.user.name;
        const authorEmail = req.user.email;

        const newNovel = new Novel({
            title, 
            cover, 
            description, 
            author: authorName, // Auto-filled
            authorEmail: authorEmail, // Auto-filled
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
        const { title, cover, description, category, tags, status } = req.body;
        
        const novel = await Novel.findById(req.params.id);
        if (!novel) return res.status(404).json({ message: "Novel not found" });

        // SECURITY CHECK: Ownership or Admin
        if (req.user.role !== 'admin') {
            if (novel.authorEmail !== req.user.email) {
                return res.status(403).json({ message: "لا تملك صلاحية تعديل هذه الرواية" });
            }
        }

        let updateData = { title, cover, description, category, tags, status };

        // 🔥 Transfer ownership if Admin edits (as requested)
        if (req.user.role === 'admin') {
            updateData.author = req.user.name;
            updateData.authorEmail = req.user.email;
        }
        
        const updated = await Novel.findByIdAndUpdate(req.params.id, updateData, { new: true });
        res.json(updated);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/novels/:id', verifyAdmin, async (req, res) => {
    try {
        const novelId = req.params.id;
        const novel = await Novel.findById(novelId);
        if (!novel) return res.status(404).json({ message: "Novel not found" });

        // SECURITY CHECK: Ownership or Admin
        if (req.user.role !== 'admin') {
            if (novel.authorEmail !== req.user.email) {
                return res.status(403).json({ message: "لا تملك صلاحية حذف هذه الرواية" });
            }
        }

        // 1. Delete content from Firestore (Chapters)
        // يتم حذف جميع المستندات في المجموعة الفرعية 'chapters' المرتبطة بالرواية
        if (firestore) {
            try {
                const chaptersRef = firestore.collection('novels').doc(novelId).collection('chapters');
                const snapshot = await chaptersRef.get();
                
                // Firestore لا يدعم حذف المجموعة مباشرة، يجب حذف المستندات داخلها
                if (!snapshot.empty) {
                    const deletePromises = snapshot.docs.map(doc => doc.ref.delete());
                    await Promise.all(deletePromises);
                }
                
                // حذف مستند الرواية نفسه من Firestore
                await firestore.collection('novels').doc(novelId).delete();
                console.log(`✅ Deleted Firestore content for novel: ${novelId}`);
            } catch (fsError) {
                console.error("❌ Firestore deletion error:", fsError);
                // لا نوقف العملية، نستمر بحذف البيانات من MongoDB
            }
        }

        // 2. Delete from MongoDB
        await Novel.findByIdAndDelete(novelId);
        
        // 3. Delete from User Libraries
        await NovelLibrary.deleteMany({ novelId: novelId });
        
        res.json({ message: "Deleted successfully (DB + Content)" });
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

        // SECURITY CHECK: Ownership or Admin
        if (req.user.role !== 'admin') {
            if (novel.authorEmail !== req.user.email) {
                return res.status(403).json({ message: "لا تملك صلاحية الإضافة لهذه الرواية" });
            }
        }

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

        // SECURITY CHECK: Ownership or Admin
        if (req.user.role !== 'admin') {
            if (novel.authorEmail !== req.user.email) {
                return res.status(403).json({ message: "لا تملك صلاحية تعديل هذا الفصل" });
            }
        }

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
        if (!novel) return res.status(404).json({ message: "Novel not found" });

        // SECURITY CHECK: Ownership or Admin
        if (req.user.role !== 'admin') {
            if (novel.authorEmail !== req.user.email) {
                return res.status(403).json({ message: "لا تملك صلاحية حذف هذا الفصل" });
            }
        }
        
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
        const { type, userId } = req.query; 
        
        let targetId = req.user.id;
        
        // Handle viewing other user's library
        if (userId) {
            const targetUser = await User.findById(userId);
            if (!targetUser) return res.status(404).json({ message: "User not found" });
            
            // Check privacy: If not self AND history is private -> return empty
            // Note: Favorites might be considered public usually, but History should be guarded
            if (userId !== req.user.id && !targetUser.isHistoryPublic && type === 'history') {
                 return res.json([]); 
            }
            targetId = userId;
        }

        let query = { user: targetId };
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

// =========================================================
// 🔔 NOTIFICATIONS API
// =========================================================
app.get('/api/notifications', verifyToken, async (req, res) => {
    try {
        // 1. Get user's favorite novels from library
        const favorites = await NovelLibrary.find({ user: req.user.id, isFavorite: true });
        
        if (!favorites || favorites.length === 0) {
            return res.json({ notifications: [], totalUnread: 0 });
        }

        const favIds = favorites.map(f => f.novelId);
        
        // 2. Get the actual novels to check chapter counts
        const novels = await Novel.find({ _id: { $in: favIds } })
            .select('title cover chapters lastChapterUpdate')
            .sort({ lastChapterUpdate: -1 })
            .lean();

        let notifications = [];
        let totalUnread = 0;

        // 3. Compare and build notification list
        novels.forEach(novel => {
            const libraryEntry = favorites.find(f => f.novelId.toString() === novel._id.toString());
            const userReadCount = libraryEntry.maxReadChapterId || 0;
            const totalChapters = novel.chapters ? novel.chapters.length : 0;
            
            // If there are new chapters
            if (totalChapters > userReadCount) {
                const diff = totalChapters - userReadCount;
                const lastChapter = novel.chapters[novel.chapters.length - 1];
                
                notifications.push({
                    _id: novel._id,
                    title: novel.title,
                    cover: novel.cover,
                    newChaptersCount: diff,
                    lastChapterNumber: lastChapter ? lastChapter.number : 0,
                    lastChapterTitle: lastChapter ? lastChapter.title : '',
                    updatedAt: novel.lastChapterUpdate
                });
                
                totalUnread += diff;
            }
        });

        res.json({ notifications, totalUnread });

    } catch (error) {
        console.error("Notifications Error:", error);
        res.status(500).json({ error: error.message });
    }
});

// =========================================================
// AUTH
// =========================================================
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
                role: role,
                createdAt: new Date() // ✅ Explicitly setting creation date just to be sure
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
