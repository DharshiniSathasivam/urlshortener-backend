require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });
const express   = require('express');
const cors      = require('cors');
const mongoose  = require('mongoose');
const crypto    = require('crypto');
const jwt       = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { nanoid } = require('nanoid');
const User = require('./User');
const Url  = require('./Url');

const app = express();
app.use(cors());
app.use(express.json());




mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));


const sendEmail = async (to, subject, html) => {
  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
  });
  await transporter.sendMail({ from: process.env.EMAIL_USER, to, subject, html });
};


const protect = async (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer '))
    return res.status(401).json({ message: 'Not logged in' });
  try {
    const decoded = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id);
    if (!req.user) return res.status(401).json({ message: 'User not found' });
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
};


app.post('/api/register', async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    if (await User.findOne({ email }))
      return res.status(400).json({ message: 'Email already registered' });

    const activationToken = crypto.randomBytes(32).toString('hex');
    await User.create({ firstName, lastName, email, password, activationToken });

    const link = `${process.env.FRONTEND_URL}/activate/${activationToken}`;
    await sendEmail(email, 'Activate your account',
      `<p>Hi ${firstName}, click below to activate your account:</p>
       <a href="${link}" style="padding:10px 20px;background:#667eea;color:white;border-radius:5px;text-decoration:none">Activate</a>`
    );

    res.json({ message: 'Registered! Check your email to activate your account.' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


app.get('/api/activate/:token', async (req, res) => {
  try {
    const user = await User.findOne({ activationToken: req.params.token });
    if (!user) return res.status(400).json({ message: 'Invalid link' });

    user.isActive = true;
    user.activationToken = null;
    await user.save();
    res.json({ message: 'Account activated! You can now log in.' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await user.matchPassword(password)))
      return res.status(400).json({ message: 'Invalid email or password' });

    if (!user.isActive)
      return res.status(400).json({ message: 'Please activate your account first' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, firstName: user.firstName, email: user.email } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


app.post('/api/forgot-password', async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.json({ message: 'If that email exists, a link was sent.' });

    const token = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken   = token;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    const link = `${process.env.FRONTEND_URL}/reset-password/${token}`;
    await sendEmail(req.body.email, 'Reset your password',
      `<p>Click below to reset your password (expires in 1 hour):</p>
       <a href="${link}" style="padding:10px 20px;background:#f5576c;color:white;border-radius:5px;text-decoration:none">Reset Password</a>`
    );
    res.json({ message: 'Reset link sent to your email!' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


app.post('/api/reset-password/:token', async (req, res) => {
  try {
    const user = await User.findOne({
      resetPasswordToken:   req.params.token,
      resetPasswordExpires: { $gt: Date.now() }
    });
    if (!user) return res.status(400).json({ message: 'Link expired or invalid' });

    user.password             = req.body.password;
    user.resetPasswordToken   = null;
    user.resetPasswordExpires = null;
    await user.save();
    res.json({ message: 'Password reset! You can now log in.' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


app.post('/api/urls', protect, async (req, res) => {
  try {
    const { originalUrl, customAlias, title } = req.body;

    try { new URL(originalUrl); }
    catch { return res.status(400).json({ message: 'Enter a valid URL' }); }

    const shortCode = customAlias || nanoid(6);

    if (customAlias && await Url.findOne({ shortCode: customAlias }))
      return res.status(400).json({ message: 'Alias already taken' });

    const url = await Url.create({ user: req.user._id, originalUrl, shortCode, title });
    res.json({ ...url.toObject(), shortUrl: `${process.env.BACKEND_URL}/r/${shortCode}` });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/urls', protect, async (req, res) => {
  try {
    const page  = parseInt(req.query.page) || 1;
    const limit = 10;
    const total = await Url.countDocuments({ user: req.user._id });
    const urls  = await Url.find({ user: req.user._id })
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    const data = urls.map(u => ({ ...u.toObject(), shortUrl: `${process.env.BACKEND_URL}/r/${u.shortCode}` }));
    res.json({ data, total, page, pages: Math.ceil(total / limit) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete('/api/urls/:id', protect, async (req, res) => {
  try {
    await Url.findOneAndDelete({ _id: req.params.id, user: req.user._id });
    res.json({ message: 'Deleted!' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


app.get('/r/:shortCode', async (req, res) => {
  try {
    const url = await Url.findOne({ shortCode: req.params.shortCode });
    if (!url) return res.status(404).json({ message: 'URL not found' });

    url.clicks.push({ clickedAt: new Date() });
    url.totalClicks += 1;
    await url.save();

    res.redirect(url.originalUrl);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/stats', protect, async (req, res) => {
  try {
    const urls        = await Url.find({ user: req.user._id });
    const totalUrls   = urls.length;
    const totalClicks = urls.reduce((sum, u) => sum + u.totalClicks, 0);

    const today = new Date(); today.setHours(0,0,0,0);
    const urlsToday = urls.filter(u => new Date(u.createdAt) >= today).length;

    const last7 = {};
    for (let i = 6; i >= 0; i--) {
      const d = new Date(); d.setDate(d.getDate() - i);
      last7[d.toISOString().slice(0,10)] = 0;
    }
    urls.forEach(u => u.clicks.forEach(c => {
      const day = new Date(c.clickedAt).toISOString().slice(0,10);
      if (last7[day] !== undefined) last7[day]++;
    }));

    res.json({ totalUrls, totalClicks, urlsToday,
               clicksPerDay: Object.entries(last7).map(([date, count]) => ({ date, count })),
               topUrls: urls.sort((a,b) => b.totalClicks - a.totalClicks).slice(0,5)
                            .map(u => ({ ...u.toObject(), shortUrl: `${process.env.BACKEND_URL}/r/${u.shortCode}` })) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.listen(process.env.PORT, () => console.log(`Server running on port ${process.env.PORT}`));