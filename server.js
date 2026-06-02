require('dotenv').config();
const express = require('express');
const passport = require('passport');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();

// Mengizinkan Frontend mengakses Backend & membaca Cookie/Credentials
app.use(cors({ 
  origin: process.env.FRONTEND_URL, 
  credentials: true 
}));

app.use(cookieParser());

// Konfigurasi session untuk Vercel (menggunakan trust proxy karena Vercel memakai reverse proxy)
app.set('trust proxy', 1); 
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true, // Wajib true di production (HTTPS)
    sameSite: 'none'
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// Konfigurasi Google OAuth Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: '/auth/google/callback',
}, (accessToken, refreshToken, profile, done) => {
  const user = {
    id: profile.id,
    name: profile.displayName,
    email: profile.emails[0].value,
    photo: profile.photos[0].value,
  };
  return done(null, user);
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Route untuk memicu Login Google
app.get('/auth/google', passport.authenticate('google', {
  scope: ['profile', 'email'],
}));

// Route Callback setelah user berhasil login di Google
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/auth/failed' }),
  (req, res) => {
    // Membuat token JWT
    const token = jwt.sign(req.user, process.env.JWT_SECRET || 'secret_fallback', { expiresIn: '7d' });
    
    // Menyimpan JWT di Cookie Browser dengan aman (Production-Ready)
    res.cookie('token', token, {
      httpOnly: true,
      secure: true,     // Wajib true karena Vercel menggunakan HTTPS
      sameSite: 'none', // Wajib 'none' agar cookie bisa dikirim lintas domain
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 Hari
    });
    
    // BARIS INI SUDAH DIUBAH: Diarahkan langsung ke halaman utama frontend, bukan ke /dashboard
    res.redirect(`${process.env.FRONTEND_URL}`);
  }
);

// Route untuk mengecek status login user
app.get('/auth/me', (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const user = jwt.verify(token, process.env.JWT_SECRET || 'secret_fallback');
    res.json({ user });
  } catch {
    res.status(401).json({ error: 'Token tidak valid' });
  }
});

// Route untuk Logout
app.get('/auth/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: true,
    sameSite: 'none'
  });
  res.redirect(process.env.FRONTEND_URL);
});

// Route jika login gagal
app.get('/auth/failed', (req, res) => {
  res.status(401).json({ error: 'Login gagal' });
});

// Menjalankan server lokal
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Backend jalan di port ${PORT}`));

module.exports = app; // Dibutuhkan oleh Vercel Serverless Functions