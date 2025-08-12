const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const RefreshToken = require("../models/RefreshToken");
const { authenticate } = require("../middleware/auth");
const multer = require("multer");
const path = require("path");
const router = express.Router();

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const ACCESS_EXPIRES = process.env.ACCESS_TOKEN_EXPIRES || "15m";
const REFRESH_EXPIRES = process.env.REFRESH_TOKEN_EXPIRES || "7d";

// helper: create access token
function createAccessToken(user) {
  return jwt.sign({ sub: user._id, email: user.email }, ACCESS_SECRET, {
    expiresIn: ACCESS_EXPIRES,
  });
}

// helper: create refresh token (randomish jwt)
function createRefreshToken(user) {
  const token = jwt.sign({ sub: user._id }, REFRESH_SECRET, {
    expiresIn: REFRESH_EXPIRES,
  });
  return token;
}

// REGISTER
router.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const existing = await User.findOne({ email });
    if (existing)
      return res.status(409).json({ message: "Email already used" });

    const salt = await bcrypt.genSalt(10);
    const hashed = await bcrypt.hash(password, salt);

    const user = new User({ email, password: hashed }); // باقي الحقول فاضية
    await user.save();

    const accessToken = createAccessToken(user);
    const refreshTokenValue = createRefreshToken(user);
    const expiresAt = new Date(Date.now() + parseDurationToMs(REFRESH_EXPIRES));

    const refreshTokenDoc = new RefreshToken({
      token: refreshTokenValue,
      user: user._id,
      expiresAt,
    });
    await refreshTokenDoc.save();

    res
      .cookie("refreshToken", refreshTokenValue, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        expires: expiresAt,
      })
      .status(201)
      .json({
        user: { id: user._id, email: user.email },
        accessToken,
      });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// LOGIN
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Invalid credentials" });

    const accessToken = createAccessToken(user);
    const refreshTokenValue = createRefreshToken(user);
    const expiresAt = new Date(Date.now() + parseDurationToMs(REFRESH_EXPIRES));

    const refreshTokenDoc = new RefreshToken({
      token: refreshTokenValue,
      user: user._id,
      expiresAt,
    });
    await refreshTokenDoc.save();

    res
      .cookie("refreshToken", refreshTokenValue, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        expires: expiresAt,
      })
      .json({
        user: { id: user._id, email: user.email },
        accessToken,
      });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// REFRESH TOKEN (token rotation)
router.post("/refresh-token", async (req, res) => {
  try {
    // token can come from cookie or body
    const token = req.cookies?.refreshToken || req.body.refreshToken;
    if (!token)
      return res.status(401).json({ message: "No refresh token provided" });

    // verify JWT signature first
    let payload;
    try {
      payload = jwt.verify(token, REFRESH_SECRET);
    } catch (err) {
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    // find the token doc in DB
    const tokenDoc = await RefreshToken.findOne({ token, revoked: false });
    if (!tokenDoc)
      return res
        .status(401)
        .json({ message: "Refresh token not found or revoked" });

    // optional: check expiry date stored in DB
    if (tokenDoc.expiresAt && tokenDoc.expiresAt < new Date()) {
      return res.status(401).json({ message: "Refresh token expired" });
    }

    // rotate: revoke old token and issue new refresh token
    tokenDoc.revoked = true;
    await tokenDoc.save();

    const user = await User.findById(payload.sub);
    if (!user) return res.status(401).json({ message: "User not found" });

    const newAccessToken = createAccessToken(user);
    const newRefreshTokenValue = createRefreshToken(user);
    const newExpiresAt = new Date(
      Date.now() + parseDurationToMs(REFRESH_EXPIRES)
    );

    const newTokenDoc = new RefreshToken({
      token: newRefreshTokenValue,
      user: user._id,
      expiresAt: newExpiresAt,
    });
    await newTokenDoc.save();

    res
      .cookie("refreshToken", newRefreshTokenValue, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        expires: newExpiresAt,
      })
      .json({ accessToken: newAccessToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// LOGOUT (revoke refresh token)
router.post("/logout", async (req, res) => {
  try {
    const token = req.cookies?.refreshToken || req.body.refreshToken;
    if (token) {
      await RefreshToken.findOneAndUpdate({ token }, { revoked: true });
    }
    res.clearCookie("refreshToken").json({ message: "Logged out" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// protected sample route
router.get("/me", authenticate, async (req, res) => {
  const user = await User.findById(req.userId).select("-password");
  res.json({ user });
});

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/"); // فولدر رفع الصور (اتأكد إنه موجود)
  },
  filename: function (req, file, cb) {
    // اسم الملف يكون timestamp + الاسم الأصلي
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({ storage });

// مثال تحديث بيانات المستخدم مع صورة أفاتار
router.put(
  "/profile",
  authenticate,
  upload.single("avatar"), // "avatar" هو اسم الحقل للملف من الفورم
  async (req, res) => {
    try {
      const { firstName, lastName, email, bio, ...otherFields } = req.body;
      let avatarUrl;

      if (req.file) {
        avatarUrl = `/uploads/${req.file.filename}`;
      }
      res.json({
        success: true,
        message: "Profile updated successfully",
        avatarUrl,
        // updatedUser,
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

module.exports = router;

// helper: parse simple durations like "15m" or "7d" to ms
function parseDurationToMs(str) {
  // supports s, m, h, d
  if (!str) return 0;
  const match = /^(\d+)(s|m|h|d)$/.exec(str);
  if (!match) return 0;
  const val = parseInt(match[1], 10);
  const unit = match[2];
  switch (unit) {
    case "s":
      return val * 1000;
    case "m":
      return val * 60 * 1000;
    case "h":
      return val * 60 * 60 * 1000;
    case "d":
      return val * 24 * 60 * 60 * 1000;
    default:
      return 0;
  }
}
