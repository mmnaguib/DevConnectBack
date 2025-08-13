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

const generateRandomName = () => {
  return `user_${Math.floor(1000 + Math.random() * 9000)}`;
};

router.post("/register", upload.single("avatar"), async (req, res) => {
  try {
    const { email, password, firstName, lastName, name, ...rest } = req.body;

    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // تحقق من الاسم
    if (name) {
      const existingName = await User.findOne({ name });
      if (existingName) {
        return res.status(400).json({ message: "Name already taken" });
      }
    }

    // توليد الاسم لو مش موجود
    const finalName = name || generateRandomName();

    // تشفير الباسورد
    const hashedPassword = await bcrypt.hash(password, 10);

    // لو فيه صورة مرفوعة
    let avatarUrl = "";
    if (req.file) {
      avatarUrl = `/uploads/${req.file.filename}`;
    }

    // إنشاء المستخدم
    const user = new User({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      name: finalName,
      avatarUrl,
      ...rest,
    });

    await user.save();

    res
      .status(201)
      .json({ message: "User registered successfully", user: user });
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

router.get("/me", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password -__v"); // شيل الحقول اللي مش محتاجها بس

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user);
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

router.put(
  "/update",
  authenticate,
  upload.single("avatar"),
  async (req, res) => {
    try {
      const userId = req.userId; // جاي من التوكين بعد authenticate

      // ناخد كل الداتا اللي جاية من الفورم
      const updateData = { ...req.body };

      // لو فيه صورة جديدة، نحط اللينك
      if (req.file) {
        updateData.avatarUrl = `/uploads/avatars/${req.file.filename}`;
      }

      // تحديث المستخدم
      const updatedUser = await User.findByIdAndUpdate(userId, updateData, {
        new: true,
      });

      if (!updatedUser) {
        return res.status(404).json({ message: "User not found" });
      }

      res.json({
        message: "Profile updated successfully",
        user: updatedUser,
      });
    } catch (error) {
      console.error("Update error:", error);
      res.status(500).json({ message: "Server error" });
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
