const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    firstName: { type: String },
    lastName: { type: String },
    name: { type: String, unique: true, trim: true },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: { type: String, required: true },
    avatarUrl: { type: String },
    headline: { type: String },
    bio: { type: String },
    skills: { type: [String], default: [] },
    location: { type: String },
    website: { type: String },
    github: { type: String },
    linkedin: { type: String },

    // 🆕 إضافات جديدة
    company: { type: String },
    jobType: { type: String }, // full-time, part-time, freelance
    education: { type: String },
    address: { type: String },
    phone: { type: String },
    birthDate: { type: Date },
    joinDate: { type: Date, default: Date.now },
    lastActive: { type: Date },
    followersCount: { type: Number, default: 0 },
    followingCount: { type: Number, default: 0 },
    connectionsCount: { type: Number, default: 0 },
    status: {
      type: String,
      enum: ["active", "inactive", "banned"],
      default: "active",
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
