import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    fullName: String,
    email: { type: String, unique: true },
    phone: String,
    password: String,
    role: { type: String, enum: ["user", "partner"], default: "user" },
    otp: String,
    otpExpires: Date,

    // Partner-specific fields
    availability: {
      type: String,
      enum: ["active", "busy", "offline"],
      default: "offline",
    },
    isOnline: { type: Boolean, default: false },

    // Current geo location (GeoJSON Point)
    location: {
      type: {
        type: String,
        enum: ["Point"],
        default: "Point",
      },
      coordinates: {
        type: [Number], // [lng, lat]
        default: [0, 0],
      },
      updatedAt: { type: Date, default: null },
    },

    lastSeenAt: { type: Date, default: null },
  },
  { timestamps: true }
);

// 2dsphere index for geospatial queries
userSchema.index({ location: "2dsphere" });

export const User = mongoose.model("User", userSchema);
