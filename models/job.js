import mongoose from "mongoose";

const jobSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
  type: { type: String, enum: ["mechanic", "helper"], required: true },
  status: { type: String, enum: ["requested", "accepted", "in_progress", "completed", "cancelled"], default: "requested" },
  location: {
    type: { type: String, enum: ["Point"], default: "Point" },
    coordinates: { type: [Number], default: [0, 0] }, // [lng, lat]
  },
  details: { type: String, default: "" },
  acceptedAt: { type: Date },
  createdAt: { type: Date, default: Date.now },
  meta: {
    partnerLastLoc: {
      lat: Number,
      lng: Number,
      ts: Date,
    },
  },
});

jobSchema.index({ location: "2dsphere" });

export const Job = mongoose.model("Job", jobSchema);
