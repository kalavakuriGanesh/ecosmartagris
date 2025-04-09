const mongoose = require("mongoose");
const { Schema } = mongoose;

const retailerSchema = new Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  phone: {
    type: String,
    required: true
  },
  businessName: {
    type: String,
    required: true
  },
  businessType: {
    type: String,
    enum: ["retailer", "wholesaler"],
    required: true
  },
  address: {
    type: String,
    required: true
  },
  gstin: {
    type: String,
    required: true
  },
  participatedAuctions: [{
    type: Schema.Types.ObjectId,
    ref: "Auction"
  }],
  wonAuctions: [{
    type: Schema.Types.ObjectId,
    ref: "Auction"
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("Retailer", retailerSchema); 