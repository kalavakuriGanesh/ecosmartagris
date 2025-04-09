const mongoose = require("mongoose");
const { Schema } = mongoose;

const auctionSchema = new Schema({
  farmer: {
    type: Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  product: {
    name: {
      type: String,
      required: true
    },
    description: String,
    quantity: {
      type: Number,
      required: true,
      min: 0
    },
    unit: {
      type: String,
      default: 'kg'
    },
    photo: String
  },
  startingPrice: {
    type: Number,
    required: true,
    min: 0
  },
  currentPrice: {
    type: Number,
    required: true,
    min: 0
  },
  minimumIncrement: {
    type: Number,
    required: true,
    min: 0,
    default: 100 // Default minimum increment
  },
  startTime: {
    type: Date,
    required: true
  },
  endTime: {
    type: Date,
    required: true
  },
  status: {
    type: String,
    enum: ["upcoming", "active", "ended", "cancelled"],
    default: "upcoming"
  },
  bids: [{
    type: Schema.Types.ObjectId,
    ref: "Bid"
  }],
  winner: {
    type: Schema.Types.ObjectId,
    ref: "User"
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Index for faster queries
auctionSchema.index({ status: 1, startTime: 1 });
auctionSchema.index({ farmer: 1, status: 1 });
auctionSchema.index({ winner: 1 });

// Virtual for time remaining
auctionSchema.virtual('timeRemaining').get(function() {
  if (this.status === 'ended' || this.status === 'cancelled') {
    return 0;
  }
  const now = new Date();
  if (now < this.startTime) {
    return this.startTime - now;
  }
  return this.endTime - now;
});

// Method to check if auction is active
auctionSchema.methods.isActive = function() {
  const now = new Date();
  return this.status === 'active' && now >= this.startTime && now <= this.endTime;
};

// Method to check if auction has ended
auctionSchema.methods.hasEnded = function() {
  const now = new Date();
  return this.status === 'ended' || now > this.endTime;
};

// Method to get minimum next bid
auctionSchema.methods.getMinimumNextBid = function() {
  return this.currentPrice + this.minimumIncrement;
};

module.exports = mongoose.model("Auction", auctionSchema); 