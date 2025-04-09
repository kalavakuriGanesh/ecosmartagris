const mongoose = require('mongoose');

const bidSchema = new mongoose.Schema({
    auction: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Auction',
        required: true
    },
    retailer: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Retailer',
        required: true
    },
    amount: {
        type: Number,
        required: true,
        min: 0
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Index for faster queries
bidSchema.index({ auction: 1, createdAt: -1 });
bidSchema.index({ retailer: 1, createdAt: -1 });

module.exports = mongoose.model('Bid', bidSchema); 