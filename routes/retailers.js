const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Retailer = require('../models/retailer');
const Auction = require('../models/auction');
const Bid = require('../models/bid');
const auth = require('../middleware/auth');

// Register a new retailer
router.post('/register', async (req, res) => {
    try {
        const { name, email, password, phone, businessName, businessType, address, gstin } = req.body;

        // Check if email already exists
        let retailer = await Retailer.findOne({ email });
        if (retailer) {
            return res.status(400).json({ message: 'Email already registered' });
        }

        // Check if GSTIN already exists
        retailer = await Retailer.findOne({ gstin });
        if (retailer) {
            return res.status(400).json({ message: 'GSTIN already registered' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new retailer
        retailer = new Retailer({
            name,
            email,
            password: hashedPassword,
            phone,
            businessName,
            businessType,
            address,
            gstin
        });

        await retailer.save();

        // Generate JWT token
        const token = jwt.sign(
            { id: retailer._id, role: 'retailer' },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({ token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login retailer
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if retailer exists
        const retailer = await Retailer.findOne({ email });
        if (!retailer) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Verify password
        const isMatch = await bcrypt.compare(password, retailer.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { id: retailer._id, role: 'retailer' },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get retailer profile
router.get('/profile', auth, async (req, res) => {
    try {
        if (req.user.role !== 'retailer') {
            return res.status(403).json({ message: 'Access denied' });
        }

        const retailer = await Retailer.findById(req.user.id)
            .select('-password')
            .populate('participatedAuctions')
            .populate('wonAuctions');

        if (!retailer) {
            return res.status(404).json({ message: 'Retailer not found' });
        }

        res.json(retailer);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get retailer dashboard data
router.get('/dashboard', auth, async (req, res) => {
    try {
        if (req.user.role !== 'retailer') {
            return res.status(403).json({ message: 'Access denied' });
        }

        const retailer = await Retailer.findById(req.user.id);
        if (!retailer) {
            return res.status(404).json({ message: 'Retailer not found' });
        }

        // Get active and upcoming auctions
        const auctions = await Auction.find({
            status: { $in: ['active', 'upcoming'] }
        }).populate('farmer', 'name location');

        // Get participated auctions count
        const participatedCount = retailer.participatedAuctions.length;

        // Get won auctions count
        const wonCount = retailer.wonAuctions.length;

        // Calculate total amount spent
        const wonAuctions = await Auction.find({
            winner: retailer._id,
            status: 'ended'
        });
        const totalSpent = wonAuctions.reduce((sum, auction) => sum + auction.currentPrice, 0);

        res.json({
            participatedCount,
            wonCount,
            totalSpent,
            auctions
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Place a bid on an auction
router.post('/bid', auth, async (req, res) => {
    try {
        if (req.user.role !== 'retailer') {
            return res.status(403).json({ message: 'Access denied' });
        }

        const { auctionId, amount } = req.body;

        // Find the auction
        const auction = await Auction.findById(auctionId);
        if (!auction) {
            return res.status(404).json({ message: 'Auction not found' });
        }

        // Check if auction is active
        if (!auction.isActive()) {
            return res.status(400).json({ message: 'Auction is not active' });
        }

        // Check if bid amount is valid
        const minimumBid = auction.getMinimumNextBid();
        if (amount < minimumBid) {
            return res.status(400).json({ 
                message: `Bid must be at least ${minimumBid}` 
            });
        }

        // Create new bid
        const bid = new Bid({
            auction: auctionId,
            retailer: req.user.id,
            amount
        });

        await bid.save();

        // Update auction
        auction.currentPrice = amount;
        auction.winner = req.user.id;
        auction.bids.push(bid._id);
        await auction.save();

        // Update retailer's participated auctions
        const retailer = await Retailer.findById(req.user.id);
        if (!retailer.participatedAuctions.includes(auctionId)) {
            retailer.participatedAuctions.push(auctionId);
            await retailer.save();
        }

        res.json({ 
            message: 'Bid placed successfully',
            bid,
            auction: {
                currentPrice: auction.currentPrice,
                winner: auction.winner
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get bid history for an auction
router.get('/auctions/:auctionId/bids', auth, async (req, res) => {
    try {
        if (req.user.role !== 'retailer') {
            return res.status(403).json({ message: 'Access denied' });
        }

        const bids = await Bid.find({ auction: req.params.auctionId })
            .populate('retailer', 'name businessName')
            .sort({ createdAt: -1 });

        res.json(bids);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get won auctions
router.get('/won-auctions', auth, async (req, res) => {
    try {
        if (req.user.role !== 'retailer') {
            return res.status(403).json({ message: 'Access denied' });
        }

        const auctions = await Auction.find({
            winner: req.user.id,
            status: 'ended'
        }).populate('farmer', 'name location');

        res.json(auctions);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router; 