const express = require('express');
const router = express.Router();
const Auction = require('../models/auction');
const Retailer = require('../models/retailer');
const auth = require('../middleware/auth');
const retailerAuth = require('../middleware/retailerAuth');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const dir = 'public/uploads/auctions';
        // Create directory if it doesn't exist
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'auction-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const fileFilter = (req, file, cb) => {
    // Accept images only
    if (!file.originalname.match(/\.(jpg|JPG|jpeg|JPEG|png|PNG|gif|GIF)$/)) {
        req.fileValidationError = 'Only image files are allowed!';
        return cb(new Error('Only image files are allowed!'), false);
    }
    cb(null, true);
};

const upload = multer({ 
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB max file size
    }
});

// Farmer's auction dashboard
router.get('/dashboard', auth, async (req, res) => {
    if (req.user.role !== 'farmer') {
        return res.status(403).json({ success: false, message: 'Access denied' });
    }

    try {
        const auctions = await Auction.find({ farmer: req.user.userId })
            .sort('-createdAt');
        res.render('layers/auction', {
            title: 'Auction Dashboard',
            board: 'auction',
            auctions: auctions,
            user: req.user
        });
    } catch (error) {
        console.error('Error fetching auctions:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Create new auction (farmers only)
router.post('/create', auth, upload.single('productPhoto'), async (req, res) => {
    if (req.user.role !== 'farmer') {
        return res.status(403).json({ success: false, message: 'Only farmers can create auctions' });
    }

    try {
        if (req.fileValidationError) {
            return res.status(400).json({ success: false, message: req.fileValidationError });
        }

        const auction = new Auction({
            farmer: req.user.userId,
            product: {
                name: req.body.product.name,
                description: req.body.product.description,
                quantity: req.body.product.quantity,
                unit: req.body.product.unit || 'kg',
                photo: req.file ? `/uploads/auctions/${req.file.filename}` : null
            },
            startingPrice: req.body.startingPrice,
            currentPrice: req.body.startingPrice,
            minimumIncrement: req.body.minimumIncrement || 100,
            startTime: new Date(req.body.startTime),
            endTime: new Date(req.body.endTime),
            status: 'upcoming'
        });

        await auction.save();
        res.redirect('/auctions/dashboard');
    } catch (error) {
        console.error('Auction creation error:', error);
        if (req.file) {
            // Remove uploaded file if auction creation fails
            fs.unlink(req.file.path, (err) => {
                if (err) console.error('Error removing failed upload:', err);
            });
        }
        res.status(400).json({ success: false, message: error.message });
    }
});

// Update auction status to ended
router.post('/:id/end', auth, async (req, res) => {
    try {
        const auction = await Auction.findById(req.params.id);
        if (!auction) {
            return res.status(404).json({ success: false, message: 'Auction not found' });
        }

        auction.status = 'ended';
        await auction.save();
        res.json({ success: true, auction });
    } catch (error) {
        console.error('Error ending auction:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Cancel auction (farmer only)
router.post('/:id/cancel', auth, async (req, res) => {
    try {
        const auction = await Auction.findById(req.params.id);
        
        if (!auction) {
            return res.status(404).json({ success: false, message: 'Auction not found' });
        }

        if (auction.farmer.toString() !== req.user.userId.toString()) {
            return res.status(403).json({ success: false, message: 'Not authorized' });
        }

        if (auction.status !== 'upcoming') {
            return res.status(400).json({ success: false, message: 'Can only cancel upcoming auctions' });
        }

        auction.status = 'cancelled';
        await auction.save();
        res.json({ success: true, auction });
    } catch (error) {
        console.error('Error cancelling auction:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// List all auctions
router.get('/', auth, async (req, res) => {
    try {
        const auctions = await Auction.find()
            .populate('farmer')
            .populate({
                path: 'bids.bidder',
                model: 'Retailer',
                select: 'businessName name'
            })
            .populate({
                path: 'winner',
                model: 'Retailer',
                select: 'businessName name'
            })
            .sort('-createdAt');
        res.render('auctions/index', { 
            auctions,
            user: req.user,
            title: 'All Auctions'
        });
    } catch (error) {
        console.error('Error fetching auctions:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get auction details
router.get('/:id', auth, async (req, res) => {
    try {
        const auction = await Auction.findById(req.params.id)
            .populate('farmer')
            .populate({
                path: 'bids.bidder',
                model: 'Retailer',
                select: 'businessName name'
            })
            .populate({
                path: 'winner',
                model: 'Retailer',
                select: 'businessName name'
            });
        
        if (!auction) {
            return res.status(404).json({ success: false, message: 'Auction not found' });
        }

        const isOwner = auction.farmer._id.toString() === req.user.userId.toString();

        res.render('auctions/detail', { 
            auction,
            user: req.user,
            isOwner,
            title: auction.product.name + ' - Auction Details'
        });
    } catch (error) {
        console.error('Error fetching auction details:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Place bid (retailers only)
router.post('/:id/bid', retailerAuth, async (req, res) => {
    try {
        const auction = await Auction.findById(req.params.id);
        
        if (!auction || auction.status !== 'active') {
            return res.status(400).send('Invalid auction');
        }

        if (req.body.amount <= auction.currentPrice) {
            return res.status(400).send('Bid must be higher than current price');
        }

        if (req.body.amount - auction.currentPrice < auction.minIncrement) {
            return res.status(400).send(`Bid increment must be at least ₹${auction.minIncrement}`);
        }

        auction.bids.push({
            bidder: req.user.userId,
            amount: req.body.amount,
            time: new Date()
        });

        auction.currentPrice = req.body.amount;
        await auction.save();

        res.json({ success: true });
    } catch (error) {
        res.status(500).send('Server error');
    }
});

module.exports = router; 