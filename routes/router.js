require('dotenv').config();
const express = require('express');
const router = express.Router();
const User = require('../models/user');
const Product = require('../models/product');
const Order = require('../models/order');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const os = require('os');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const fs = require("fs");
const Admin = require("../models/admin");
const Auction = require("../models/auction");
const Bid = require("../models/bid");
// image upload

var storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, './public/img');
    },
    filename: function(req, file, cb) {
        cb(null, file.fieldname + "_" + Date.now() + "_" + file.originalname);
    },
});

var upload = multer({
    storage: storage,
}).single('image');  // 'image' is a 'name' field from input tag

router.use(express.urlencoded({extended: true}));
router.use(express.json());
router.use(cookieParser());
const head_name = process.env.HEAD;
// const secret_key = 'something';


router.post('/register', async (req, res) => {
  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPass = await bcrypt.hash(req.body.pass, salt);

    const user = new User({
      name: req.body.name,
      email: req.body.email,
      pass: hashedPass,
      address: req.body.address,
      phone: req.body.phone,
      role: req.body.role,
    });

    const savedUser = await user.save();

    // Now update Admin database
    const admin = await Admin.findOne(); // Assuming you have only 1 admin
    if(admin){
        if (admin) {
            if (savedUser.role === "customer") {
              admin.users.push(savedUser._id);
            } else if (savedUser.role === "farmer") {
              admin.farmers.push(savedUser._id);
            } else if (savedUser.role === "retailer") {
              admin.retailers.push(savedUser._id);
            }
            await admin.save();
          } else {
            console.log('Admin record not found!');
          }
    }

    // Set success message in session
    req.session.message = { type: 'success', text: 'Registration successful! Please login.' };
    return res.redirect('/login');

  } catch (error) {
    console.log(error);
    req.session.message = { type: 'error', text: 'Registration failed. Please try again.' };
    return res.redirect('/register');
  }
});

router.post('/auth', async (req,res) => {
    try{
        const {email, pass} = req.body;
        
        // First check if it's an admin login
        const admin = await Admin.findOne({email});
        if(admin){
            if(await bcrypt.compare(pass, admin.password)) {
                const token = jwt.sign(
                    {userId: admin._id, role: 'admin'}, 
                    process.env.BYTPASS,
                    { expiresIn: process.env.JWTEXP}
                );
                res.cookie('json', token, {
                    httpOnly: true,
                    secure: false,
                    sameSite: 'strict',
                    maxAge: process.env.COOEXP * 60 * 60 * 1000,
                });
                return res.redirect('/admin/dashboard');
            }
        }

        // Then check for regular user (customer or farmer)
        const user = await User.findOne({ email: email });
        if (!user) {
            req.session.message = { type: 'error', text: 'User not found' };
            return res.redirect('/login');
        }

        if(await bcrypt.compare(pass, user.pass)) {
            const token = jwt.sign(
                {userId: user._id, role: user.role}, 
                process.env.BYTPASS,
                { expiresIn: process.env.JWTEXP}
            );
            res.cookie('json', token, {
                httpOnly: true,
                secure: false,
                sameSite: 'strict',
                maxAge: process.env.COOEXP * 60 * 60 * 1000,
            });
            return res.redirect('/dashboard/home');
        } else {
            req.session.message = { type: 'error', text: 'Invalid password' };
            return res.redirect('/login');
        }
    } catch (error) {
        console.log(error);
        req.session.message = { type: 'error', text: 'An error occurred' };
        return res.redirect('/login');
    }
});

router.post("/reset", async (req, res) => {
    const email = req.body.email;
    const user = await User.findOne({ email : email }).exec();
    if(user){
        const encryptedData = encryptLinkData(user._id);
        const link = `${req.protocol}://${req.headers.host}/change?step=${encodeURIComponent(encryptedData)}`;
        const content = `<p>The Like could be expire in 5 minutes.
            Click the link below to reset your password:</p>
            <a href="${link}">${link}</a>`
        await sendEmail(email, "Reset Password", content);
        console.log(`Reset Link: ${link}`);
        res.status(200).send("Link has been sented to the Registered Email. <a href='/'>Click to Login</a>")
    } else {
        return res.status(400).send("No Email has registered... <a href='/'>Back to Login</a>");
    }   
});

router.post("/setpass", async (req, res) => {
    const password = req.body.pass;
    const conf_password = req.body.conf_pass;
    if(password != conf_password){
        return res.send("Password Mismatch... <a href='/'>Back to Login</a>");
    }
    try{
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt)
        const updateUser = await User.findByIdAndUpdate(req.session.user,
            { pass : hashedPassword },
            { new : true }
        );

        if(!updateUser) {
            return res.status(404).send("Session Expired. <a href='/'>Click to Back</a>");
        }

        // res.status(200).send("Password updated successfully... <a href='/dashboard/home'>Click to Dashboard</a>");
        req.session.message = {
            message : "Success",
        };
        res.redirect("/dashboard/home");
    } catch(error) {
        console.log(error);
        res.status(404).send("Update Process Failed...");
    }

});

router.post("/update_profile", authToken, async (req, res) => {
    try{
        const updateUser = await User.findByIdAndUpdate(req.auth_user._id,
            { 
                name : req.body.name.trim(),
                email : req.body.email.trim(),
                phone : req.body.phone.trim(),
                address : req.body.address.trim(),
            },
            { new : true }
        );
        if(!updateUser) {
            return res.status(404).send("User not found.");
        }
        // res.status(200).send("Profile Updated Successfully... <a href='/dashboard/profile'>Click to Dashboard</a>");
        res.redirect("/dashboard/profile")

    } catch (error) {
        console.log(error);
        res.send("Updating Profile has been failed due to server error...");
    }
});

router.post('/upload_photo', authToken, upload, async (req, res) => {
    try{
        if(req.file){
            new_image = req.file.filename;
            const updatePhoto = await User.findByIdAndUpdate(req.auth_user._id,
                { photo : new_image },
                { new : true }
            );
            if(!updatePhoto){
                return res.status(401).send("No User found... <a href='/dashboard/home'>Click to Dashboard</a>")
            }
            // res.status(200).send("Photo has been Updated... <a href='/dashboard/home'>Click to Dashboard</a>")
            res.redirect('/dashboard/home');
            if(req.auth_user.photo){
                try{
                    fs.unlinkSync("./public"+req.body.old_image);
                } catch (error) {
                    console.log(error);
                }
            } 
        }
    } catch(error) {
        console.log(error);
    }
});

// ------------------------------------Product Section ----------------------------------------------------------

router.post('/addproduct', authToken, upload, async (req, res) => {
    try{
        const currentDate = getDate();
        const product = new Product({
            name: req.body.name,
            price: req.body.price,
            quantity: req.body.quantity,
            location: req.body.location,
            description: req.body.description,
            seller: req.auth_user._id,
            photo: req.file.filename,
            created: currentDate,
            last_updated: currentDate,
        });
        const prod = await product.save();
        const admin = await Admin.findOne();
        if (admin) {
            admin.products.push(prod._id);
            await admin.save();
        } else {
            console.error("Admin record not found!");
            return res.status(500).send("Admin record not found. Please contact support.");
        }
        res.redirect('/dashboard/product');
    } catch (error) {
        console.log(error);
    }
});

router.post('/product/update', authToken, async (req, res) => {
    try{
        var currentDate = getDate();
        const updateProduct = await Product.findByIdAndUpdate(req.body.productId,
            { 
                price : req.body.price,
                location : req.body.location,
                last_updated : currentDate,
            },
            { new : true }
        );
        if(!updateProduct) {
            console.log(updateProduct);
            return res.status(401).send("No Product found... <a href='/dashboard/product/own'>Click to Products</a>")
        }

        // res.status(200).send("Product Updated Successfully... <a href='/dashboard/product/own'>Click to Dashboard</a>");
        res.redirect('/dashboard/product/own');

    } catch (error) {
        console.log(error);
        res.send("Updating Product has been failed due to server error...");
    }
});

router.post('/product/order', authToken, async (req, res) => {
    try{
        // const check = await sendEmail(req.auth_user.email, "Reset Password", "content");
        const check = true;
        if(!(check)) {
            return res.send("Something went wrong in sending request");
        }
        const currentDate = getDate();
        const expire = Date.now() + 1*60*1000;
        const product = await Product.findById(req.body.productId, { seller: 1, quantity: 1, ordered: 1 });
        const order = new Order({
            product: product._id,
            seller: product.seller,
            buyer: req.auth_user._id,
            quantity: req.body.quantity,
            requested: currentDate,
            expire: expire,
        });
        const updated = String(parseFloat(product.ordered) + (parseFloat(order.quantity)));
        if(parseFloat(updated) > parseFloat(product.quantity)){
            return res.send("Out of Stock Quantity... <a href='/dashboard/product'>Click to Back</a>"+updated+"-"+product.quantity)
        } else{
        await order.save();
        await Product.findByIdAndUpdate(product._id, { ordered : updated })
        // res.send("Request has Sended, Kindly Wait for Acceptance. <a href='/dashboard/product'>Click to Back</a>");
        res.redirect('/dashboard/product');
        }
    } catch (error) {
        res.status(400).send("Product has failed to order due to Server Error...");
        console.log(error);
    }
});

router.post('/product/result', async (req, res) => {
    try{
        const result = req.body;
        const order = await Order.findById(result.orderId);
        if(result.btn === 'accepted') {
            const salt = await bcrypt.genSalt(10);
            const product = await Product.findById(order.product, { quantity: 1, ordered: 1});
            const quantity = String(parseFloat(product.quantity) - (parseFloat(order.quantity)));
            const ordered = String(parseFloat(product.ordered) - (parseFloat(order.quantity)));
            const productUpdated = await Product.findByIdAndUpdate(product._id, 
                {
                    quantity: quantity,
                    ordered: ordered,
                },
                { new: true},
            );
            if(productUpdated) {
                await Order.findByIdAndUpdate(order._id, 
                    {
                        status: "accepted",
                        code: generateCode(),
                    },
                    { new: true },
                );
                res.redirect('/product/request');
            } else {
                res.send("Failed to Accept...");
            }
        } else { 
            res.send("reject");
        }
    } catch (error) {
        res.status(400).send("Server Issue...");
        console.log(error);
    }
});

router.post('/order/verify', async (req, res) => {
    const code = await Order.findById(req.body.orderID, { product: 1, code: 1, quantity: 1 });
    if(req.body.code === code.code){
        
        await Order.findByIdAndUpdate(code._id, 
            {
                status: "completed",
            },
            { new : true },
        );
        res.redirect('/product/request');

        // res.send(product.quantity);
    }
    else {
        res.send("Invalid Code.. Try Again...");
    }
});

//---------------------------------------- functions -------------------------------------------------------------------

function getDate(){
    var date = new Date();
    var currentDate = date.getDate()+'-'+(date.getMonth()+1)+'-'+date.getFullYear()+' '+date.getHours()+':'+date.getMinutes()+':'+date.getSeconds();
    return currentDate;
}

function generateCode(){
    var val = Math.floor(1000 + Math.random() * 9999);
    return val;
}

async function getUser(id) {
    try{
        const user = await User.findById(id);
        return user;
    } catch (error) {
        console.log(error);
    }
}

async function sendEmail(recipientEmail, subject, content) {
    try{
        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL,
                pass: process.env.PASS,
            },
        });

        const mailOptions = {
            from: '"Smart Agri Connector" <noreply@smartariconnectoru>',
            to: recipientEmail,
            subject: subject,
            html: content,
        };

        const info = await transporter.sendMail(mailOptions);
        if(!info){
            return false;
        }
        return true;
    } catch (error) {
        console.log('Error sending email: ',error);
        return false;
    }
}

function getIp(){
    const networkInterfaces = os.networkInterfaces();
    for (const interfaceName in networkInterfaces) {
        for (const interface of networkInterfaces[interfaceName]) {
            if (interface.family === 'IPv4' && !interface.internal) {
                return interface.address;
            }
        }
    }
}

const secretKey = crypto.randomBytes(32).toString("hex").substring(0,32);
const iv = crypto.randomBytes(16);

function encryptLinkData(input){
    const data = JSON.stringify({input, exp: Date.now() + process.env.PASSLINKEXP * 60 * 1000});  //Link Expiry
    const cipher = crypto.createCipheriv("aes-256-cbc", secretKey, iv);
    let encrypted = cipher.update(data, "utf8", "hex");
    encrypted += cipher.final("hex");
    return `${iv.toString("hex")}:${encrypted}`;
}

function decryptLinktData(encryptedData){
    const [ivHex, encrypted] = encryptedData.split(":");
    const iv = Buffer.from(ivHex, "hex");
    const decipher = crypto.createDecipheriv("aes-256-cbc", secretKey, iv);
    let decrypted = decipher.update(encrypted, "hex", "utf-8");
    decrypted += decipher.final("utf-8");
    return JSON.parse(decrypted);
}

async function authToken(req, res, next){
    const token = req.cookies.json;
    if(!token) {
        return res.redirect('/login');
    }
    try{
        const decode = jwt.verify(token, process.env.BYTPASS);
        
        // Check if it's an admin token
        if(decode.role === 'admin') {
            const admin = await Admin.findById(decode.userId);
            if (!admin) {
                res.clearCookie('json');
                return res.redirect('/login');
            }
            req.auth_user = admin;
            next();
        } else {
            // Regular user token
            const user = await User.findById(decode.userId);
            if (!user) {
                res.clearCookie('json');
                return res.redirect('/login');
            }
            req.auth_user = user;
            next();
        }
    } catch (error) {
        console.log(error);
        res.clearCookie('json');
        res.redirect('/login');
    }
}

async function updateExpire(){
    try{
        const currentTime = Date.now();
        const updated = await Order.find(
            { expire: { $lt: currentTime }, status: { $ne: "rejected" } },
        );
        if(updated.length > 0){
            for (const order of updated){
                await Order.updateOne({_id: order._id}, {$set:{status:"rejected"}});

                const product = await Product.findById(order.product, { ordered: 1});
                // const updateQuantity = String(parseFloat(product.quantity) + (parseFloat(order.quantity)));
                const updateOrdered = String(parseFloat(product.ordered) - (parseFloat(order.quantity)));
                await Product.updateOne({_id: product._id},
                    {
                        ordered: updateOrdered,
                    }
                );
            }
        }
        await Order.updateMany({status: "rejected"}, {$unset:{expire:1}});
        await Order.updateMany({status: "completed"}, {$unset:{code:1}});
        await Order.updateMany({status: "accepted"}, {$unset:{expire:1}});
        return updated;
    } catch (error) {
        console.log(error);
    }
}

//----------------------------------------------------------------------------------------------------------------

// Welcome and Authentication Routes
router.get("/", (req, res) => {
    res.render('welcome', {head: head_name, title: "Welcome to ECOSMARTAGRI"});
});

router.get("/login", (req, res) => {
    res.render('index', {head: head_name, title: "Login to ECOSMARTAGRI"});
});

router.get("/register", (req, res) => {
    res.render('register', {head: head_name, title: "Register with ECOSMARTAGRI"});
});

router.get("/reset", (req, res) => {
    res.render('reset', {head: head_name, title: "Reset Page"});
});

router.get('/change', (req, res) => {
    try{
        const encryptedData = req.query.step;
        const decryptedData = decryptLinktData(encryptedData);
        if (decryptedData.exp < Date.now()) {
            return res.status(400).send("The Link has Expired... <a href='/'>Click to Login</a>");
        }
        const id = decryptedData.input;
        req.session.user = id;
        req.session.cookie.maxAge = process.env.PASSPAGEEXP * 60 * 1000;
        res.render('password', {head: head_name, title: "Recover Password"});
    } catch(error) {
        console.log(error);
        res.status(400).send("Invalid or Corrupted link...");
    }
});

router.get('/update_password', authToken, (req, res) => {
    try{
        const encryptedData = encryptLinkData(req.auth_user._id);
        res.redirect(`/change?step=${encodeURIComponent(encryptedData)}`);
    } catch (error) {
        console.log(error);
        res.send('Unable to connect.. <a href="/dashboard/home">back to the dashboard</a>');
    }
});

router.get('/dashboard/home', authToken, async (req, res) => {
    try {
        const user = req.auth_user;
        let stats = {};

        if (user.role === 'customer') {
            // Calculate total goods bought for customers
            const boughtStats = await Order.aggregate([
                {
                    $match: {
                        buyer: user._id,
                        status: { $in: ['accepted', 'completed'] }
                    }
                },
                {
                    $lookup: {
                        from: 'products',
                        localField: 'product',
                        foreignField: '_id',
                        as: 'productDetail'
                    }
                },
                {
                    $unwind: '$productDetail'
                },
                {
                    $group: {
                        _id: '$productDetail.name',
                        totalQuantity: { $sum: { $toDouble: '$quantity' } },
                        totalPrice: { $sum: { $multiply: [{ $toDouble: '$quantity' }, { $toDouble: '$productDetail.price' }] } }
                    }
                }
            ]);

            stats.totalBought = boughtStats.map(stat => ({
                productName: stat._id,
                quantity: `${stat.totalQuantity} kg`,
                totalPrice: `₹${stat.totalPrice.toFixed(2)}`
            }));
        } else if (user.role === 'farmer') {
            // Calculate total goods sold for farmers
            const soldStats = await Order.aggregate([
                {
                    $match: {
                        seller: user._id,
                        status: { $in: ['accepted', 'completed'] }
                    }
                },
                {
                    $lookup: {
                        from: 'products',
                        localField: 'product',
                        foreignField: '_id',
                        as: 'productDetail'
                    }
                },
                {
                    $unwind: '$productDetail'
                },
                {
                    $group: {
                        _id: '$productDetail.name',
                        totalQuantity: { $sum: { $toDouble: '$quantity' } },
                        totalPrice: { $sum: { $multiply: [{ $toDouble: '$quantity' }, { $toDouble: '$productDetail.price' }] } }
                    }
                }
            ]);

            stats.totalSold = soldStats.map(stat => ({
                productName: stat._id,
                quantity: `${stat.totalQuantity} kg`,
                totalPrice: `₹${stat.totalPrice.toFixed(2)}`
            }));
        } else if (user.role === 'retailer') {
            // Get all active and upcoming auctions with farmer details
            const auctions = await Auction.aggregate([
                {
                    $match: {
                        status: { $in: ['active', 'upcoming'] }
                    }
                },
                {
                    $addFields: {
                        // Update status based on current time
                        currentStatus: {
                            $switch: {
                                branches: [
                                    {
                                        case: { 
                                            $and: [
                                                { $lte: ['$startTime', new Date()] },
                                                { $gte: ['$endTime', new Date()] }
                                            ]
                                        },
                                        then: 'active'
                                    },
                                    {
                                        case: { $gt: ['$startTime', new Date()] },
                                        then: 'upcoming'
                                    }
                                ],
                                default: 'ended'
                            }
                        }
                    }
                },
                {
                    $match: {
                        currentStatus: { $in: ['active', 'upcoming'] }
                    }
                },
                {
                    $lookup: {
                        from: 'users',
                        localField: 'farmer',
                        foreignField: '_id',
                        as: 'farmerDetails'
                    }
                },
                {
                    $unwind: '$farmerDetails'
                },
                {
                    $lookup: {
                        from: 'bids',
                        let: { auctionId: '$_id' },
                        pipeline: [
                            {
                                $match: {
                                    $expr: { $eq: ['$auction', '$$auctionId'] }
                                }
                            },
                            {
                                $lookup: {
                                    from: 'users',
                                    localField: 'retailer',
                                    foreignField: '_id',
                                    as: 'retailerDetails'
                                }
                            },
                            {
                                $unwind: '$retailerDetails'
                            },
                            {
                                $project: {
                                    amount: 1,
                                    time: 1,
                                    'retailerDetails.name': 1
                                }
                            },
                            {
                                $sort: { time: -1 }
                            },
                            {
                                $limit: 5
                            }
                        ],
                        as: 'bids'
                    }
                },
                {
                    $project: {
                        product: 1,
                        startingPrice: 1,
                        currentPrice: 1,
                        minimumIncrement: 1,
                        startTime: 1,
                        endTime: 1,
                        status: '$currentStatus',
                        'farmerDetails.name': 1,
                        'farmerDetails.location': 1,
                        bids: 1
                    }
                },
                {
                    $sort: {
                        startTime: 1
                    }
                }
            ]);

            // Calculate retailer's bidding statistics
            const biddingStats = await Bid.aggregate([
                {
                    $match: {
                        retailer: user._id
                    }
                },
                {
                    $lookup: {
                        from: 'auctions',
                        localField: 'auction',
                        foreignField: '_id',
                        as: 'auctionDetails'
                    }
                },
                {
                    $unwind: '$auctionDetails'
                },
                {
                    $group: {
                        _id: null,
                        totalBids: { $sum: 1 },
                        totalAmount: { $sum: '$amount' },
                        wonAuctions: {
                            $sum: {
                                $cond: [
                                    { $eq: ['$auctionDetails.winner', user._id] },
                                    1,
                                    0
                                ]
                            }
                        }
                    }
                }
            ]);

            stats = {
                auctions: auctions,
                biddingStats: biddingStats[0] || {
                    totalBids: 0,
                    totalAmount: 0,
                    wonAuctions: 0
                }
            };
        }

        res.render('dashboard', {
            head: "Dashboard",
            title: "Dashboard",
            user: user,
            board: 'home',
            stats: stats
        });
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).send("Error loading dashboard");
    }
});

router.get('/dashboard/profile', authToken, async (req, res) => {
    try {
        const user = req.auth_user;
        res.render('dashboard', {
            head: head_name,
            title: "Profile",
            user: user,
            board: "profile"
        });
    } catch (error) {
        console.error('Profile error:', error);
        res.redirect('/login');
    }
});

router.get('/dashboard/photo', authToken, async (req, res) => {
    try {
        const user = req.auth_user;
        res.render('dashboard', {
            head: head_name,
            title: "Photo",
            user: user,
            board: "photo"
        });
    } catch (error) {
        console.error('Photo error:', error);
        res.redirect('/login');
    }
});

router.get('/dashboard/rm-ph', authToken, async (req, res) => {
    try{
        fs.unlinkSync("./public/uploads/"+req.auth_user.photo);
        await User.updateOne(
            {_id : req.auth_user._id},
            { $unset : { photo: ""}}
        );
        res.redirect('/dashboard/home');
    } catch (error) {
        console.log(error);
        res.status(401).send("Failed to Remove Photo.. <a href='/dashboard/home'>Click to Dashboard</a>")
    }
});

//--------------------------------- Product Section ---------------------------------------------

router.get('/dashboard/product', authToken, async (req, res) => {
    const user = req.auth_user;
    const products = await Product.find().exec();
    const result = await User.find({ role: 'farmer' }, { name: 1, phone: 1, address: 1 });
    const farmers = result.reduce((acc, farmer) => {
        acc[farmer._id] = {
          name: farmer.name,
          phone: farmer.phone,
          address: farmer.address,
        };
        return acc;
      }, {});
    res.render('dashboard', {
        head: head_name, title: "Dashboard", user, board: "product", products, farmers
    });
});

router.get('/dashboard/product/add', authToken, (req, res) => {
    const user = req.auth_user;
    res.render('dashboard', {
        head: head_name, title: "Dashboard", user, board: "addProduct"
    });
});

router.get('/dashboard/product/own', authToken, async (req, res) => {
    const user = req.auth_user;
    await updateExpire();
    const products = await Product.find({ seller: user._id });
    res.render('dashboard', {
        head: head_name, title: "Dashboard", user, board: "ownProduct", products
    });
});

router.get('/product/orders', authToken, async (req, res) => {
    const user = req.auth_user;
    await updateExpire();
    const orders = await Order.aggregate([
        { $match: {buyer: user._id} },
        {
            $lookup: {
                from: "products",
                localField: "product",
                foreignField: "_id",
                as: "productDetail"
            }
        },
        {
            $lookup: {
                from: "users",
                localField: "seller",
                foreignField: "_id",
                as: "sellerDetail"
            }
        },
        { $unwind: "$productDetail"},
        { $unwind: "$sellerDetail"},
        {
            $addFields: {
                statusOrder: {
                    $switch: {
                        branches: [
                            { case: { $eq: ["$status", "pending"] }, then: 0},
                            { case: { $eq: ["$status", "accepted"] }, then: 1 },
                            { case: { $eq: ["$status", "completed"] }, then: 2 }
                        ],
                        default: 3
                    }
                }
            }
        },
        {
            $project: {
                "productDetail.photo":1,
                "sellerDetail.photo":1,
                "productDetail.name":1,
                "productDetail.location":1,
                "sellerDetail.name":1,
                "sellerDetail.phone":1,
                "sellerDetail.address":1,
                "productDetail.price":1,
                statusOrder: 1,
                quantity: 1,
                status: 1,
                requested: 1,
                code: 1,
            }
        },
        {
            $sort: { statusOrder: 1, requested: -1 }
        },
    ]);

    res.render('dashboard', {
        head: head_name, title: "Dashboard", user, board: "orders", orders,
    });
});

router.get('/product/request', authToken, async (req, res) => {
    const user = req.auth_user;
    await updateExpire();
    const requests = await Order.aggregate([
        { $match: {seller: user._id}},
        {
            $lookup: {
                from: "products",
                localField: "product",
                foreignField: "_id",
                as: "productDetail"
            }
        },
        {
            $lookup: {
                from: "users",
                localField: "buyer",
                foreignField: "_id",
                as: "buyerDetail"
            }
        },
        { $unwind: "$productDetail" },
        { $unwind: "$buyerDetail" },
        {
            $addFields: {
                statusOrder: {
                    $switch: {
                        branches: [
                            { case: { $eq: ["$status", "pending"] }, then: 0},
                            { case: { $eq: ["$status", "accepted"] }, then: 1 },
                            { case: { $eq: ["$status", "completed"] }, then: 2 }
                        ],
                        default: 3
                    }
                }
            }
        },
        {
            $project: {
                "productDetail.photo": 1,
                "buyerDetail.photo": 1,
                "productDetail.name": 1,
                "productDetail.location": 1,
                "buyerDetail.name": 1,
                "buyerDetail.phone": 1,
                "buyerDetail.address": 1,
                "buyerDetail.role": 1,
                "productDetail.price": 1,
                quantity: 1,
                status: 1,
                requested: 1,
                statusOrder: 1
            }
        },
        {
            $sort: { statusOrder: 1, requested: -1 }
        },
    ]);
    res.render('dashboard', {
        head: head_name, title: "Dashboard", user, board: "request", requests
    });
});

router.get('/logout', (req, res) => {
    // Clear the authentication cookie
    res.clearCookie('json', {
        httpOnly: true,
        secure: false,
        sameSite: 'strict',
        path: '/'
    });
    
    // Clear any session data
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
        }
    });
    
    // Redirect to welcome page
    res.redirect('/');
});

// Retailer Registration Route
router.get('/retailers/register', (req, res) => {
    res.render('retailers/register');
});

console.log(`Server Started at http://${getIp()}:${process.env.PORT}`);

module.exports = router;