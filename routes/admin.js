const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const Admin = require("../models/admin");
const User = require("../models/user");
const product = require("../models/product");
const order = require("../models/order");
const jwt = require("jsonwebtoken");

// Admin Authentication Middleware
const adminAuth = async (req, res, next) => {
    try {
        const token = req.cookies.json;
        if (!token) {
            return res.redirect('/admin/login');
        }
        const decoded = jwt.verify(token, process.env.BYTPASS);
        const admin = await Admin.findById(decoded.userId);
        if (!admin || admin.role !== 'admin') {
            return res.redirect('/admin/login');
        }
        req.admin = admin;
        next();
    } catch (error) {
        console.error('Admin auth error:', error);
        res.redirect('/admin/login');
    }
};

// Admin Login Routes (no auth required)
router.get("/login", (req, res) => {
    if(req.cookies.json){
        return res.redirect('/admin/dashboard');
    }
    res.render("admin/login", { 
        message: req.session.message,
        title: "Admin Login"
    });
});

router.post("/auth", async (req, res) => {
    try {
        const { email, password } = req.body;
        const admin = await Admin.findOne({ email });
        
        if (!admin) {
            req.session.message = { type: 'error', text: 'Invalid email or password' };
            return res.redirect('/admin/login');
        }

        const isValidPassword = await bcrypt.compare(password, admin.password);
        if (!isValidPassword) {
            req.session.message = { type: 'error', text: 'Invalid email or password' };
            return res.redirect('/admin/login');
        }

        // Create JWT token
        const token = jwt.sign(
            { userId: admin._id },
            process.env.BYTPASS,
            { expiresIn: process.env.JWTEXP }
        );

        // Set cookie
        res.cookie('json', token, {
            httpOnly: true,
            secure: false,
            sameSite: 'strict',
            maxAge: process.env.COOEXP * 60 * 60 * 1000,
        });

        return res.redirect('/admin/dashboard');
    } catch (error) {
        console.error('Admin auth error:', error);
        req.session.message = { type: 'error', text: 'An error occurred during login' };
        return res.redirect('/admin/login');
    }
});

// Admin Logout Route (no auth required)
router.get('/logout', (req, res) => {
    // Clear the authentication cookie
    res.clearCookie('json', {
        httpOnly: true,
        secure: false,
        sameSite: 'strict',
        path: '/',
        maxAge: 0
    });
    
    // Clear any session data
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
        }
        // Redirect to admin login page after session is destroyed
        res.redirect('/admin/login');
    });
});

// Apply admin auth middleware to all other admin routes
router.use(adminAuth);

router.post("/register", async (req, res) => {
  try {
    console.log("Request Body:", req.body);
    if (!req.body.password) {
      return res.status(400).json({ error: "Password is required" });
    }
    const existingAdmin = await Admin.findOne({ role: "admin" });
    if (existingAdmin) {
      console.log("Unauthorized access - Admin already exists");
      return res.status(403).json({ error: "Admin already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    const user = new Admin({
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
      phone: req.body.phone,
      role: "admin",
    });

    await user.save();

    console.log("Successfully created admin account");
    return res.redirect("/");
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

router.get("/dashboard", async (req, res) => {
    try {
        // Get statistics
        const totalUsers = await User.countDocuments({ role: 'customer' });
        const totalFarmers = await User.countDocuments({ role: 'farmer' });
        const totalProducts = await product.countDocuments();
        const totalOrders = await order.countDocuments();
        
        // Get recent orders
        const recentOrders = await order.find()
            .sort({ createdAt: -1 })
            .limit(5)
            .populate('product')
            .populate('buyer')
            .populate('seller');

        // Get all customers and farmers
        const customers = await User.find({ role: 'customer' }).select('name email phone address createdAt');
        const farmers = await User.find({ role: 'farmer' }).select('name email phone address createdAt');

        res.render("adminDash", {
            feature: "dashboard",
            admin: req.admin,
            stats: {
                totalUsers,
                totalFarmers,
                totalProducts,
                totalOrders
            },
            recentOrders,
            customers,
            farmers
        });
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).send("Error loading dashboard");
    }
});

router.get("/allUsers", async (req, res) => {
  try {
    const admin = await Admin.findOne();
    const usersId = admin.users;
    const users = await User.find({ _id: { $in: usersId } });
    console.log(users);
    return res.render("allUsers",{users});
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

router.get("/deleteUser/:id", async (req, res) => {
  try {
      await User.findByIdAndDelete(req.params.id);
      res.redirect("/admin/dashboard");
  } catch (error) {
      console.error(error);
      res.status(500).send("Error deleting user.");
  }
});

router.get("/loadContent", async (req, res) => {
    const feature = req.query.feature;

    try {
        switch(feature) {
            case "dashboard":
                // Get statistics
                const totalUsers = await User.countDocuments({ role: 'customer' });
                const totalFarmers = await User.countDocuments({ role: 'farmer' });
                const totalProducts = await product.countDocuments();
                const totalOrders = await order.countDocuments();
                
                // Get recent orders
                const recentOrders = await order.find()
                    .sort({ createdAt: -1 })
                    .limit(5)
                    .populate('product')
                    .populate('buyer')
                    .populate('seller');

                // Get all customers and farmers
                const customers = await User.find({ role: 'customer' }).select('name email phone address createdAt');
                const farmers = await User.find({ role: 'farmer' }).select('name email phone address createdAt');

                res.render("admin/dashboard", {
                    stats: {
                        totalUsers,
                        totalFarmers,
                        totalProducts,
                        totalOrders
                    },
                    recentOrders,
                    customers,
                    farmers
                });
                break;

            case "users":
                const allCustomers = await User.find({ role: 'customer' }).select('name email phone address createdAt');
                res.render("admin/users", { users: allCustomers });
                break;

            case "farmers":
                const allFarmers = await User.find({ role: 'farmer' })
                    .select('name email phone address createdAt')
                    .sort({ createdAt: -1 });
                res.render("admin/farmers", { 
                    farmers: allFarmers,
                    message: req.session.message
                });
                break;

            case "products":
                const allProducts = await product.find()
                    .populate('seller', 'name email')
                    .sort({ createdAt: -1 });
                res.render("admin/products", { 
                    products: allProducts,
                    message: req.session.message
                });
                break;

            case "orders":
                const allOrders = await order.find()
                    .populate('product')
                    .populate('buyer')
                    .populate('seller')
                    .sort({ createdAt: -1 });
                res.render("admin/orders", { 
                    orders: allOrders,
                    message: req.session.message
                });
                break;

            case "settings":
                res.render("admin/settings", { 
                    admin: req.admin,
                    message: req.session.message
                });
                break;

            default:
                res.status(400).send("<p class='text-danger'>Invalid Feature Selected</p>");
        }
    } catch (error) {
        console.error('Load content error:', error);
        res.status(500).send("<p class='text-danger'>Error loading content.</p>");
    }
});

// Add user search functionality
router.get("/searchUsers", async (req, res) => {
    try {
        const { query } = req.query;
        const users = await User.find({
            $or: [
                { name: { $regex: query, $options: 'i' } },
                { email: { $regex: query, $options: 'i' } },
                { phone: { $regex: query, $options: 'i' } }
            ]
        });
        res.json(users);
    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ error: 'Search failed' });
    }
});

// Add order search functionality
router.get("/searchOrders", adminAuth, async (req, res) => {
    try {
        const { search, status, date } = req.query;
        let query = {};

        if (search) {
            query.$or = [
                { '_id': { $regex: search, $options: 'i' } },
                { 'product.name': { $regex: search, $options: 'i' } },
                { 'buyer.name': { $regex: search, $options: 'i' } },
                { 'seller.name': { $regex: search, $options: 'i' } }
            ];
        }

        if (status) {
            query.status = status;
        }

        if (date) {
            const startDate = new Date(date);
            const endDate = new Date(date);
            endDate.setDate(endDate.getDate() + 1);
            query.createdAt = { $gte: startDate, $lt: endDate };
        }

        const orders = await order.find(query)
            .populate('product')
            .populate('buyer', 'name email phone')
            .populate('seller', 'name email phone')
            .sort({ createdAt: -1 });

        res.json({ orders });
    } catch (error) {
        console.error('Search orders error:', error);
        res.status(500).json({ error: 'Search failed' });
    }
});

// Get single order details
router.get("/getOrder/:id", adminAuth, async (req, res) => {
    try {
        const orderDetails = await order.findById(req.params.id)
            .populate('product')
            .populate('buyer', 'name email phone')
            .populate('seller', 'name email phone');

        if (!orderDetails) {
            return res.status(404).json({ error: 'Order not found' });
        }

        res.json(orderDetails);
    } catch (error) {
        console.error('Get order error:', error);
        res.status(500).json({ error: 'Failed to fetch order details' });
    }
});

// Update order status
router.post("/updateOrderStatus", adminAuth, async (req, res) => {
    try {
        const { orderId, status } = req.body;
        
        const updatedOrder = await order.findByIdAndUpdate(
            orderId,
            { 
                status,
                updatedAt: new Date()
            },
            { new: true }
        ).populate('product')
         .populate('buyer', 'name email phone')
         .populate('seller', 'name email phone');

        if (!updatedOrder) {
            return res.status(404).json({ error: 'Order not found' });
        }

        // Send email notifications
        if (status === 'completed') {
            // Send completion email to buyer
            await sendEmail(
                updatedOrder.buyer.email,
                'Order Completed',
                `Your order for ${updatedOrder.product.name} has been completed.`
            );
            
            // Send notification to seller
            await sendEmail(
                updatedOrder.seller.email,
                'Order Completed',
                `Order for ${updatedOrder.product.name} has been marked as completed.`
            );
        } else if (status === 'cancelled') {
            // Send cancellation emails
            await sendEmail(
                updatedOrder.buyer.email,
                'Order Cancelled',
                `Your order for ${updatedOrder.product.name} has been cancelled.`
            );
            
            await sendEmail(
                updatedOrder.seller.email,
                'Order Cancelled',
                `Order for ${updatedOrder.product.name} has been cancelled.`
            );
        }

        res.json(updatedOrder);
    } catch (error) {
        console.error('Update order error:', error);
        res.status(500).json({ error: 'Failed to update order status' });
    }
});

module.exports = router;
