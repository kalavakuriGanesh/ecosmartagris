require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Admin = require('../models/admin');

// Connect to MongoDB
mongoose.connect(process.env.DB_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

async function setupAdmin() {
    try {
        // Check if admin already exists
        const existingAdmin = await Admin.findOne({ email: 'admin@eco.com' });
        if (existingAdmin) {
            console.log('Admin account already exists');
            process.exit(0);
        }

        // Create new admin account
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash('admin123', salt); // Change 'admin123' to your desired password

        const admin = new Admin({
            name: 'Admin',
            email: 'admin@eco.com',
            password: hashedPassword,
            phone: '12345789',
            role: 'admin',
            createdAt: new Date()
        });

        await admin.save();
        console.log('Admin account created successfully');
        process.exit(0);
    } catch (error) {
        console.error('Error creating admin account:', error);
        process.exit(1);
    }
}

setupAdmin(); 