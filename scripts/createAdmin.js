require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Admin = require('../models/admin');

async function createAdminAccount() {
    try {
        // Connect to MongoDB
        await mongoose.connect(process.env.DB_URI);
        console.log('Connected to MongoDB');

        // Check if admin already exists
        const existingAdmin = await Admin.findOne({ role: 'admin' });
        if (existingAdmin) {
            console.log('Admin account already exists');
            process.exit(0);
        }

        // Create admin account
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash('admin123', salt);

        const admin = new Admin({
            name: 'Admin',
            email: 'admin@ecosmartagri.com',
            password: hashedPassword,
            phone: '1234567890',
            role: 'admin'
        });

        await admin.save();
        console.log('Admin account created successfully');
        console.log('Email: admin@ecosmartagri.com');
        console.log('Password: admin123');

    } catch (error) {
        console.error('Error creating admin account:', error);
    } finally {
        await mongoose.disconnect();
        console.log('Disconnected from MongoDB');
        process.exit(0);
    }
}

createAdminAccount(); 