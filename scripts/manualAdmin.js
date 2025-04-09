require('dotenv').config();
const bcrypt = require('bcryptjs');

async function generateHashedPassword() {
    const password = 'admin123';
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    console.log('Use these MongoDB commands to create the admin account:');
    console.log('\n1. Connect to MongoDB:');
    console.log(`mongosh "${process.env.DB_URI}"`);
    
    console.log('\n2. Switch to your database and insert the admin:');
    console.log(`
use your_database_name

db.admins.insertOne({
    name: "Admin",
    email: "admin@ecosmartagri.com",
    password: "${hashedPassword}",
    phone: "1234567890",
    role: "admin",
    createdAt: new Date()
})
    `);
    
    console.log('\nAfter running these commands, you can login with:');
    console.log('Email: admin@ecosmartagri.com');
    console.log('Password: admin123');
}

generateHashedPassword(); 