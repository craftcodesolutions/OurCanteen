const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGODB_URI = process.env.MONGODB_URI;

// MongoDB connection
let db;
const client = new MongoClient(MONGODB_URI);

async function connectToMongoDB() {
    try {
        await client.connect();
        db = client.db();
        console.log('Connected to MongoDB successfully');
    } catch (error) {
        console.error('Failed to connect to MongoDB:', error);
        process.exit(1);
    }
}

// Connect to MongoDB on startup
connectToMongoDB();

// // Handle application shutdown
// process.on('SIGINT', async () => {
//     try {
//         await client.close();
//         console.log('MongoDB connection closed');
//         process.exit(0);
//     } catch (error) {
//         console.error('Error closing MongoDB connection:', error);
//         process.exit(1);
//     }
// });

// Utility function to handle async errors
const handleAsync = (fn) => {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
};

// Middleware for validating ObjectId parameters
const validateObjectId = (paramName) => {
    return (req, res, next) => {
        const id = req.params[paramName];
        if (!id || !ObjectId.isValid(id)) {
            return res.status(400).json({ error: `Invalid ${paramName} format` });
        }
        next();
    };
};

// Middleware (Optional)
app.use(express.json());

app.use(cors({
    origin: '*',
    credentials: true
}));


const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

const validateSignup = (req, res, next) => {
    const { name, email, password, institute, studentId, phoneNumber } = req.body;

    if (!name || !email || !password || !institute || !studentId || !phoneNumber) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    next();
};

app.post('/api/auth/signup', validateSignup, handleAsync(async (req, res) => {
    const { name, email, password, institute, studentId, phoneNumber } = req.body;

    // Check if user exists
    const existingUser = await db.collection('users').findOne({ email });
    if (existingUser) {
        return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = {
        name: name.trim(),
        email: email.toLowerCase().trim(),
        password: hashedPassword,
        institute: institute.trim(),
        studentId: studentId.trim(),
        phoneNumber: phoneNumber.trim(),
        isOwner: false,
        createdAt: new Date(),
        updatedAt: new Date()
    };

    const result = await db.collection('users').insertOne(user);
    const token = jwt.sign(
        { userId: result.insertedId, email: user.email, isOwner: false },
        JWT_SECRET,
        { expiresIn: '7d' }
    );

    res.status(201).json({
        token,
        user: {
            id: result.insertedId,
            name: user.name,
            email: user.email,
            institute: user.institute,
            studentId: user.studentId,
            phoneNumber: user.phoneNumber,
            isOwner: false
        }
    });
}));

app.post('/api/auth/login', handleAsync(async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await db.collection('users').findOne({
        email: email.toLowerCase().trim()
    });

    if (!user) {
        return res.status(400).json({ error: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
        return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
        { userId: user._id, email: user.email, isOwner: user.isOwner },
        JWT_SECRET,
        { expiresIn: '7d' }
    );

    res.json({
        token,
        user: {
            id: user._id,
            name: user.name,
            email: user.email,
            institute: user.institute,
            studentId: user.studentId,
            phoneNumber: user.phoneNumber,
            isOwner: user.isOwner
        }
    });
}));


app.get('/api/user/profile', authenticateToken, handleAsync(async (req, res) => {
    const user = await db.collection('users').findOne(
        { _id: new ObjectId(req.user.userId) },
        { projection: { password: 0 } }
    );

    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
}));

app.put('/api/user/profile', authenticateToken, handleAsync(async (req, res) => {
    const { name, institute, studentId, phoneNumber } = req.body;

    const updateData = {
        updatedAt: new Date()
    };

    if (name) updateData.name = name.trim();
    if (institute) updateData.institute = institute.trim();
    if (studentId) updateData.studentId = studentId.trim();
    if (phoneNumber) updateData.phoneNumber = phoneNumber.trim();

    await db.collection('users').updateOne(
        { _id: new ObjectId(req.user.userId) },
        { $set: updateData }
    );

    res.json({ message: 'Profile updated successfully' });
}));

// Institute Routes
app.get('/api/institutes', handleAsync(async (req, res) => {
    const institutes = await db.collection('institutes').find({}).toArray();
    res.json(institutes);
}));

app.post('/api/institutes', authenticateToken, handleAsync(async (req, res) => {
    const { name, location } = req.body;

    if (!name || !location) {
        return res.status(400).json({ error: 'Name and location are required' });
    }

    const institute = {
        name: name.trim(),
        location: location.trim(),
        createdAt: new Date()
    };

    const result = await db.collection('institutes').insertOne(institute);
    res.status(201).json({ id: result.insertedId, ...institute });
}));

// Restaurant Routes
app.get('/api/restaurants', handleAsync(async (req, res) => {
    const { institute, search } = req.query;
    const filter = {};

    if (institute) filter.institute = institute;
    if (search) {
        filter.$or = [
            { name: { $regex: search, $options: 'i' } },
            { location: { $regex: search, $options: 'i' } }
        ];
    }

    const restaurants = await db.collection('restaurants').find(filter)
        .sort({ createdAt: -1 })
        .toArray();
    res.json(restaurants);
}));

app.post('/api/restaurants', authenticateToken, handleAsync(async (req, res) => {
    const { name, banner, location, institute } = req.body;

    if (!name || !banner || !location || !institute) {
        return res.status(400).json({ error: 'Name, location, and institute are required' });
    }

    // Check if user already has a restaurant
    const existingRestaurant = await db.collection('restaurants').findOne({
        ownerId: new ObjectId(req.user.userId)
    });

    if (existingRestaurant) {
        return res.status(400).json({ error: 'You already have a restaurant' });
    }

    const restaurant = {
        name: name.trim(),
        location: location.trim(),
        institute: institute.trim(),
        banner: banner.trim(),
        ownerId: new ObjectId(req.user.userId),
        createdAt: new Date(),
        updatedAt: new Date()
    };

    const result = await db.collection('restaurants').insertOne(restaurant);

    // Update user to be owner
    await db.collection('users').updateOne(
        { _id: new ObjectId(req.user.userId) },
        { $set: { isOwner: true, updatedAt: new Date() } }
    );

    res.status(201).json({ id: result.insertedId, ...restaurant });
}));

app.get('/api/restaurants/my', authenticateToken, handleAsync(async (req, res) => {
    const restaurant = await db.collection('restaurants').findOne({
        ownerId: new ObjectId(req.user.userId)
    });
    res.json(restaurant);
}));

app.put('/api/restaurants/:id', authenticateToken, validateObjectId('id'), handleAsync(async (req, res) => {
    const { name, location, institute, banner } = req.body;
    const updateData = { updatedAt: new Date() };

    if (name) updateData.name = name.trim();
    if (location) updateData.location = location.trim();
    if (institute) updateData.institute = institute.trim();
    if (banner) updateData.banner = banner.trim();

    const result = await db.collection('restaurants').updateOne(
        { _id: new ObjectId(req.params.id), ownerId: new ObjectId(req.user.userId) },
        { $set: updateData }
    );

    if (result.matchedCount === 0) {
        return res.status(404).json({ error: 'Restaurant not found or access denied' });
    }

    res.json({ message: 'Restaurant updated successfully' });
}));

// Cuisine Routes
app.get('/api/cuisines', handleAsync(async (req, res) => {
    const { restaurantId } = req.query;
    const filter = restaurantId ? { restaurantId: new ObjectId(restaurantId) } : {};
    const cuisines = await db.collection('cuisines').find(filter)
        .sort({ createdAt: -1 })
        .toArray();
    res.json(cuisines);
}));

app.post('/api/cuisines', authenticateToken, handleAsync(async (req, res) => {
    const { name, photo, restaurantId } = req.body;

    if (!name || !photo || !restaurantId) {
        return res.status(400).json({ error: 'Name, photo, and restaurant ID are required' });
    }

    // Verify restaurant ownership
    const restaurant = await db.collection('restaurants').findOne({
        _id: new ObjectId(restaurantId),
        ownerId: new ObjectId(req.user.userId)
    });

    if (!restaurant) {
        return res.status(403).json({ error: 'Access denied' });
    }

    const cuisine = {
        name: name.trim(),
        photo: photo.trim(),
        restaurantId: new ObjectId(restaurantId),
        createdAt: new Date(),
        updatedAt: new Date()
    };

    const result = await db.collection('cuisines').insertOne(cuisine);
    res.status(201).json({ id: result.insertedId, ...cuisine });
}));

app.put('/api/cuisines/:id', authenticateToken, validateObjectId('id'), handleAsync(async (req, res) => {
    const { name, photo } = req.body;
    const updateData = { updatedAt: new Date() };

    if (name) updateData.name = name.trim();
    if (photo) updateData.photo = photo.trim();

    const result = await db.collection('cuisines').updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: updateData }
    );

    if (result.matchedCount === 0) {
        return res.status(404).json({ error: 'Cuisine not found' });
    }

    res.json({ message: 'Cuisine updated successfully' });
}));

app.delete('/api/cuisines/:id', authenticateToken, validateObjectId('id'), handleAsync(async (req, res) => {
    // First delete all products in this cuisine
    await db.collection('products').deleteMany({
        cuisineId: new ObjectId(req.params.id)
    });

    // Then delete the cuisine
    const result = await db.collection('cuisines').deleteOne({
        _id: new ObjectId(req.params.id)
    });

    if (result.deletedCount === 0) {
        return res.status(404).json({ error: 'Cuisine not found' });
    }

    res.json({ message: 'Cuisine deleted successfully' });
}));

// Product Routes
app.get('/api/products', handleAsync(async (req, res) => {
    const { restaurantId, cuisineId, search } = req.query;
    const filter = {};

    if (restaurantId) filter.restaurantId = new ObjectId(restaurantId);
    if (cuisineId) filter.cuisineId = new ObjectId(cuisineId);
    if (search) {
        filter.$or = [
            { name: { $regex: search, $options: 'i' } },
            { description: { $regex: search, $options: 'i' } }
        ];
    }

    const products = await db.collection('products').aggregate([
        { $match: filter },
        {
            $lookup: {
                from: 'cuisines',
                localField: 'cuisineId',
                foreignField: '_id',
                as: 'cuisine'
            }
        },
        {
            $lookup: {
                from: 'restaurants',
                localField: 'restaurantId',
                foreignField: '_id',
                as: 'restaurant'
            }
        },
        { $sort: { createdAt: -1 } }
    ]).toArray();

    res.json(products);
}));

app.post('/api/products', authenticateToken, handleAsync(async (req, res) => {
    const { name, description, price, cuisineId, restaurantId, photo } = req.body;

    if (!name || !price || !cuisineId || !restaurantId || !photo) {
        return res.status(400).json({ error: 'Name, price, cuisine ID, restaurant ID, and photo are required' });
    }

    // Verify restaurant ownership
    const restaurant = await db.collection('restaurants').findOne({
        _id: new ObjectId(restaurantId),
        ownerId: new ObjectId(req.user.userId)
    });

    if (!restaurant) {
        return res.status(403).json({ error: 'Access denied' });
    }

    const product = {
        name: name.trim(),
        description: description ? description.trim() : '',
        price: parseFloat(price),
        photo: photo.trim(),
        cuisineId: new ObjectId(cuisineId),
        restaurantId: new ObjectId(restaurantId),
        available: true,
        createdAt: new Date(),
        updatedAt: new Date()
    };

    const result = await db.collection('products').insertOne(product);
    res.status(201).json({ id: result.insertedId, ...product });
}));

app.put('/api/products/:id', authenticateToken, validateObjectId('id'), handleAsync(async (req, res) => {
    const { name, description, price, cuisineId, available, photo } = req.body;
    const updateData = { updatedAt: new Date() };

    if (name) updateData.name = name.trim();
    if (description !== undefined) updateData.description = description.trim();
    if (price) updateData.price = parseFloat(price);
    if (cuisineId) updateData.cuisineId = new ObjectId(cuisineId);
    if (available !== undefined) updateData.available = Boolean(available);
    if (photo) updateData.photo = photo.trim();

    const result = await db.collection('products').updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: updateData }
    );

    if (result.matchedCount === 0) {
        return res.status(404).json({ error: 'Product not found' });
    }

    res.json({ message: 'Product updated successfully' });
}));

app.delete('/api/products/:id', authenticateToken, validateObjectId('id'), handleAsync(async (req, res) => {
    const result = await db.collection('products').deleteOne({
        _id: new ObjectId(req.params.id)
    });

    if (result.deletedCount === 0) {
        return res.status(404).json({ error: 'Product not found' });
    }

    res.json({ message: 'Product deleted successfully' });
}));

// Order Routes
app.post('/api/orders', authenticateToken, handleAsync(async (req, res) => {
    const { restaurantId, items, totalAmount, notes } = req.body;

    if (!restaurantId || !items || !Array.isArray(items) || items.length === 0 || !totalAmount) {
        return res.status(400).json({ error: 'Restaurant ID, items, and total amount are required' });
    }

    // Validate items and calculate total
    let calculatedTotal = 0;
    const orderItems = [];

    for (const item of items) {
        const product = await db.collection('products').findOne({
            _id: new ObjectId(item.productId),
            available: true
        });

        if (!product) {
            return res.status(400).json({ error: `Product ${item.productId} not found or unavailable` });
        }

        const itemTotal = product.price * item.quantity;
        calculatedTotal += itemTotal;

        orderItems.push({
            productId: new ObjectId(item.productId),
            name: product.name,
            price: product.price,
            quantity: item.quantity,
            total: itemTotal
        });
    }

    if (Math.abs(calculatedTotal - parseFloat(totalAmount)) > 0.01) {
        return res.status(400).json({ error: 'Total amount mismatch' });
    }

    const order = {
        userId: new ObjectId(req.user.userId),
        restaurantId: new ObjectId(restaurantId),
        items: orderItems,
        totalAmount: calculatedTotal,
        notes: notes ? notes.trim() : '',
        status: 'pending',
        createdAt: new Date(),
        updatedAt: new Date()
    };

    const result = await db.collection('orders').insertOne(order);
    res.status(201).json({ id: result.insertedId, ...order });
}));

app.get('/api/orders', authenticateToken, handleAsync(async (req, res) => {
    const { status, page = 1, limit = 10 } = req.query;
    const filter = { userId: new ObjectId(req.user.userId) };

    if (status) filter.status = status;

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const orders = await db.collection('orders').aggregate([
        { $match: filter },
        {
            $lookup: {
                from: 'restaurants',
                localField: 'restaurantId',
                foreignField: '_id',
                as: 'restaurant'
            }
        },
        { $sort: { createdAt: -1 } },
        { $skip: skip },
        { $limit: parseInt(limit) }
    ]).toArray();

    const total = await db.collection('orders').countDocuments(filter);

    res.json({
        orders,
        pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total,
            pages: Math.ceil(total / parseInt(limit))
        }
    });
}));

app.get('/api/orders/restaurant', authenticateToken, handleAsync(async (req, res) => {
    const { status, page = 1, limit = 10 } = req.query;

    const restaurant = await db.collection('restaurants').findOne({
        ownerId: new ObjectId(req.user.userId)
    });

    if (!restaurant) {
        return res.status(404).json({ error: 'Restaurant not found' });
    }

    const filter = { restaurantId: restaurant._id };
    if (status) filter.status = status;

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const orders = await db.collection('orders').aggregate([
        { $match: filter },
        {
            $lookup: {
                from: 'users',
                localField: 'userId',
                foreignField: '_id',
                as: 'user'
            }
        },
        { $sort: { createdAt: -1 } },
        { $skip: skip },
        { $limit: parseInt(limit) }
    ]).toArray();

    const total = await db.collection('orders').countDocuments(filter);

    res.json({
        orders,
        pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total,
            pages: Math.ceil(total / parseInt(limit))
        }
    });
}));

// QR Code verification
app.post('/api/orders/verify-qr', authenticateToken, handleAsync(async (req, res) => {
    const { userId, orderId } = req.body;

    if (!userId || !orderId) {
        return res.status(400).json({ error: 'User ID and Order ID are required' });
    }

    const order = await db.collection('orders').findOne({
        _id: new ObjectId(orderId),
        userId: new ObjectId(userId),
        status: { $in: ['pending', 'preparing'] }
    });

    if (!order) {
        return res.status(404).json({ error: 'Order not found or already processed' });
    }

    await db.collection('orders').updateOne(
        { _id: new ObjectId(orderId) },
        {
            $set: {
                status: 'ready',
                scannedAt: new Date(),
                updatedAt: new Date()
            }
        }
    );

    // Get order details with user info
    const orderDetails = await db.collection('orders').aggregate([
        { $match: { _id: new ObjectId(orderId) } },
        {
            $lookup: {
                from: 'users',
                localField: 'userId',
                foreignField: '_id',
                as: 'user'
            }
        }
    ]).toArray();

    res.json({
        message: 'QR verified successfully',
        order: orderDetails[0]
    });
}));

app.put('/api/orders/:id/status', authenticateToken, validateObjectId('id'), handleAsync(async (req, res) => {
    const { status } = req.body;
    const validStatuses = ['pending', 'preparing', 'ready', 'completed', 'cancelled'];

    if (!validStatuses.includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }

    const updateData = {
        status,
        updatedAt: new Date()
    };

    if (status === 'completed') {
        updateData.completedAt = new Date();
    }

    const result = await db.collection('orders').updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: updateData }
    );

    if (result.matchedCount === 0) {
        return res.status(404).json({ error: 'Order not found' });
    }

    res.json({ message: 'Order status updated successfully' });
}));

// Statistics Routes
app.get('/api/statistics', authenticateToken, handleAsync(async (req, res) => {
    const restaurant = await db.collection('restaurants').findOne({
        ownerId: new ObjectId(req.user.userId)
    });

    if (!restaurant) {
        return res.status(404).json({ error: 'Restaurant not found' });
    }

    // Get date ranges
    const today = new Date();
    const startOfDay = new Date(today.getFullYear(), today.getMonth(), today.getDate());
    const endOfDay = new Date(today.getFullYear(), today.getMonth(), today.getDate() + 1);

    const startOfWeek = new Date(today.getFullYear(), today.getMonth(), today.getDate() - today.getDay());
    const startOfMonth = new Date(today.getFullYear(), today.getMonth(), 1);

    // Aggregate statistics
    const stats = await db.collection('orders').aggregate([
        { $match: { restaurantId: restaurant._id } },
        {
            $group: {
                _id: null,
                totalOrders: { $sum: 1 },
                totalRevenue: { $sum: '$totalAmount' },
                completedOrders: {
                    $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
                },
                pendingOrders: {
                    $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
                },
                todayOrders: {
                    $sum: {
                        $cond: [
                            { $and: [{ $gte: ['$createdAt', startOfDay] }, { $lt: ['$createdAt', endOfDay] }] },
                            1, 0
                        ]
                    }
                },
                todayRevenue: {
                    $sum: {
                        $cond: [
                            { $and: [{ $gte: ['$createdAt', startOfDay] }, { $lt: ['$createdAt', endOfDay] }] },
                            '$totalAmount', 0
                        ]
                    }
                },
                weeklyOrders: {
                    $sum: {
                        $cond: [{ $gte: ['$createdAt', startOfWeek] }, 1, 0]
                    }
                },
                weeklyRevenue: {
                    $sum: {
                        $cond: [{ $gte: ['$createdAt', startOfWeek] }, '$totalAmount', 0]
                    }
                },
                monthlyOrders: {
                    $sum: {
                        $cond: [{ $gte: ['$createdAt', startOfMonth] }, 1, 0]
                    }
                },
                monthlyRevenue: {
                    $sum: {
                        $cond: [{ $gte: ['$createdAt', startOfMonth] }, '$totalAmount', 0]
                    }
                }
            }
        }
    ]).toArray();

    const result = stats[0] || {
        totalOrders: 0,
        totalRevenue: 0,
        completedOrders: 0,
        pendingOrders: 0,
        todayOrders: 0,
        todayRevenue: 0,
        weeklyOrders: 0,
        weeklyRevenue: 0,
        monthlyOrders: 0,
        monthlyRevenue: 0
    };

    res.json(result);
}));

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        version: process.env.npm_package_version || '1.0.0'
    });
});

// Global error handler
app.use((error, req, res, next) => {
    console.error('Error:', error);

    // Handle path-to-regexp errors specifically
    if (error.message && error.message.includes('Missing parameter name')) {
        return res.status(400).json({
            error: 'Invalid route parameter format',
            details: 'Route parameter validation failed'
        });
    }

    res.status(500).json({
        error: process.env.NODE_ENV === 'production'
            ? 'Internal server error'
            : error.message
    });
});

// 404 handler
// app.use('*', (req, res) => {
//     res.status(404).json({ error: 'Route not found' });
// });

// Graceful shutdown
// process.on('SIGTERM', () => {
//     console.log('SIGTERM signal received: closing HTTP server');
//     app.close(() => {
//         console.log('HTTP server closed');
//         process.exit(0);
//     });
// });

if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
        console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    });
}

module.exports = app;