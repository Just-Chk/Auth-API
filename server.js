const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
app.use(express.json());

const config = require('./config');
const uri = config.mongodbUri;       

const client = new MongoClient(uri);

const dbName = "day-16";
const usersCollectionName = "assignment";

const JWT_SECRET = "MyLittleFellowMartians";

let db, usersCollection;

let tokenBlacklist = [];

setInterval(() => 
{
    tokenBlacklist = tokenBlacklist.filter(token => 
    {
        try {
            const decoded = jwt.decode(token);
            if (decoded && decoded.exp) {
                return decoded.exp * 1000 > Date.now();
            }
            return false;
        } 
        
        catch 
        {
            return false;
        }
    });
    console.log(`Cleaned token blacklist. Current size: ${tokenBlacklist.length}`);
}, 3600000);

async function connectToMongoDB() 
{
    try 
    {
        await client.connect();
        console.log("Connected to MongoDB Atlas");
        db = client.db(dbName);
        usersCollection = db.collection(usersCollectionName);
        
        await usersCollection.createIndex({ email: 1 }, { unique: true });
    } 
    
    catch (error) 
    {
        console.error("MongoDB connection error:", error.message);
        process.exit(1);
    }
}

connectToMongoDB();

function authenticateToken(req, res, next) 
{
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) 
    {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }
    
    if (tokenBlacklist.includes(token)) 
    {
        return res.status(401).json({ error: 'Token has been invalidated. Please login again.' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) 
        {
            return res.status(403).json({ error: 'Invalid or expired token.' });
        }
        req.user = user;
        req.token = token;
        next();
    });
}

function requireAdmin(req, res, next) 
{
    if (req.user && req.user.role === 'admin') 
    {
        next();
    } 
    
    else 
    {
        return res.status(403).json({ error: 'Access denied. Admin privileges required.' });
    }
}

app.post('/signup', async (req, res) => 
{
    try 
    {
        const { name, email, password, role } = req.body;
        
        if (!name || !email || !password) 
        {
            return res.status(400).json({ error: 'Name, email and password are required' });
        }
        
        const existingUser = await usersCollection.findOne({ email: email });
        if (existingUser) 
        {
            return res.status(400).json({ error: 'Email already registered' });
        }
        
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        let userRole = 'user';
        if (role && (role === 'admin' || role === 'user')) 
        {
            userRole = role;
        }
        
        const newUser = 
        {
            name,
            email,
            password: hashedPassword,
            role: userRole,
            createdAt: new Date(),
            updatedAt: new Date()
        };
        
        const result = await usersCollection.insertOne(newUser);
        
        const { password: _, ...userWithoutPassword } = newUser;
        
        res.status(201).json
        ({ 
            message: 'User created successfully',
            user: { ...userWithoutPassword, _id: result.insertedId }
        });
    } 
    
    catch (error) 
    {
        console.error("Error creating user:", error.message);
        
        if (error.code === 11000) 
        {
            res.status(400).json({ error: 'Email already registered' });
        } 
        
        else 
        {
            res.status(500).json({ error: 'Failed to create user' });
        }
    }
});

app.post('/login', async (req, res) => 
{
    try 
    {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        
        const user = await usersCollection.findOne({ email: email });
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        const isPasswordValid = await bcrypt.compare(password, user.password);
        
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        const token = jwt.sign(
            { 
                userId: user._id,
                email: user.email,
                name: user.name,
                role: user.role || 'user'
            }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );
        
        const { password: _, ...userWithoutPassword } = user;
        
        res.json({
            message: 'Login successful',
            token,
            user: userWithoutPassword
        });
    } 
    
    catch (error) 
    {
        console.error("Error logging in:", error.message);
        res.status(500).json({ error: 'Failed to login' });
    }
});

app.post('/logout', authenticateToken, async (req, res) => 
{
    try 
    {
        tokenBlacklist.push(req.token);
        
        res.json({
            message: 'Logout successful. Token invalidated.'
        });
    } 
    
    catch (error) 
    {
        console.error("Error during logout:", error.message);
        res.status(500).json({ error: 'Failed to logout' });
    }
});

app.get('/admin/users', authenticateToken, requireAdmin, async (req, res) => 
{
    try 
    {
        const users = await usersCollection.find(
            {},
            { projection: { password: 0 } }
        ).toArray();
        
        res.json
        ({
            message: 'Admin access granted',
            totalUsers: users.length,
            users
        });
    } 
    
    catch (error) 
    {
        console.error("Error fetching users:", error.message);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.delete('/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => 
{
    try 
    {
        const userId = req.params.id;
        
        if (userId === req.user.userId) 
        {
            return res.status(400).json({ error: 'Cannot delete your own account' });
        }
        
        const result = await usersCollection.deleteOne(
            { _id: new ObjectId(userId) }
        );
        
        if (result.deletedCount === 0) 
        {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({
            message: 'User deleted successfully'
        });
    } 
    
    catch (error) 
    {
        console.error("Error deleting user:", error.message);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

app.patch('/admin/users/:id/role', authenticateToken, requireAdmin, async (req, res) => 
{
    try 
    {
        const userId = req.params.id;
        const { role } = req.body;
        
        if (!role || (role !== 'admin' && role !== 'user')) {
            return res.status(400).json({ error: 'Valid role (admin or user) is required' });
        }
        
        // Prevent admin from changing their own role
        if (userId === req.user.userId) {
            return res.status(400).json({ error: 'Cannot change your own role' });
        }
        
        const result = await usersCollection.updateOne(
            { _id: new ObjectId(userId) },
            { 
                $set: { 
                    role: role,
                    updatedAt: new Date()
                } 
            }
        );
        
        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({
            message: 'User role updated successfully',
            userId,
            newRole: role
        });
    } 
    
    catch (error) 
    {
        console.error("Error updating user role:", error.message);
        res.status(500).json({ error: 'Failed to update user role' });
    }
});

app.get('/profile', authenticateToken, async (req, res) => 
{
    try 
    {
        const user = await usersCollection.findOne(
            { _id: new ObjectId(req.user.userId) },
            { projection: { password: 0 } }
        );
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({
            message: 'Profile accessed successfully',
            user
        });
    } 
    
    catch (error) 
    {
        console.error("Error fetching profile:", error.message);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

process.on('SIGINT', async () => 
{
    await client.close();
    console.log('MongoDB connection closed');
    process.exit(0);
});

app.listen(3000, () => console.log('Server: http://localhost:3000'));