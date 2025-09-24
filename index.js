// 1. Import all our tools
const http = require('http');
const { WebSocketServer } = require('ws');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

// Import our Models and Middleware
const User = require('./models/User');
const FriendRequest = require('./models/friendRequest');
const Conversation = require('./models/Conversation');
const Message = require('./models/Message');
const auth = require('./middleware/auth');

// 2. Initialize the Express app
const app = express();
const server = http.createServer(app);

// CRITICAL FIX: WebSocket server setup for Render
const wss = new WebSocketServer({ 
    server,
    // Add these options for better compatibility
    perMessageDeflate: false,
    maxPayload: 1024 * 1024 // 1MB limit
});

// CRITICAL FIX: Use environment PORT (Render assigns this)
const PORT = process.env.PORT || 3000;

// 3. Add middleware with proper CORS for production
app.use(cors({
    origin: process.env.NODE_ENV === 'production' 
        ? ['https://social-chat-app-ltbi.onrender.com', 'https://your-custom-domain.com']
        : ['http://localhost:3000', 'http://127.0.0.1:3000'],
    credentials: true
}));

// Increase the payload size limit for base64 image uploads
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// CRITICAL FIX: Serve static files properly
app.use(express.static(path.join(__dirname, 'public')));

// 4. Connect to the MongoDB database with better error handling
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
    console.error('MONGODB_URI environment variable is not set');
    process.exit(1);
}

mongoose.connect(MONGODB_URI, {
    // Add these options for better reliability
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 30000, // 30 seconds
    socketTimeoutMS: 45000, // 45 seconds
    bufferCommands: false,
    maxPoolSize: 10
}).then(() => {
    console.log('Successfully connected to MongoDB Atlas!');
}).catch(err => {
    console.error('Error connecting to MongoDB:', err.message);
    // Don't exit immediately in production, retry logic would be better
    if (process.env.NODE_ENV !== 'production') {
        process.exit(1);
    }
});

// Handle MongoDB connection events
mongoose.connection.on('error', (err) => {
    console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.log('MongoDB disconnected');
});

const onlineUsers = new Map();

// --- HELPER FUNCTION FOR WEBSOCKETS ---
const notifyFriendsOfStatusChange = async (userId, status) => {
    try {
        const user = await User.findById(userId).populate('friends');
        if (!user || !user.friends) return;

        const notification = JSON.stringify({
            type: `friend_${status}`,
            user: { _id: user._id, username: user.username, avatar: user.avatar }
        });

        user.friends.forEach(friend => {
            const friendSocket = onlineUsers.get(friend._id.toString());
            if (friendSocket && friendSocket.readyState === friendSocket.OPEN) {
                try {
                    friendSocket.send(notification);
                } catch (err) {
                    console.error('Error sending WebSocket message:', err);
                    // Remove dead connections
                    onlineUsers.delete(friend._id.toString());
                }
            }
        });
    } catch (error) {
        console.error(`Error notifying friends about ${status} status:`, error);
    }
};

// --- REAL-TIME WEBSOCKET LOGIC ---
wss.on('connection', (ws) => {
    console.log('New WebSocket connection established');
    ws.userId = null;
    ws.isAlive = true;

    // CRITICAL FIX: Add ping/pong for connection health
    ws.on('pong', () => {
        ws.isAlive = true;
    });

    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);
            console.log('Received WebSocket message:', data.type);

            if (data.type === 'auth') {
                const { token } = data;
                if (!token) {
                    console.log('No token provided, closing connection');
                    return ws.close(1008, 'Token not provided.');
                }
                
                jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
                    if (err) {
                        console.log('Invalid token, closing connection:', err.message);
                        return ws.close(1008, 'Invalid token.');
                    }
                    
                    const { userId, username } = decoded;
                    ws.userId = userId;
                    ws.username = username;
                    onlineUsers.set(userId, ws);
                    
                    console.log(`${username} (${userId}) is now online.`);
                    await notifyFriendsOfStatusChange(userId, 'online');
                });
            } else if (data.type === 'chat_message') {
                if (!ws.userId) {
                    console.log('Unauthenticated message attempt');
                    return;
                }

                const { recipientId, text } = data;
                const senderId = ws.userId;

                let conversation = await Conversation.findOne({ 
                    participants: { $all: [senderId, recipientId] } 
                });
                
                if (!conversation) {
                    conversation = new Conversation({ 
                        participants: [senderId, recipientId] 
                    });
                    await conversation.save();
                }

                const newMessage = new Message({
                    conversationId: conversation._id,
                    sender: senderId,
                    text: text
                });
                await newMessage.save();

                await newMessage.populate('sender', 'username avatar');

                conversation.lastMessage = newMessage._id;
                await conversation.save();
                
                const recipientSocket = onlineUsers.get(recipientId);
                if (recipientSocket && recipientSocket.readyState === ws.OPEN) {
                    try {
                        recipientSocket.send(JSON.stringify({
                            type: 'new_message',
                            message: newMessage
                        }));
                    } catch (err) {
                        console.error('Error sending message to recipient:', err);
                        onlineUsers.delete(recipientId);
                    }
                }
            }

        } catch (error) {
            console.error('Error processing WebSocket message:', error);
        }
    });

    ws.on('close', async (code, reason) => {
        console.log(`WebSocket connection closed: ${code} - ${reason}`);
        if (ws.userId) {
            onlineUsers.delete(ws.userId);
            console.log(`User ${ws.username} (${ws.userId}) went offline.`);
            await notifyFriendsOfStatusChange(ws.userId, 'offline');
        }
    });

    ws.on('error', (error) => {
        console.error('WebSocket error:', error);
        if (ws.userId) {
            onlineUsers.delete(ws.userId);
        }
    });
});

// CRITICAL FIX: Add WebSocket health check
const interval = setInterval(() => {
    wss.clients.forEach((ws) => {
        if (!ws.isAlive) {
            console.log('Terminating dead WebSocket connection');
            if (ws.userId) {
                onlineUsers.delete(ws.userId);
            }
            return ws.terminate();
        }
        
        ws.isAlive = false;
        ws.ping();
    });
}, 30000); // Check every 30 seconds

wss.on('close', () => {
    clearInterval(interval);
});

// 5. CRITICAL FIX: Serve the frontend HTML file properly
app.get('/', (req, res) => {
    try {
        res.sendFile(path.join(__dirname, 'index.html'));
    } catch (error) {
        console.error('Error serving index.html:', error);
        res.status(500).send('Server error');
    }
});

// Add health check endpoint for Render
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

// --- API ROUTES ---
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log('Registration attempt for username:', username);
        
        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required.' });
        }
        
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'Username already taken.' });
        }
        
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        
        console.log('User registered successfully:', username);
        res.status(201).json({ message: 'User registered successfully.' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log('Login attempt for username:', username);
        
        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required.' });
        }
        
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        
        const payload = { userId: user._id, username: user.username };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '24h' });
        
        console.log('Login successful for:', username);
        res.json({ 
            token, 
            userId: user._id, 
            username: user.username, 
            avatar: user.avatar 
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

app.post('/api/friend-requests/send', auth, async (req, res) => {
    try {
        const { recipientUsername } = req.body;
        const senderId = req.user.userId;
        const recipient = await User.findOne({ username: recipientUsername });
        if (!recipient) return res.status(404).json({ message: 'User not found.' });
        const recipientId = recipient._id;
        if (senderId === recipientId.toString()) return res.status(400).json({ message: "You can't send a friend request to yourself." });
        const sender = await User.findById(senderId);
        if (sender.friends.includes(recipientId)) return res.status(400).json({ message: 'You are already friends with this user.' });
        const existingRequest = await FriendRequest.findOne({ $or: [ { from: senderId, to: recipientId }, { from: recipientId, to: senderId } ], status: 'pending' });
        if (existingRequest) return res.status(400).json({ message: 'A pending friend request already exists.' });
        const newRequest = new FriendRequest({ from: senderId, to: recipientId });
        await newRequest.save();
        res.status(201).json({ message: 'Friend request sent successfully.' });
    } catch (error) { console.error('Error sending friend request:', error); res.status(500).json({ message: 'Server error.' }); }
});

app.get('/api/friend-requests', auth, async (req, res) => {
    try {
        const userId = req.user.userId;
        const requests = await FriendRequest.find({ to: userId, status: 'pending' }).populate('from', 'username avatar');
        res.json(requests);
    } catch (error) { console.error('Error fetching friend requests:', error); res.status(500).json({ message: 'Server error.' }); }
});

app.post('/api/friend-requests/respond', auth, async (req, res) => {
    try {
        const { requestId, response } = req.body;
        const userId = req.user.userId;
        const request = await FriendRequest.findById(requestId);
        if (!request || request.to.toString() !== userId) return res.status(404).json({ message: 'Friend request not found or you are not the recipient.' });
        if (request.status !== 'pending') return res.status(400).json({ message: 'This request has already been responded to.' });
        
        request.status = response;
        await request.save();
        
        if (response === 'accepted') {
            const senderId = request.from;
            const recipientId = request.to;
            await User.findByIdAndUpdate(senderId, { $addToSet: { friends: recipientId } });
            await User.findByIdAndUpdate(recipientId, { $addToSet: { friends: senderId } });
        }
        res.json({ message: `Friend request ${response}.` });
    } catch (error) { console.error('Error responding to friend request:', error); res.status(500).json({ message: 'Server error.' }); }
});

app.get('/api/conversations/:friendId', auth, async (req, res) => {
    try {
        const { friendId } = req.params;
        const userId = req.user.userId;
        const conversation = await Conversation.findOne({ participants: { $all: [userId, friendId] } });
        if (!conversation) return res.json([]);
        const messages = await Message.find({ conversationId: conversation._id }).populate('sender', 'username avatar').sort({ createdAt: 'asc' });
        res.json(messages);
    } catch (error) { console.error('Error fetching conversation:', error); res.status(500).json({ message: 'Server error.' }); }
});

app.get('/api/friends', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).populate('friends', 'username avatar');
        if (!user) return res.status(404).json({ message: 'User not found.' });
        const friendsWithStatus = user.friends.map(friend => ({ ...friend.toObject(), isOnline: onlineUsers.has(friend._id.toString()) }));
        res.json(friendsWithStatus);
    } catch (error) { console.error('Error fetching friends:', error); res.status(500).json({ message: 'Server error.' }); }
});

app.post('/api/profile/avatar', auth, async (req, res) => {
    try {
        const { avatar } = req.body;
        if (!avatar) return res.status(400).json({ message: 'Avatar data is required.' });
        const user = await User.findByIdAndUpdate(req.user.userId, { avatar: avatar }, { new: true });
        res.json({ message: 'Avatar updated successfully.', avatar: user.avatar });
    } catch (error) { console.error('Error updating avatar:', error); res.status(500).json({ message: 'Server error updating avatar.' }); }
});

// CRITICAL FIX: Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ message: 'Internal server error' });
});

// Handle 404s - Fix for path-to-regexp error
app.use((req, res) => {
    res.status(404).json({ message: 'Route not found' });
});

// CRITICAL FIX: Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    server.close(() => {
        mongoose.connection.close();
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down gracefully');
    server.close(() => {
        mongoose.connection.close();
        process.exit(0);
    });
});

// 6. Start the server
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`MongoDB URI: ${MONGODB_URI ? 'Set' : 'Not set'}`);
    console.log(`JWT Secret: ${process.env.JWT_SECRET ? 'Set' : 'Not set'}`);
});