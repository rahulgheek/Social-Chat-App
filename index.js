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
const wss = new WebSocketServer({ server });

const PORT = process.env.PORT || 3000;

// 3. Add middleware
app.use(cors());
// Increase the payload size limit for base64 image uploads
app.use(express.json({ limit: '10mb' }));

// 4. Connect to the MongoDB database
const MONGODB_URI = process.env.MONGODB_URI;
mongoose.connect(MONGODB_URI).then(() => console.log('Successfully connected to MongoDB Atlas!')).catch(err => { console.error('Error connecting to MongoDB:', err.message); process.exit(1); });

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
                friendSocket.send(notification);
            }
        });
    } catch (error) {
        console.error(`Error notifying friends about ${status} status:`, error);
    }
};


// --- REAL-TIME WEBSOCKET LOGIC ---
wss.on('connection', (ws) => {
    ws.userId = null; 

    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);

            if (data.type === 'auth') {
                const { token } = data;
                if (!token) return ws.close(1008, 'Token not provided.');
                
                jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
                    if (err) return ws.close(1008, 'Invalid token.');
                    
                    const { userId, username } = decoded;
                    ws.userId = userId;
                    ws.username = username;
                    onlineUsers.set(userId, ws);
                    
                    console.log(`${username} (${userId}) is now online.`);
                    await notifyFriendsOfStatusChange(userId, 'online');
                });
            } else if (data.type === 'chat_message') {
                if (!ws.userId) return;

                const { recipientId, text } = data;
                const senderId = ws.userId;

                let conversation = await Conversation.findOne({ participants: { $all: [senderId, recipientId] } });
                if (!conversation) {
                    conversation = new Conversation({ participants: [senderId, recipientId] });
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
                    recipientSocket.send(JSON.stringify({
                        type: 'new_message',
                        message: newMessage
                    }));
                }
            }

        } catch (error) {
            console.error('Error processing message:', error);
        }
    });

    ws.on('close', async () => {
        if (ws.userId) {
            onlineUsers.delete(ws.userId);
            console.log(`User ${ws.username} (${ws.userId}) went offline.`);
            await notifyFriendsOfStatusChange(ws.userId, 'offline');
        }
    });
});


// 5. Serve the frontend HTML file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});


// --- API ROUTES ---
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
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
        res.status(201).json({ message: 'User registered successfully.' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ message: 'Username and password are required.' });
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ message: 'Invalid credentials.' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials.' });
        
        const payload = { userId: user._id, username: user.username };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '24h' });
        
        res.json({ token, userId: user._id, username: user.username, avatar: user.avatar });
    } catch (error) { console.error('Login error:', error); res.status(500).json({ message: 'Server error during login.' }); }
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

// GET /api/friends - Get all friends for the logged-in user with their online status
app.get('/api/friends', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).populate('friends', 'username avatar');
        if (!user) return res.status(404).json({ message: 'User not found.' });
        const friendsWithStatus = user.friends.map(friend => ({ ...friend.toObject(), isOnline: onlineUsers.has(friend._id.toString()) }));
        res.json(friendsWithStatus);
    } catch (error) { console.error('Error fetching friends:', error); res.status(500).json({ message: 'Server error.' }); }
});

// POST /api/profile/avatar - Update user's profile picture
app.post('/api/profile/avatar', auth, async (req, res) => {
    try {
        const { avatar } = req.body; // Expecting a base64 data URL
        if (!avatar) return res.status(400).json({ message: 'Avatar data is required.' });
        const user = await User.findByIdAndUpdate(req.user.userId, { avatar: avatar }, { new: true });
        res.json({ message: 'Avatar updated successfully.', avatar: user.avatar });
    } catch (error) { console.error('Error updating avatar:', error); res.status(500).json({ message: 'Server error updating avatar.' }); }
});


// 6. Start the server
server.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});