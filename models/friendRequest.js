const mongoose = require('mongoose');

const friendRequestSchema = new mongoose.Schema({
    from: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User', // A reference to the User who sent the request
        required: true
    },
    to: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User', // A reference to the User who received the request
        required: true
    },
    status: {
        type: String,
        enum: ['pending', 'accepted', 'declined'], // The status can only be one of these values
        default: 'pending'
    }
}, {
    timestamps: true // Automatically add createdAt and updatedAt
});

const FriendRequest = mongoose.model('FriendRequest', friendRequestSchema);

module.exports = FriendRequest;
