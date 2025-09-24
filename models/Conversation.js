const mongoose = require('mongoose');

const conversationSchema = new mongoose.Schema({
    participants: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User', // An array of user IDs who are in this conversation
        required: true
    }],
    lastMessage: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Message', // A reference to the most recent message
        default: null
    }
}, {
    timestamps: true
});

const Conversation = mongoose.model('Conversation', conversationSchema);

module.exports = Conversation;
