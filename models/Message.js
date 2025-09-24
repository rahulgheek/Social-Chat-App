const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
    conversationId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Conversation', // The conversation this message belongs to
        required: true
    },
    sender: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User', // The user who sent the message
        required: true
    },
    text: {
        type: String,
        required: true,
        trim: true
    },
    seenBy: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User' // An array of user IDs who have seen this message
    }]
}, {
    timestamps: true
});

const Message = mongoose.model('Message', messageSchema);

module.exports = Message;

