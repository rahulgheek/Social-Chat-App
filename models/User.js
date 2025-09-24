const mongoose = require('mongoose');

// Define the blueprint (Schema) for a User
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Username is required.'],
        unique: true, // No two users can have the same username
        trim: true,   // Removes leading/trailing whitespace
        lowercase: true // Stores the username in lowercase for easier lookups
    },
    password: {
        type: String,
        required: [true, 'Password is required.']
    },
    avatar: {
        type: String,
        default: ''
    },
    friends: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User' // A list of IDs, each referencing another User
    }]
}, {
    // Add timestamps to automatically manage createdAt and updatedAt properties
    timestamps: true
});

// Create the tool (Model) from the blueprint
const User = mongoose.model('User', userSchema);

// Export the User model to be used in other parts of our app
module.exports = User;

