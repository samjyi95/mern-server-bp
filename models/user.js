let bcrypt = require('bcryptjs')
let mongoose = require('mongoose')

// TODO: Create user schema
let userSchema = new mongoose.Schema({
    firstname: {
        type: String,
        required: true
    },
    lastname: String,
    email: {
        type: String,
        required: true,
        unique: true,
        minlength: 6
    },
    password: {
        type: String,
        required: true,
        minlength: 1
    },
    pic: String,
    admin: {
        type: Boolean,
        default: false
    }
})

//TODO: Hash the passwords
//This is a hook, a function that runs just before you save 
userSchema.pre('save', function(done) {
    //Make sure its new, as opposed to modified
    if ( this.isNew ) {
        this.password = bcrypt.hashSync(this.password, 12)
    }
    //Tell it we're okay to move on 
    done()
})

// Make a JSON reprensentation of the user (for sending on the JWT payload)
// We're deleing password bc we dont want to pass the token back to the user their own pw when the token can be seen by everyone 
userSchema.set('toJSON', {
    transform: (doc, user) => {
        delete user.password
        delete user.lastname 
        delete user.__v
        return user
    }
})

//TODO: Make a function that compares the passwords
// think of this as one specific user and one specific user object data, this is basically referring to the user's hashed password 
userSchema.methods.validPasswords = function (typedPassword) {
//typedpassword: PLain text, just typed in by user
//this.password: Existing hashed password
    return bcrypt.compareSync(typedPassword, this.password)
} 

// TODO: Export user model
module.exports = mongoose.model('User', userSchema)
