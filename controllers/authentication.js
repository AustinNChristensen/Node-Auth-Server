const User = require('../models/user');
const jwt = require('jwt-simple');
const config = require('../config');

function tokenForUser(user) {
    const timestamp = new Date().getTime();
    return jwt.encode({ sub: user.id, iat: timestamp}, config.secret);
}  

exports.signin = function(req, res, next){
    // user has been authed, just need token
    res.send({ token: tokenForUser(req.user) })
}

exports.signup = function(req, res, next) {
    const email = req.body.email;
    const password = req.body.password;
    if(!email || !password){
        return res.status(422).send({error: 'Both an email and password are required'})
    }
    // check if user with email exists
    User.findOne({ email: email }, function(err, existingUser){
        if (err) { return next(err); }
        // if exists, return error
        if(existingUser){
            return res.status(422).send({ error: 'Email is already in use' });
        }
        // else, create and save record
        const user = new User({
            email: email, 
            password: password
        })

        user.save(function(err){
            if (err) { return next(err) }
            console.log('in save')
            res.json({ token: tokenForUser(user) })
        });
    })
}