const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const User = require('../models/user');
const config = require('../config');
const LocalStrategy = require('passport-local').Strategy;

// Create local strategy
const localOptions = { usernameField: 'email' }
const localLogin = new LocalStrategy( localOptions, function(email, password, done) {
    // verify un and pass, call done w/ if success, false otherwise
    User.findOne({ email: email }, function(err, user){
        if(err){ return done(err, false) }
        if(!user){ return done(null, false) }

        // compare passwords
        user.comparePassword(password, function(err, isMatch){
            if(err){ return done(err) }
            if(!isMatch) { return done(null, false); }

            return done(null, user);
        })
    })
})

// setup jwt options for strategy
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey: config.secret
};

// create JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done){
    // is user ID in DB?
    User.findById(payload.sub, function(err, user){
        if(err){ return done(err, false) }
        // Done if yes w/ no error
        if(user){
             done(null, user);
             // else done w/o user if failed
        } else { 
            done(null, false)
        }
    })
})
// config strategy with passport
passport.use(jwtLogin);
passport.use(localLogin);
