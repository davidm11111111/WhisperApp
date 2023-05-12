//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');


const app = express();


app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true})

const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

//  To maintain a login session, Passport serializes and deserializes user information to and from the session.
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
        return cb(null, {
            id: user.id,
            username: user.username,
            picture: user.picture
        });
    });
});

passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
        return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    function(accessToken, refreshToken, profile, cb) {
        console.log(profile);

        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get("/", function(req, res){
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: '/login', failureMessage: true }),
    function(req, res) {
        // Successful authentication, redirect to secrets page
        res.redirect('/secrets');
    });

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", function(req, res){
    User.find({"secret": {$ne: null}})
        .then(function(foundUsers){
            if (foundUsers) {
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        })
        .catch(function(err){
            console.log(err);
        });
});

app.get("/submit", function (req, res){
    if (req.isAuthenticated()){
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", function (req, res){
    const submittedSecret = req.body.secret;
    console.log(req.user.id);

    User.findById(req.user.id)
        .then(function(foundUser) {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                return foundUser.save();
            }
        })
        .then(function() {
            res.redirect("/secrets");
        })
        .catch(function(err) {
            console.log(err);
        });
});

app.get("/logout", function (req, res){
    req.logout(function(err) {
        if (err) {
            console.log(err);
        } else {
            res.redirect("/");
        }
    });
});
//

app.post("/register", function (req, res){
    User.register({username: req.body.username}, req.body.password)
        .then(function(user){
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        })
        .catch(function(err){
            console.log(err);
            res.redirect("/register");
        });
});

app.post("/login", function(req, res){

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err){
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local", function(err, user, info) {
                if (err) {
                    console.log(err);
                } else if (!user) {
                    res.redirect("/login");
                } else {
                    req.logIn(user, function(err) {
                        if (err) {
                            console.log(err);
                        } else {
                            res.redirect("/secrets");
                        }
                    });
                }
            })(req, res);
        }
    });
});

// POST route that uses bcrypt to hash passwords and saves a new user to a MongoDB database using Mongoose
// app.post("/register", function (req, res){

    //bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    //    const newUser = new User ({
    //        email: req.body.username,
    //        password: hash
    //    });
    //    // During save, documents are encrypted. During find, documents are then decrypted
    //    newUser.save()
    //        .then(() => {
    //            res.render("secrets");
    //        })
    //        .catch((err) => {
    //            console.log(err);
    //        });
    //});
//});

// Comparing stored password hash to the provided password using bcrypt
//app.post("/login", function(req, res){
    //const username = req.body.username;
    //const password = req.body.password;
    //
    //User.findOne({email: username})
    //    .then(function(foundUser){
    //        if (foundUser) {
    //            // Load hash from password DB.
    //            bcrypt.compare(password, foundUser.password, function(err, result) {
    //                if (result === true) {
    //                    res.render("secrets");
    //                }
    //            });
    //        }
    //    })
    //    .catch(function(err){
    //        console.log(err);
    //    });
// });

app.listen(3000, function (){
    console.log("Server started on port 3000.");
});