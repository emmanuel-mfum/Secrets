//jshint esversion:6
require('dotenv').config() // allows us to use environment variables

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
var findOrCreate = require("mongoose-findorcreate");
const FacebookStrategy = require("passport-facebook").Strategy;





const app = express(); // initialize the app


app.set('view engine', 'ejs'); // set our view engine

app.use(bodyParser.urlencoded({
  extended: true
})); // allows us to use body-parser
app.use(express.static("public")); // set the location of our static files

app.use(session({ // set up our session
  secret:"Our little secret.",
  resave:false,
  saveUninitialized:false
}));

app.use(passport.initialize());// initialize Passport
app.use(passport.session()); //  Use Passport to manage our session

mongoose.connect("mongodb+srv://admin-emmanuel:home123@cluster0.tngp1.mongodb.net/userDB",{useNewUrlParser:true}); // connects our app to MongoDB
mongoose.set("useCreateIndex", true);// avoid deprecation warning

const userSchema = new mongoose.Schema ({ // user Schema for our users in the collection
  email:String,
  password:String,
  googleId:String,
  facebookId:String,
  secret:String
});

userSchema.plugin(passportLocalMongoose); // set our userSchema to use passportLocalMongoose as a plugin
userSchema.plugin(findOrCreate); // set our userSchema to use the findOrCreate package containing the findOrCreate method

const User = new mongoose.model("User",userSchema); // create our collection of users

passport.use(User.createStrategy()); // passportLocalMongoose creates a local login strategy
 
passport.serializeUser(function(user, done) {// simplified way of serializing users that works for all strategies
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {// simplified way of de-serializing users that works for all strategies
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({ // set up of the Google OAuth strategy
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets", // callback URL to our site
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" // avoid using Google + for retrieving user information
  },
  function(accessToken, refreshToken, profile, cb) { // callback triggered once Google authentication is completed
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({ // set up of the Facebook OAuth strategy
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets" // callback URL to our site
  },
  function(accessToken, refreshToken, profile, cb) { // callback triggered once Google authentication is completed
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req,res){ // home route
  res.render("home");

});

app.get("/auth/google", // route for authentication via Google
  passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets", // callback URL from Google to our site
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  }
);

app.get("/auth/facebook", // route for authentication via Facebook
  passport.authenticate("facebook")
);

app.get('/auth/facebook/secrets', // callback URL from Facebook to our site
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });


app.get("/login", function(req,res){ // login route
  res.render("login");

});

app.get("/register", function(req,res){ // register route
  res.render("register");

});

app.get("/secrets", function(req,res){ // route for the page with all the secrets
  User.find({"secret":{$ne:null}},function(err,foundUsers){ // checks for all users whose secret field is not null
    if(err){
      console.log(err);
    } else{
      if(foundUsers){
        res.render("secrets", {usersWithSecrets:foundUsers}); // pass the arrays of documents (users) to secrets.ejs file
      }
    }

  });
});

app.get("/submit", function(req, res){ // route for the page where users can submit secrets
  if(req.isAuthenticated()){
    res.render("submit"); // if the user is authenticated
  } else{
    res.redirect("/login"); // if there is no authentication
  }
});

app.post("/submit", function(req,res){ // route for posting of secrets
  const submittedSecret = req.body.secret; // store the secret as String into that constant
  console.log(req.user);

  User.findById(req.user.id, function(err,foundUser){ // find the current user by its id
    if(err){
      console.log(err);
    } else{
      if(foundUser){
        foundUser.secret = submittedSecret; // assign the submitted secret to the user's field secret
        foundUser.save(function(){ // save the user
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout", function(req,res){
  req.logout(); // logs out the user, ends the session
  res.redirect("/");
})

app.post("/register",function(req,res){ // local way of registration
  User.register({username:req.body.username},req.body.password, function(err,user){ // the register method gives us either an error or the new registered user
    if(err){
      console.log(err); // displays the error in the console
      res.redirect("/register"); // redirects to register page
    } else{
      passport.authenticate("local")(req,res,function(){ // set up a cookie
        res.redirect("/secrets"); // redirects to secrets page
      })
    }
  })




});

app.post("/login", function(req,res){
  const user = new User({ // tap into a user using the data sent from the form
    username:req.body.username,
    password:req.body.password
  });

  req.login(user,function(err){ // we pass the user we just created above
    if(err){
      console.log(err);
    } else{
      passport.authenticate("local")(req,res,function(){ // set up cookie
        res.redirect("/secrets");
      })
    }
  });


});

let port = process.env.PORT; // let port be the port Heroku has set up
if (port == null || port == "") { // if it is not set up or port is an empty string
  port = 3000;
}

app.listen(port, function() {
  console.log("Server has started successfully");
});
