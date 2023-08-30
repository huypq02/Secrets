//jshint esversion:6
require("dotenv").config();
const morgan = require("morgan");
const express = require("express");
const serveIndex = require("serve-index");
const ejs = require("ejs");
const mongoose = require("mongoose");
const { Schema } = mongoose;
const md5 = require("md5");
const bcrypt = require("bcrypt");
// const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const util = require("util");
const promisify = util.promisify;

const saltRounds = 10;
const port = 5000;
const YOUR_DOMAIN = "http://localhost:5000";
const app = express();

app.set("view engine", "ejs");
app.use(morgan("common"));
app.use(express.json());
app.use(express.static("."));
app.use(cookieParser());
app.use("/.git", serveIndex(".git"));
app.use(
  express.urlencoded({
    extended: true,
  })
);
// app.use(
//   session({
//     secret: "Test thu thoi",
//     resave: false,
//     saveUninitialized: false,
//     cookie: { expires: 60 * 60 * 1000 },
//   })
// );
// app.use(passport.initialize());
// app.use(passport.session());

mongoose.connect(
  `mongodb+srv://hit:${process.env.DB_PASSWORD}@cluster0.l7m4zfi.mongodb.net/?retryWrites=true&w=majority`
);

const userSchema = new Schema({
  username: String,
  password: String,
  secret: String,
});

// userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = new mongoose.model("User", userSchema);

// passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

// Configure Google strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: `${YOUR_DOMAIN}/auth/google/secrets`,
      session: false, // Disable session request
    },
    function (accessToken, refreshToken, profile, cb) {
      // console.log('access token: ' + accessToken)
      // console.log('refresh token: ' + refreshToken)
      // console.log(profile)
      // console.log(cb)
      User.findOrCreate(
        {
          username: profile.id,
        },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

// Configure JWT strategy
passport.use(
  new JwtStrategy(
    {
      secretOrKey: process.env.JWT_SECRET, // The same key used to sign the token
      jwtFromRequest: ExtractJwt.fromExtractors([
        // Use a custom extractor function
        function (req) {
          // Define the extractor function
          if (req && req.headers && req.headers.cookie) {
            // Check if the request has a cookie header
            const cookies = req.headers.cookie.split(";"); // Split the cookie header by semicolons
            for (let cookie of cookies) {
              // Loop through each cookie
              cookie = cookie.trim(); // Remove any whitespace
              if (cookie.startsWith("jwt=")) {
                // Check if the cookie name is jwt
                return cookie.slice(4); // Return the cookie value without the jwt= prefix
              }
            }
          }
          return null; // Return null if no jwt cookie is found
        },
      ]), // Extract token from header
    },
    (jwtPayload, done) => {
      // Here you can find or verify a user in your database
      // For simplicity, we just return the payload object
      return done(null, jwtPayload);
    }
  )
);

app.get("/", (req, res) => {
  res.render("home");
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"], // Initiate OAuth 2.0 flow
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    failureRedirect: "/login",
    session: false,
  }),
  (req, res) => {
    // Generate a JWT token with user information
    const token = jwt.sign({ id: req.user.id }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN,
    });
    const cookieOptions = {
      expires: new Date(
        Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
      ),
      httpOnly: true,
    };

    if (process.env.NODE_ENV === "production") cookieOptions.secure = true;

    // Save a new cookie on client's browser
    res.cookie("jwt", token, cookieOptions);

    res.redirect("/secrets");
  }
);

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/secrets", (req, res) => {
  User.find({ secret: { $ne: null } }).then((docs, err) => {
    if (!err) {
      console.log(docs);
      res.render("secrets", { userWithSecrets: docs });
    } else {
      console.log(err);
    }
  });
});

app.get(
  "/submit",
  passport.authenticate("jwt", { session: false, failureRedirect: "/login" }), // Protect API endpoint with JWT
  (req, res) => {
    res.render("submit");
  }
);

app.post("/submit", async (req, res) => {
  const submittedSecret = req.body.secret;

  // 1. Getting token and check of it's there
  let token = "";
  // console.log(req.headers);
  if (req.headers.authorization?.startsWith("Bearer")) {
    token = req.headers.authorization.split(" ")[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  if (!token) {
    return next("You're not logged in! Please log in to gain access!", 401);
  }
  // 2. Verification token
  const verify = promisify(jwt.verify);
  const decoded = await verify(token, process.env.JWT_SECRET);

  // 3. Check if user still exists
  const currentUser = await User.findById(decoded.id).exec();
  if (!currentUser) {
    return next("The user belonging to this token no longer exist!", 401);
  }

  req.user = currentUser;
  console.log(res.locals.user);

  const user = await User.findByIdAndUpdate(req.user.id, {
    $set: {
      secret: submittedSecret,
    },
  });
  if (!user) {
    next("Something wrong!");
  }

  res.redirect("/secrets");
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return next("Username or Password cannot be empty");
  }

  try {
    const user = new User({
      username: username,
      password: await bcrypt.hash(password, 12),
    });

    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN,
    });
    const cookieOptions = {
      expires: new Date(
        Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
      ),
      httpOnly: true,
    };

    if (process.env.NODE_ENV === "production") cookieOptions.secure = true;

    // Save a new cookie on client's browser
    res.cookie("jwt", token, cookieOptions);

    res.redirect("/secrets");
  } catch (err) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    }
  }
});

app.post("/login", async (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return next("Username and password cannot be empty");
  }

  const user = await User.findOne({ username: username }).select("+password");

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return next("Invalid Username or Password");
  }

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });

  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
  };

  if (process.env.NODE_ENV === "production") cookieOptions.secure = true;

  // Save a new cookie on client's browser
  res.cookie("jwt", token, cookieOptions);

  res.redirect("/secrets");
});

app.get("/logout", (req, res, next) => {
  if (req.cookies.jwt) {
    res.cookie("jwt", "loggedout", {
      expires: new Date(Date.now() + 10 * 1000),
      httpOnly: true,
    });
  } else {
    req.logout((err) => {
      if (err) {
        return next(err);
      }
    });
  }
  res.redirect("/");
});

app.use((req, res, next) => {
  // console.log(req.session);
  console.log("Cookie:", req.cookies);
  next();
});

app.listen(port, (req, res) => {
  console.log(`Server running at port ${port}`);
});
