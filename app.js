// Load environment variables from .env file
require("dotenv").config();

// Import necessary modules
const express = require("express");
const session = require("express-session");
const MongoDBStore = require("connect-mongodb-session")(session);
const bcrypt = require("bcrypt");
const saltRounds = 12;
const Joi = require("joi");

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;
const ExpireTime = 60 * 60 * 1000; // 1 hour

// Import database connection
const { database } = require("./databaseConnection");

// Connect to MongoDB and start the server
const userCollection = database
  .db(process.env.MONGODB_DATABASE)
  .collection("users");

// Middleware configuration
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from the "public" directory
app.use(express.static(__dirname + "/public"));

// Configure session store with MongoDB
var mongoStore = new MongoDBStore({
  uri: `mongodb+srv://${process.env.MONGODB_USER}:${encodeURIComponent(process.env.MONGODB_PASSWORD)}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`,
  collection: "sessions",
});

// Session configuration
app.use(
  session({
    secret: process.env.NODE_SESSION_SECRET,
    store: mongoStore,
    resave: true,
    saveUninitialized: false,
    cookie: {
      maxAge: ExpireTime,
    },
  }),
);

// Home Page
app.get("/", (req, res) => {
  if (req.session.authenticated) {
    res.send(`
            <h1>Hello, ${req.session.name}!</h1>
            <a href="/members"><button>Go to Members Area</button></a><br><br>
            <a href="/logout"><button>Logout</button></a>
        `);
  } else {
    res.send(`
            <h1>Welcome to the Home Page</h1>
            <a href="/signup"><button>Sign Up</button></a><br><br>
            <a href="/login"><button>Login</button></a>
        `);
  }
});

// Sign Up Page
app.get("/signup", (req, res) => {
  res.send(`<h2>Sign Up</h2>
        <form action="/submitSignup" method="POST">
        <input name="name" type="text" placeholder="Name" required><br><br>
        <input name="email" type="email" placeholder="Email" required><br><br>
        <input name="password" type="password" placeholder="Password" required><br><br>
        <button type="submit">Sign Up</button>
        </form>
    `);
});

// Handle Sign Up form submission
app.post("/submitSignup", async (req, res) => {
  // Extract user input from the request body
  var name = req.body.name;
  var email = req.body.email;
  var password = req.body.password;

  // Validate user input
  if (!name)
    return res.send(`Name is required. <a href="/signup">Try again</a>`);
  if (!email)
    return res.send(`Email is required. <a href="/signup">Try again</a>`);
  if (!password)
    return res.send(`Password is required. <a href="/signup">Try again</a>`);

  // Define a Joi schema for validating the user input
  const schema = Joi.object({
    name: Joi.string().alphanum().max(30).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  // Validate the user input against the schema
  const { error } = schema.validate({ name, email, password });

  // If validation fails, redirect back to the signup page with an error message
  if (error) {
    return res.redirect(
      "/signup?error=" + encodeURIComponent(error.details[0].message),
    );
  }

  // Check if the email is already registered
  var hashPassword = await bcrypt.hash(password, saltRounds);

  // Insert the new user into the database
  await userCollection.insertOne({
    name: name,
    email: email,
    password: hashPassword,
  });

  // Set session variables and redirect to the members area
  req.session.authenticated = true;
  req.session.name = name;
  res.redirect("/members");
});

// Login Page
app.get("/login", (req, res) => {
  res.send(`
        <h2>log in</h2>
        <form action='/submitLogin' method='post'>
            <input name='email' type='text' placeholder='email'><br>
            <input name='password' type='password' placeholder='password'><br>
            <button>Submit</button>
        </form>
    `);
});

// Handle Login form submission
app.post("/submitLogin", async (req, res) => {
  // Extract user input from the request body
  var email = req.body.email;
  var password = req.body.password;

  // Validate user input
  const schema = Joi.string().email().required();
  const validationResult = schema.validate(email);

  // If validation fails, redirect back to the login page with an error message
  if (validationResult.error != null) {
    return res.send(
      `Invalid email/password combination. <a href="/login">Try again</a>`,
    );
  }

  // Query the database for a user with the provided email
  const result = await userCollection.find({ email: email }).toArray();

  // If no user is found or multiple users are found, redirect back to the login page with an error message
  if (result.length != 1) {
    return res.send(
      `Invalid email/password combination. <a href="/login">Try again</a>`,
    );
  }

  // Compare the provided password with the hashed password stored in the database
  if (await bcrypt.compare(password, result[0].password)) {
    req.session.authenticated = true;
    req.session.name = result[0].name;
    res.redirect("/members");
  } else {
    return res.send(
      `Invalid email/password combination. <a href="/login">Try again</a>`,
    );
  }
});

// Members Area, only for logged in users
app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect("/");
  }

  const randomImageId = Math.floor(Math.random() * 3) + 1;

  res.send(`
        <h1>Welcome to the Members Area, ${req.session.name}!</h1>
        <img src="/${randomImageId}.gif" style="width:250px;"><br><br>
        <a href="/logout"><button>Logout</button></a>
    `);
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// Catch all route for handling 404 Not Found
app.use((req, res) => {
  res.status(404).send(`
        <h1>404 Not Found</h1>
        <p>The page you are looking for does not exist.</p>
        <a href="/"><button>Go to Home Page</button></a>
    `);
});

// Start the server and listen on the specified port
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
