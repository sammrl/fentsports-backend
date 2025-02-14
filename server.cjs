// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const nacl = require('tweetnacl');
const bs58 = require('bs58').default;
const { TextEncoder } = require('util');
const jwt = require('jsonwebtoken'); // JWT session tokens
require('dotenv').config();

const app = express();

// Constants for JWT
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';
const SESSION_DURATION = 10 * 60; 

// JSON parsing middleware 
app.use(express.json());
// Configure CORS middleware:
app.use(cors({
  origin: process.env.FRONTEND_URL,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Connect to MongoDB 
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB connection error:", err));

/**
 * Define the Score schema and model.
 */
const scoreSchema = new mongoose.Schema({
  wallet: String,
  game: String,
  score: Number,
  name: { type: String, default: "" },
  timestamp: { type: Date, default: Date.now },
});
const Score = mongoose.model('Score', scoreSchema);

/**
 * Define the User schema and model.
 * This will track unique wallet addresses that have connected.
 */
const userSchema = new mongoose.Schema({
  wallet: { type: String, unique: true, required: true },
  name: { type: String, maxlength: 10 },
  createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model('User', userSchema);

/**
 * Registration Endpoint
 * This endpoint allows a new user to register their wallet.
 */
app.post('/api/register', async (req, res) => {
  try {
    // Destructure the skip flag along with other fields.
    const { wallet, signature, message, name, skip } = req.body;
    
    if (!wallet) {
      return res.status(400).json({ error: 'Missing wallet' });
    }
    
    if (!skip) {
      // When not skipping, signature and message are required.
      if (!signature || !message) {
        return res.status(400).json({ error: 'Missing required fields' });
      }
  
      // Verify the signature using tweetnacl
      const publicKey = bs58.decode(wallet);
      const sig = bs58.decode(signature);
      const messageBytes = new TextEncoder().encode(message);
      const isValid = nacl.sign.detached.verify(messageBytes, sig, publicKey);
      if (!isValid) {
        return res.status(400).json({ error: 'Invalid signature' });
      }
    }
    
    // Check if the user already exists; if not, create a new user including the provided name.
    let user = await User.findOne({ wallet });
    if (!user) {
      user = new User({ wallet, name });
      await user.save();
      console.log("New user registered:", wallet, "with name:", name);
    } else {
      console.log("User already registered:", wallet);
    }
  
    res.json({ success: true, user });
  } catch (error) {
    console.error("Error in registration:", error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * Generate a JWT session token valid for a limited duration.
 */
app.post('/api/session', (req, res) => {
  const { wallet, game } = req.body;
  if (!wallet || !game) {
    return res.status(400).json({ error: 'Missing wallet or game' });
  }
  const payload = { wallet, game };
  const sessionToken = jwt.sign(payload, JWT_SECRET, { expiresIn: SESSION_DURATION });
  res.json({ sessionToken });
});

/**
 * POST endpoint to log scores.
 */
app.post('/api/score', async (req, res) => {
  try {
    const { wallet, game, score, sessionToken, clientSignature, signatureMessage } = req.body;
    if (!wallet || !game || score === undefined || !sessionToken || !clientSignature || !signatureMessage) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Verify the session token
    let sessionPayload;
    try {
      sessionPayload = jwt.verify(sessionToken, JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired session token' });
    }
    
    // Ensure the session token matches the request
    if (sessionPayload.wallet !== wallet || sessionPayload.game !== game) {
      return res.status(401).json({ error: 'Session token does not match the request' });
    }

    // Verify the client's cryptographic signature
    const messageBytes = new TextEncoder().encode(signatureMessage);
    const sigBytes = bs58.decode(clientSignature);
    const walletPublicKey = bs58.decode(wallet);
    const isValidSignature = nacl.sign.detached.verify(messageBytes, sigBytes, walletPublicKey);
    if (!isValidSignature) {
      return res.status(401).json({ error: 'Invalid client signature' });
    }

    // Look up registered user to obtain their name (if registered)
    let userName = "";
    const user = await User.findOne({ wallet });
    if (user && user.name) {
      userName = user.name;
    }

    // Save the score with the user's name if available
    const newScore = new Score({ wallet, game, score, name: userName });
    await newScore.save();
    console.log('Score saved successfully for wallet:', wallet);
    return res.json({ success: true });
  } catch (error) {
    console.error("Unexpected error in /api/score:", error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET endpoint to retrieve the best score for a specific user and game.
 */
app.get('/api/bestscore', async (req, res) => {
  console.log("GET /api/bestscore called with query:", req.query);
  const { wallet, game } = req.query;
  if (!wallet || !game) {
    return res.status(400).json({ error: 'Missing wallet or game query parameter' });
  }
  try {
    // Find the highest score entry for this wallet and game.
    const best = await Score.findOne({ wallet, game }).sort({ score: -1 });
    return res.json({ best });
  } catch (error) {
    console.error("Error retrieving best score:", error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET endpoint to retrieve leaderboard data for a specific game.
 */
app.get('/api/leaderboard', async (req, res) => {
  const { game } = req.query;
  if (!game) return res.status(400).json({ error: 'Missing game query parameter' });
  try {
    // Find the top 50 scores for the specified game, sorted descending by score.
    const scores = await Score.find({ game }).sort({ score: -1 }).limit(50);
    res.json({ scores });
  } catch (error) {
    console.error("Error retrieving leaderboard:", error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// New endpoint to check registration status for a wallet
app.get('/api/user', async (req, res) => {
  const { wallet } = req.query;
  if (!wallet) {
    return res.status(400).json({ error: 'Missing wallet parameter' });
  }
  try {
    const user = await User.findOne({ wallet });
    if (user) {
      return res.json({ registered: true, name: user.name });
    } else {
      return res.json({ registered: false });
    }
  } catch (error) {
    console.error("Error checking user registration:", error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Listen on port 5001
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));