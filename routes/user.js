const express = require('express');
const router = express.Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const mongoose = require('mongoose');

// Generate a random referral code
const generateReferralCode = () => {
  return Math.random().toString(36).substring(2, 8).toUpperCase();
};

// Middleware to protect routes
const authenticate = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  const actualToken = token.split(' ')[1]; // Extract actual token
  console.log('Received token:', actualToken);

  jwt.verify(actualToken, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.log('Token verification failed:', err);
      return res.status(401).json({ message: 'Failed to authenticate token' });
    }
    req.userId = decoded.id;
    next();
  });
};

// Register a new user
router.post('/register', [
  body('username').notEmpty().withMessage('Username is required'),
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, email, password, referralCode } = req.body;

  try {
    const newUser = new User({
      username,
      email,
      password, // No need to hash here; hash in pre-save middleware
      referralCode: generateReferralCode()
    });

    if (referralCode) {
      const referrer = await User.findOne({ referralCode });
      if (referrer) {
        newUser.referredBy = referrer._id;
        referrer.referredUsers.push(newUser._id);
        await referrer.save();
      } else {
        return res.status(400).json({ message: 'Invalid referral code' });
      }
    }

    await newUser.save();
    res.status(201).json(newUser);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login a user
router.post('/login', [
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user info including hierarchical referred users (protected route)
router.get('/:id', authenticate, async (req, res) => {
  if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
    return res.status(400).json({ message: 'Invalid user ID format' });
  }

  try {
    const userHierarchy = await fetchUserHierarchy(req.params.id);
    if (!userHierarchy) {
      return res.status(404).json({ message: 'User not found' });
    }
    delete userHierarchy.password; // Remove the password field
    res.json(userHierarchy);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Helper function to fetch user hierarchy
const fetchUserHierarchy = async (userId) => {
  const user = await User.findById(userId).lean();
  if (!user) {
    return null;
  }

  const referredUsers = await User.find({ referredBy: userId }).lean();
  user.referredUsers = await Promise.all(
    referredUsers.map(async (referredUser) => {
      const refUser = await fetchUserHierarchy(referredUser._id);
      delete refUser.password; // Remove the password field
      return refUser;
    })
  );

  return user;
};

module.exports = router;
