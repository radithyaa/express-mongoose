const express = require('express');
const { authenticate, authorize, optionalAuth } = require('../middleware/auth');

const router = express.Router();

// @route   GET /api/protected/user
// @desc    Protected route for authenticated users
// @access  Private
router.get('/user', authenticate, (req, res) => {
  res.json({
    success: true,
    message: 'This is a protected route for authenticated users',
    data: {
      user: req.user,
      timestamp: new Date().toISOString()
    }
  });
});

// @route   GET /api/protected/admin
// @desc    Protected route for admin users only
// @access  Private/Admin
router.get('/admin', authenticate, authorize('admin'), (req, res) => {
  res.json({
    success: true,
    message: 'This is a protected route for admin users only',
    data: {
      user: req.user,
      timestamp: new Date().toISOString()
    }
  });
});

// @route   GET /api/protected/moderator
// @desc    Protected route for moderators and admins
// @access  Private/Moderator
router.get('/moderator', authenticate, authorize('moderator', 'admin'), (req, res) => {
  res.json({
    success: true,
    message: 'This is a protected route for moderators and admins',
    data: {
      user: req.user,
      timestamp: new Date().toISOString()
    }
  });
});

// @route   GET /api/protected/optional
// @desc    Route with optional authentication
// @access  Public/Optional Auth
router.get('/optional', optionalAuth, (req, res) => {
  const message = req.user 
    ? `Hello ${req.user.firstName}, you are authenticated!`
    : 'Hello guest, you can access this route without authentication';

  res.json({
    success: true,
    message,
    data: {
      user: req.user || null,
      isAuthenticated: !!req.user,
      timestamp: new Date().toISOString()
    }
  });
});

module.exports = router;