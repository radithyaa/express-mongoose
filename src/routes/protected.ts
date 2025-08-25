import { Router, Request, Response } from 'express';
import { authenticate, authorize, optionalAuth } from '../middleware/auth';
import { IApiResponse } from '../types';

const router = Router();

// @route   GET /api/protected/user
// @desc    Protected route for authenticated users
// @access  Private
router.get('/user', authenticate, (req: Request, res: Response<IApiResponse<{ user: any; timestamp: string }>>): void => {
  const response: IApiResponse<{ user: any; timestamp: string }> = {
    success: true,
    message: 'This is a protected route for authenticated users',
    data: {
      user: req.user,
      timestamp: new Date().toISOString()
    }
  };
  res.json(response);
});

// @route   GET /api/protected/admin
// @desc    Protected route for admin users only
// @access  Private/Admin
router.get('/admin', authenticate, authorize('admin'), (req: Request, res: Response<IApiResponse<{ user: any; timestamp: string }>>): void => {
  const response: IApiResponse<{ user: any; timestamp: string }> = {
    success: true,
    message: 'This is a protected route for admin users only',
    data: {
      user: req.user,
      timestamp: new Date().toISOString()
    }
  };
  res.json(response);
});

// @route   GET /api/protected/moderator
// @desc    Protected route for moderators and admins
// @access  Private/Moderator
router.get('/moderator', authenticate, authorize('moderator', 'admin'), (req: Request, res: Response<IApiResponse<{ user: any; timestamp: string }>>): void => {
  const response: IApiResponse<{ user: any; timestamp: string }> = {
    success: true,
    message: 'This is a protected route for moderators and admins',
    data: {
      user: req.user,
      timestamp: new Date().toISOString()
    }
  };
  res.json(response);
});

// @route   GET /api/protected/optional
// @desc    Route with optional authentication
// @access  Public/Optional Auth
router.get('/optional', optionalAuth, (req: Request, res: Response<IApiResponse<{ user: any; isAuthenticated: boolean; timestamp: string }>>): void => {
  const message = req.user 
    ? `Hello ${req.user.firstName}, you are authenticated!`
    : 'Hello guest, you can access this route without authentication';

  const response: IApiResponse<{ user: any; isAuthenticated: boolean; timestamp: string }> = {
    success: true,
    message,
    data: {
      user: req.user || null,
      isAuthenticated: !!req.user,
      timestamp: new Date().toISOString()
    }
  };
  res.json(response);
});

export default router;