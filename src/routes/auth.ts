import { Router, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { User } from '../models/User';
import { generateTokens, authenticate } from '../middleware/auth';
import { validateRegister, validateLogin } from '../middleware/validation';
import { 
  IRegisterRequest, 
  ILoginRequest, 
  IApiResponse, 
  IAuthResponse, 
  IRefreshResponse,
  IJWTPayload,
  IApiError
} from '../types';

const router = Router();

// @route   POST /api/auth/register
// @desc    Register a new user
// @access  Public
router.post('/register', validateRegister, async (req: Request<{}, IApiResponse<IAuthResponse>, IRegisterRequest>, res: Response<IApiResponse<IAuthResponse> | IApiError>): Promise<void> => {
  try {
    const { username, email, password, firstName, lastName } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      const field = existingUser.email === email ? 'Email' : 'Username';
      const error: IApiError = {
        error: 'User already exists',
        message: `${field} is already registered`
      };
      res.status(409).json(error);
      return;
    }

    // Create new user
    const user = new User({
      username,
      email,
      password,
      firstName,
      lastName
    });

    await user.save();

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user._id);

    // Save refresh token to user
    user.refreshTokens.push({ token: refreshToken, createdAt: new Date() });
    await user.save();

    // Set refresh token as HTTP-only cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    const response: IApiResponse<IAuthResponse> = {
      success: true,
      message: 'User registered successfully',
      data: {
        user: user.toJSON(),
        accessToken
      }
    };
    res.status(201).json(response);
  } catch (error) {
    console.error('Registration error:', error);
    const apiError: IApiError = {
      error: 'Internal server error',
      message: 'Failed to register user'
    };
    res.status(500).json(apiError);
  }
});

// @route   POST /api/auth/login
// @desc    Login user
// @access  Public
router.post('/login', validateLogin, async (req: Request<{}, IApiResponse<IAuthResponse>, ILoginRequest>, res: Response<IApiResponse<IAuthResponse> | IApiError>): Promise<void> => {
  try {
    const { email, password } = req.body;

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      const error: IApiError = {
        error: 'Authentication failed',
        message: 'Invalid email or password'
      };
      res.status(401).json(error);
      return;
    }

    // Check if user is active
    if (!user.isActive) {
      const error: IApiError = {
        error: 'Account deactivated',
        message: 'Your account has been deactivated'
      };
      res.status(401).json(error);
      return;
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      const error: IApiError = {
        error: 'Authentication failed',
        message: 'Invalid email or password'
      };
      res.status(401).json(error);
      return;
    }

    // Clean up expired tokens
    user.removeExpiredTokens();

    // Generate new tokens
    const { accessToken, refreshToken } = generateTokens(user._id);

    // Save refresh token
    user.refreshTokens.push({ token: refreshToken, createdAt: new Date() });
    user.lastLogin = new Date();
    await user.save();

    // Set refresh token as HTTP-only cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    const response: IApiResponse<IAuthResponse> = {
      success: true,
      message: 'Login successful',
      data: {
        user: user.toJSON(),
        accessToken
      }
    };
    res.json(response);
  } catch (error) {
    console.error('Login error:', error);
    const apiError: IApiError = {
      error: 'Internal server error',
      message: 'Failed to login'
    };
    res.status(500).json(apiError);
  }
});

// @route   POST /api/auth/refresh
// @desc    Refresh access token
// @access  Public
router.post('/refresh', async (req: Request, res: Response<IApiResponse<IRefreshResponse> | IApiError>): Promise<void> => {
  try {
    const { refreshToken } = req.cookies as { refreshToken?: string };

    if (!refreshToken) {
      const error: IApiError = {
        error: 'Access denied',
        message: 'No refresh token provided'
      };
      res.status(401).json(error);
      return;
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET as string) as IJWTPayload;
    
    // Find user and check if refresh token exists
    const user = await User.findById(decoded.userId);
    if (!user || !user.refreshTokens.some(tokenObj => tokenObj.token === refreshToken)) {
      const error: IApiError = {
        error: 'Access denied',
        message: 'Invalid refresh token'
      };
      res.status(401).json(error);
      return;
    }

    if (!user.isActive) {
      const error: IApiError = {
        error: 'Account deactivated',
        message: 'Your account has been deactivated'
      };
      res.status(401).json(error);
      return;
    }

    // Generate new tokens
    const { accessToken, refreshToken: newRefreshToken } = generateTokens(user._id);

    // Remove old refresh token and add new one
    user.refreshTokens = user.refreshTokens.filter(tokenObj => tokenObj.token !== refreshToken);
    user.refreshTokens.push({ token: newRefreshToken, createdAt: new Date() });
    await user.save();

    // Set new refresh token as HTTP-only cookie
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    const response: IApiResponse<IRefreshResponse> = {
      success: true,
      message: 'Token refreshed successfully',
      data: {
        accessToken
      }
    };
    res.json(response);
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError || error instanceof jwt.TokenExpiredError) {
      const apiError: IApiError = {
        error: 'Access denied',
        message: 'Invalid refresh token'
      };
      res.status(401).json(apiError);
      return;
    }

    console.error('Token refresh error:', error);
    const apiError: IApiError = {
      error: 'Internal server error',
      message: 'Failed to refresh token'
    };
    res.status(500).json(apiError);
  }
});

// @route   POST /api/auth/logout
// @desc    Logout user (single device)
// @access  Private
router.post('/logout', authenticate, async (req: Request, res: Response<IApiResponse | IApiError>): Promise<void> => {
  try {
    const { refreshToken } = req.cookies as { refreshToken?: string };

    if (refreshToken && req.user) {
      // Remove specific refresh token
      const user = await User.findById(req.user._id);
      if (user) {
        user.refreshTokens = user.refreshTokens.filter(tokenObj => tokenObj.token !== refreshToken);
        await user.save();
      }
    }

    // Clear refresh token cookie
    res.clearCookie('refreshToken');

    const response: IApiResponse = {
      success: true,
      message: 'Logged out successfully'
    };
    res.json(response);
  } catch (error) {
    console.error('Logout error:', error);
    const apiError: IApiError = {
      error: 'Internal server error',
      message: 'Failed to logout'
    };
    res.status(500).json(apiError);
  }
});

// @route   POST /api/auth/logout-all
// @desc    Logout user from all devices
// @access  Private
router.post('/logout-all', authenticate, async (req: Request, res: Response<IApiResponse | IApiError>): Promise<void> => {
  try {
    if (req.user) {
      // Remove all refresh tokens
      const user = await User.findById(req.user._id);
      if (user) {
        user.refreshTokens = [];
        await user.save();
      }
    }

    // Clear refresh token cookie
    res.clearCookie('refreshToken');

    const response: IApiResponse = {
      success: true,
      message: 'Logged out from all devices successfully'
    };
    res.json(response);
  } catch (error) {
    console.error('Logout all error:', error);
    const apiError: IApiError = {
      error: 'Internal server error',
      message: 'Failed to logout from all devices'
    };
    res.status(500).json(apiError);
  }
});

// @route   GET /api/auth/me
// @desc    Get current user profile
// @access  Private
router.get('/me', authenticate, async (req: Request, res: Response<IApiResponse<{ user: any }> | IApiError>): Promise<void> => {
  try {
    const response: IApiResponse<{ user: any }> = {
      success: true,
      message: 'User profile retrieved successfully',
      data: {
        user: req.user
      }
    };
    res.json(response);
  } catch (error) {
    console.error('Get profile error:', error);
    const apiError: IApiError = {
      error: 'Internal server error',
      message: 'Failed to get user profile'
    };
    res.status(500).json(apiError);
  }
});

export default router;