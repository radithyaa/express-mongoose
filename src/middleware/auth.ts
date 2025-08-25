import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { User } from '../models/User';
import { IAuthenticatedRequest, IJWTPayload, UserRole, IApiError } from '../types';

// Extend Express Request interface
declare global {
  namespace Express {
    interface Request {
      user?: import('../types').IUser;
    }
  }
}

// Generate JWT tokens
export const generateTokens = (userId: string): { accessToken: string; refreshToken: string } => {
  const accessToken = jwt.sign(
    { userId } as IJWTPayload, 
    process.env.JWT_SECRET as string, 
    { expiresIn: process.env.JWT_EXPIRE || '15m' }
  );
  
  const refreshToken = jwt.sign(
    { userId } as IJWTPayload, 
    process.env.JWT_REFRESH_SECRET as string, 
    { expiresIn: process.env.JWT_REFRESH_EXPIRE || '7d' }
  );
  
  return { accessToken, refreshToken };
};

// Middleware to verify JWT token
export const authenticate = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    // Get token from header
    const authHeader = req.header('Authorization');
    const token = authHeader?.startsWith('Bearer ') 
      ? authHeader.substring(7) 
      : null;

    if (!token) {
      const error: IApiError = { 
        error: 'Access denied', 
        message: 'No token provided' 
      };
      res.status(401).json(error);
      return;
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as IJWTPayload;
    
    // Find user
    const user = await User.findById(decoded.userId).select('-password -refreshTokens');
    if (!user) {
      const error: IApiError = { 
        error: 'Access denied', 
        message: 'Invalid token - user not found' 
      };
      res.status(401).json(error);
      return;
    }

    if (!user.isActive) {
      const error: IApiError = { 
        error: 'Access denied', 
        message: 'Account is deactivated' 
      };
      res.status(401).json(error);
      return;
    }

    req.user = user;
    next();
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      const apiError: IApiError = { 
        error: 'Access denied', 
        message: 'Invalid token' 
      };
      res.status(401).json(apiError);
      return;
    }
    
    if (error instanceof jwt.TokenExpiredError) {
      const apiError: IApiError = { 
        error: 'Access denied', 
        message: 'Token expired' 
      };
      res.status(401).json(apiError);
      return;
    }
    
    console.error('Authentication error:', error);
    const apiError: IApiError = { 
      error: 'Internal server error',
      message: 'Authentication failed' 
    };
    res.status(500).json(apiError);
  }
};

// Middleware to check user roles
export const authorize = (...roles: UserRole[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      const error: IApiError = { 
        error: 'Access denied', 
        message: 'Authentication required' 
      };
      res.status(401).json(error);
      return;
    }

    if (!roles.includes(req.user.role)) {
      const error: IApiError = { 
        error: 'Forbidden', 
        message: 'Insufficient permissions' 
      };
      res.status(403).json(error);
      return;
    }

    next();
  };
};

// Middleware for optional authentication (won't fail if no token)
export const optionalAuth = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const authHeader = req.header('Authorization');
    const token = authHeader?.startsWith('Bearer ') 
      ? authHeader.substring(7) 
      : null;

    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as IJWTPayload;
      const user = await User.findById(decoded.userId).select('-password -refreshTokens');
      if (user?.isActive) {
        req.user = user;
      }
    }
    
    next();
  } catch (error) {
    // Continue without authentication
    next();
  }
};