import { Request, Response, NextFunction } from 'express';
import { body, validationResult, ValidationError } from 'express-validator';
import { IApiError } from '../types';

// Handle validation errors
const handleValidationErrors = (req: Request, res: Response, next: NextFunction): void => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const apiError: IApiError = {
      error: 'Validation failed',
      message: 'Please check your input data',
      details: errors.array().map((error: ValidationError) => ({
        field: 'path' in error ? error.path : 'unknown',
        message: error.msg,
        value: 'value' in error ? error.value : undefined
      }))
    };
    res.status(400).json(apiError);
    return;
  }
  next();
};

// Validation rules for user registration
export const validateRegister = [
  body('username')
    .isLength({ min: 3, max: 20 })
    .withMessage('Username must be between 3 and 20 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores'),
  
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),
  
  body('firstName')
    .isLength({ min: 1, max: 30 })
    .withMessage('First name must be between 1 and 30 characters')
    .trim(),
  
  body('lastName')
    .isLength({ min: 1, max: 30 })
    .withMessage('Last name must be between 1 and 30 characters')
    .trim(),
  
  handleValidationErrors
];

// Validation rules for user login
export const validateLogin = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  
  handleValidationErrors
];

// Validation rules for password change
export const validatePasswordChange = [
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required'),
  
  body('newPassword')
    .isLength({ min: 6 })
    .withMessage('New password must be at least 6 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('New password must contain at least one uppercase letter, one lowercase letter, and one number'),
  
  handleValidationErrors
];

// Validation rules for profile update
export const validateProfileUpdate = [
  body('firstName')
    .optional()
    .isLength({ min: 1, max: 30 })
    .withMessage('First name must be between 1 and 30 characters')
    .trim(),
  
  body('lastName')
    .optional()
    .isLength({ min: 1, max: 30 })
    .withMessage('Last name must be between 1 and 30 characters')
    .trim(),
  
  body('username')
    .optional()
    .isLength({ min: 3, max: 20 })
    .withMessage('Username must be between 3 and 20 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores'),
  
  handleValidationErrors
];