import { Request, Response, NextFunction } from 'express';
import { Error as MongooseError } from 'mongoose';
import { JsonWebTokenError, TokenExpiredError } from 'jsonwebtoken';
import { IApiError } from '../types';

interface MongoError extends Error {
  code?: number;
  keyPattern?: Record<string, number>;
  statusCode?: number;
}

export const errorHandler = (
  err: MongoError | MongooseError.ValidationError | JsonWebTokenError | TokenExpiredError,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  console.error('Error:', err);

  // Mongoose validation error
  if (err instanceof MongooseError.ValidationError) {
    const errors = Object.values(err.errors).map(error => ({
      field: error.path,
      message: error.message
    }));
    
    const apiError: IApiError = {
      error: 'Validation failed',
      message: 'Please check your input data',
      details: errors
    };
    res.status(400).json(apiError);
    return;
  }

  // Mongoose duplicate key error
  if ('code' in err && err.code === 11000) {
    const field = err.keyPattern ? Object.keys(err.keyPattern)[0] : 'field';
    const apiError: IApiError = {
      error: 'Duplicate entry',
      message: `${field?.charAt(0).toUpperCase()}${field?.slice(1)} already exists`
    };
    res.status(409).json(apiError);
    return;
  }

  // Mongoose cast error
  if (err instanceof MongooseError.CastError) {
    const apiError: IApiError = {
      error: 'Invalid data',
      message: 'Invalid ID format'
    };
    res.status(400).json(apiError);
    return;
  }

  // JWT errors
  if (err instanceof JsonWebTokenError) {
    const apiError: IApiError = {
      error: 'Authentication failed',
      message: 'Invalid token'
    };
    res.status(401).json(apiError);
    return;
  }

  if (err instanceof TokenExpiredError) {
    const apiError: IApiError = {
      error: 'Authentication failed',
      message: 'Token expired'
    };
    res.status(401).json(apiError);
    return;
  }

  // Default error
  const statusCode = err.statusCode || 500;
  const apiError: IApiError = {
    error: err.message || 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? (err.stack || 'Something went wrong') : 'Something went wrong'
  };
  res.status(statusCode).json(apiError);
};