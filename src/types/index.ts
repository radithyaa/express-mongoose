import { Request } from 'express';
import { Document } from 'mongoose';

// User interface
export interface IUser extends Document {
  _id: string;
  username: string;
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  role: UserRole;
  isActive: boolean;
  lastLogin?: Date;
  refreshTokens: IRefreshToken[];
  createdAt: Date;
  updatedAt: Date;
  
  // Methods
  comparePassword(candidatePassword: string): Promise<boolean>;
  removeExpiredTokens(): void;
  toJSON(): Omit<IUser, 'password' | 'refreshTokens'>;
}

// Refresh token interface
export interface IRefreshToken {
  token: string;
  createdAt: Date;
}

// User roles
export type UserRole = 'user' | 'admin' | 'moderator';

// JWT payload interface
export interface IJWTPayload {
  userId: string;
  iat?: number;
  exp?: number;
}

// Request with user
export interface IAuthenticatedRequest extends Request {
  user: IUser;
}

// API Response interfaces
export interface IApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  error?: string;
  details?: any;
}

export interface IApiError {
  error: string;
  message: string;
  details?: any;
}

// Auth request bodies
export interface IRegisterRequest {
  username: string;
  email: string;
  password: string;
  firstName: string;
  lastName: string;
}

export interface ILoginRequest {
  email: string;
  password: string;
}

export interface IChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
}

export interface IUpdateProfileRequest {
  firstName?: string;
  lastName?: string;
  username?: string;
}

// Auth responses
export interface IAuthResponse {
  user: Omit<IUser, 'password' | 'refreshTokens'>;
  accessToken: string;
}

export interface IRefreshResponse {
  accessToken: string;
}

// Pagination interface
export interface IPagination {
  page: number;
  limit: number;
  total: number;
  pages: number;
}

export interface IPaginatedResponse<T> {
  data: T[];
  pagination: IPagination;
}

// Environment variables
export interface IEnvironmentVariables {
  NODE_ENV: string;
  PORT: string;
  MONGODB_URI: string;
  JWT_SECRET: string;
  JWT_REFRESH_SECRET: string;
  JWT_EXPIRE: string;
  JWT_REFRESH_EXPIRE: string;
  COOKIE_SECRET: string;
  FRONTEND_URL: string;
  RATE_LIMIT_WINDOW_MS: string;
  RATE_LIMIT_MAX_REQUESTS: string;
}