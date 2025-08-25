# TypeScript Express.js MongoDB JWT Authentication

A modern, type-safe Express.js backend with MongoDB and comprehensive JWT authentication system built with TypeScript.

## 🚀 Features

### Core Features
- **TypeScript** - Full type safety throughout the application
- **Express.js Server** - Modern web framework with typed routing
- **MongoDB Integration** - Database with Mongoose ODM and TypeScript interfaces
- **JWT Authentication** - Access token and refresh token system with full typing
- **Password Security** - Bcrypt hashing with salt
- **Input Validation** - Express-validator with TypeScript support
- **Error Handling** - Comprehensive typed error handling middleware
- **Security Middleware** - Helmet, CORS, rate limiting
- **Role-Based Access** - User roles (user, admin, moderator) with type safety

### Authentication Features
- User registration and login with typed request/response
- JWT access token (short-lived)
- JWT refresh token (long-lived)
- Token refresh mechanism
- Logout single device
- Logout all devices
- Password change with validation
- Profile management

### TypeScript Features
- **Strict Type Checking** - Full TypeScript strict mode enabled
- **Interface Definitions** - Comprehensive interfaces for all data structures
- **Type-Safe Middleware** - All middleware functions are properly typed
- **Generic API Responses** - Reusable response types
- **Environment Variables** - Typed environment configuration
- **Request/Response Typing** - Full typing for Express routes

## 📦 Dependencies

### Production Dependencies
- `express` - Web framework
- `mongoose` - MongoDB ODM
- `bcryptjs` - Password hashing
- `jsonwebtoken` - JWT implementation
- `cors` - CORS middleware
- `helmet` - Security headers
- `morgan` - HTTP logging
- `express-rate-limit` - Rate limiting
- `express-validator` - Input validation
- `cookie-parser` - Cookie parsing
- `dotenv` - Environment variables

### Development Dependencies
- `typescript` - TypeScript compiler
- `ts-node` - TypeScript execution environment
- `nodemon` - Development server
- `@types/*` - Type definitions for all dependencies

## 🛠️ Installation

1. **Install dependencies**
   ```bash
   npm install
   ```

2. **Setup environment variables**
   Edit `.env` file with your configuration:
   ```env
   NODE_ENV=development
   PORT=5000
   MONGODB_URI=mongodb://localhost:27017/typescript-express-auth
   JWT_SECRET=your-super-secret-jwt-key
   JWT_REFRESH_SECRET=your-super-secret-refresh-key
   # ... and others
   ```

3. **Start MongoDB**
   Ensure MongoDB is running on your system

4. **Run the application**
   ```bash
   # Development mode (with TypeScript compilation)
   npm run dev
   
   # Build TypeScript to JavaScript
   npm run build
   
   # Production mode (run compiled JavaScript)
   npm start
   
   # Type checking only
   npm run type-check
   ```

## 📚 API Documentation

### Authentication Routes (`/api/auth`)

#### Register User
```typescript
POST /api/auth/register
Content-Type: application/json

interface RegisterRequest {
  username: string;
  email: string;
  password: string;
  firstName: string;
  lastName: string;
}

interface AuthResponse {
  success: boolean;
  message: string;
  data: {
    user: Omit<IUser, 'password' | 'refreshTokens'>;
    accessToken: string;
  };
}
```

#### Login User
```typescript
POST /api/auth/login
Content-Type: application/json

interface LoginRequest {
  email: string;
  password: string;
}
```

#### Refresh Token
```typescript
POST /api/auth/refresh
Cookie: refreshToken=your_refresh_token

interface RefreshResponse {
  success: boolean;
  message: string;
  data: {
    accessToken: string;
  };
}
```

### User Routes (`/api/users`)

#### Update Profile
```typescript
PUT /api/users/profile
Authorization: Bearer your_access_token
Content-Type: application/json

interface UpdateProfileRequest {
  firstName?: string;
  lastName?: string;
  username?: string;
}
```

#### Change Password
```typescript
PUT /api/users/change-password
Authorization: Bearer your_access_token
Content-Type: application/json

interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
}
```

## 🏗️ Project Structure

```
src/
├── types/
│   └── index.ts             # All TypeScript interfaces and types
├── config/
│   └── database.ts          # Database connection configuration
├── models/
│   └── User.ts              # User model with TypeScript interfaces
├── middleware/
│   ├── auth.ts              # JWT authentication middleware
│   ├── validation.ts        # Input validation middleware
│   └── errorHandler.ts      # Error handling middleware
├── routes/
│   ├── auth.ts              # Authentication routes
│   ├── users.ts             # User management routes
│   └── protected.ts         # Protected route examples
└── server.ts                # Main application file
```

## 🔧 TypeScript Configuration

### Key TypeScript Features Used

1. **Strict Type Checking**
   ```typescript
   // tsconfig.json
   {
     "strict": true,
     "noImplicitAny": true,
     "noImplicitReturns": true,
     "noUnusedLocals": true,
     "exactOptionalPropertyTypes": true
   }
   ```

2. **Interface Definitions**
   ```typescript
   interface IUser extends Document {
     _id: string;
     username: string;
     email: string;
     // ... other properties
     comparePassword(candidatePassword: string): Promise<boolean>;
   }
   ```

3. **Generic API Responses**
   ```typescript
   interface IApiResponse<T = any> {
     success: boolean;
     message: string;
     data?: T;
     error?: string;
   }
   ```

4. **Typed Express Routes**
   ```typescript
   router.post('/login', 
     validateLogin, 
     async (req: Request<{}, IApiResponse<IAuthResponse>, ILoginRequest>, 
            res: Response<IApiResponse<IAuthResponse> | IApiError>): Promise<void> => {
       // Fully typed route handler
     }
   );
   ```

## 🔐 Security Features

### Type-Safe Security
- **Typed JWT Payloads** - JWT tokens use typed interfaces
- **Typed Middleware** - All authentication middleware is type-safe
- **Typed Validation** - Input validation with TypeScript support
- **Typed Error Handling** - Comprehensive error types

### Security Implementation
- Password hashing with bcrypt (salt rounds 12)
- Short-lived access tokens (15 minutes)
- Long-lived refresh tokens (7 days)
- HTTP-only cookies for refresh tokens
- Rate limiting (100 requests per 15 minutes)
- CORS configuration
- Helmet security headers

## 🚦 Usage Examples

### Frontend Integration (TypeScript)

```typescript
// Types for API responses
interface AuthResponse {
  success: boolean;
  message: string;
  data: {
    user: User;
    accessToken: string;
  };
}

interface LoginRequest {
  email: string;
  password: string;
}

// Login function with full typing
const login = async (credentials: LoginRequest): Promise<AuthResponse> => {
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    credentials: 'include',
    body: JSON.stringify(credentials)
  });
  
  if (!response.ok) {
    throw new Error('Login failed');
  }
  
  return response.json() as Promise<AuthResponse>;
};

// Type-safe API client
class ApiClient {
  private baseUrl: string;
  private accessToken: string | null = null;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  async makeAuthenticatedRequest<T>(
    endpoint: string, 
    options: RequestInit = {}
  ): Promise<T> {
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${this.accessToken}`,
        'Content-Type': 'application/json'
      },
      credentials: 'include'
    });

    if (response.status === 401) {
      // Handle token refresh
      await this.refreshToken();
      // Retry request
      return this.makeAuthenticatedRequest<T>(endpoint, options);
    }

    return response.json();
  }

  private async refreshToken(): Promise<void> {
    const response = await fetch(`${this.baseUrl}/api/auth/refresh`, {
      method: 'POST',
      credentials: 'include'
    });

    if (response.ok) {
      const data = await response.json();
      this.accessToken = data.data.accessToken;
    } else {
      // Redirect to login
      window.location.href = '/login';
    }
  }
}
```

## 🧪 Development

### Type Checking
```bash
# Run TypeScript compiler without emitting files
npm run type-check

# Build the project
npm run build

# Clean build directory
npm run clean
```

### Development Workflow
1. Make changes to TypeScript files in `src/`
2. TypeScript compiler will check types automatically
3. `nodemon` will restart the server on file changes
4. All type errors will be caught at compile time

## 📄 License

This project is licensed under the ISC License.