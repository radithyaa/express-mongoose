# Express.js MongoDB JWT Authentication Starter

Starter pack backend Express.js yang lengkap dengan sistem autentikasi JWT dan MongoDB menggunakan Mongoose.

## 🚀 Features

### Core Features
- **Express.js Server** - Web framework dengan routing yang terstruktur
- **MongoDB Integration** - Database dengan Mongoose ODM
- **JWT Authentication** - Access token dan refresh token system
- **Password Security** - Bcrypt hashing dengan salt
- **Input Validation** - Express-validator untuk validasi data
- **Error Handling** - Comprehensive error handling middleware
- **Security Middleware** - Helmet, CORS, rate limiting
- **Role-Based Access** - User roles (user, admin, moderator)

### Authentication Features
- User registration dan login
- JWT access token (short-lived)
- JWT refresh token (long-lived)
- Token refresh mechanism
- Logout single device
- Logout all devices
- Password change
- Profile management

### Security Features
- Password hashing dengan bcrypt
- JWT token dengan expiration
- HTTP-only cookies untuk refresh token
- Rate limiting
- CORS protection
- Helmet security headers
- Input validation dan sanitization

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
- `nodemon` - Development server

## 🛠️ Installation

1. **Clone atau copy project files**

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Setup environment variables**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` file dengan konfigurasi Anda:
   ```env
   NODE_ENV=development
   PORT=5000
   MONGODB_URI=mongodb://localhost:27017/express-jwt-starter
   JWT_SECRET=your-super-secret-jwt-key
   JWT_REFRESH_SECRET=your-super-secret-refresh-key
   # ... dan lainnya
   ```

4. **Start MongoDB**
   Pastikan MongoDB berjalan di sistem Anda

5. **Run the application**
   ```bash
   # Development mode
   npm run dev
   
   # Production mode
   npm start
   ```

## 📚 API Documentation

### Authentication Routes (`/api/auth`)

#### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "Password123",
  "firstName": "John",
  "lastName": "Doe"
}
```

#### Login User
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "Password123"
}
```

#### Refresh Token
```http
POST /api/auth/refresh
Cookie: refreshToken=your_refresh_token
```

#### Logout
```http
POST /api/auth/logout
Authorization: Bearer your_access_token
```

#### Logout All Devices
```http
POST /api/auth/logout-all
Authorization: Bearer your_access_token
```

#### Get Current User
```http
GET /api/auth/me
Authorization: Bearer your_access_token
```

### User Routes (`/api/users`)

#### Get Profile
```http
GET /api/users/profile
Authorization: Bearer your_access_token
```

#### Update Profile
```http
PUT /api/users/profile
Authorization: Bearer your_access_token
Content-Type: application/json

{
  "firstName": "Jane",
  "lastName": "Doe",
  "username": "janedoe"
}
```

#### Change Password
```http
PUT /api/users/change-password
Authorization: Bearer your_access_token
Content-Type: application/json

{
  "currentPassword": "OldPassword123",
  "newPassword": "NewPassword123"
}
```

#### Get All Users (Admin Only)
```http
GET /api/users?page=1&limit=10&search=john&role=user
Authorization: Bearer admin_access_token
```

### Protected Routes (`/api/protected`)

#### User Protected Route
```http
GET /api/protected/user
Authorization: Bearer your_access_token
```

#### Admin Protected Route
```http
GET /api/protected/admin
Authorization: Bearer admin_access_token
```

#### Optional Auth Route
```http
GET /api/protected/optional
Authorization: Bearer your_access_token (optional)
```

## 🏗️ Project Structure

```
├── models/
│   └── User.js              # User model dengan Mongoose
├── routes/
│   ├── auth.js              # Authentication routes
│   ├── users.js             # User management routes
│   └── protected.js         # Protected route examples
├── middleware/
│   ├── auth.js              # JWT authentication middleware
│   ├── validation.js        # Input validation middleware
│   └── errorHandler.js      # Error handling middleware
├── server.js                # Main application file
├── .env                     # Environment variables
├── .env.example             # Environment variables example
├── .gitignore              # Git ignore rules
├── package.json            # Dependencies and scripts
└── README.md               # This file
```

## 🔧 Configuration

### Environment Variables

- `NODE_ENV` - Environment (development/production)
- `PORT` - Server port (default: 5000)
- `MONGODB_URI` - MongoDB connection string
- `JWT_SECRET` - JWT access token secret
- `JWT_REFRESH_SECRET` - JWT refresh token secret
- `JWT_EXPIRE` - Access token expiration (default: 15m)
- `JWT_REFRESH_EXPIRE` - Refresh token expiration (default: 7d)
- `COOKIE_SECRET` - Cookie parser secret
- `FRONTEND_URL` - Frontend URL for CORS
- `RATE_LIMIT_WINDOW_MS` - Rate limiting window
- `RATE_LIMIT_MAX_REQUESTS` - Max requests per window

### Database Configuration

MongoDB dengan Mongoose ODM:
- Automatic connection handling
- Schema validation
- Index optimization
- Connection error handling

## 🔐 Security Features

### Password Security
- Bcrypt hashing dengan salt rounds 12
- Password complexity validation
- Secure password comparison

### JWT Security
- Short-lived access tokens (15 minutes)
- Long-lived refresh tokens (7 days)
- HTTP-only cookies untuk refresh tokens
- Token rotation pada refresh
- Multi-device logout support

### API Security
- Rate limiting (100 requests per 15 minutes)
- CORS configuration
- Helmet security headers
- Input validation dan sanitization
- Error handling tanpa information leakage

## 🚦 Usage Examples

### Frontend Integration (JavaScript)

```javascript
// Login
const login = async (email, password) => {
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    credentials: 'include', // Include cookies
    body: JSON.stringify({ email, password })
  });
  
  const data = await response.json();
  if (data.success) {
    // Store access token
    localStorage.setItem('accessToken', data.data.accessToken);
  }
  return data;
};

// API call dengan authentication
const makeAuthenticatedRequest = async (url, options = {}) => {
  const token = localStorage.getItem('accessToken');
  
  const response = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    credentials: 'include'
  });
  
  if (response.status === 401) {
    // Try to refresh token
    const refreshResponse = await fetch('/api/auth/refresh', {
      method: 'POST',
      credentials: 'include'
    });
    
    if (refreshResponse.ok) {
      const refreshData = await refreshResponse.json();
      localStorage.setItem('accessToken', refreshData.data.accessToken);
      
      // Retry original request
      return fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          'Authorization': `Bearer ${refreshData.data.accessToken}`,
          'Content-Type': 'application/json'
        },
        credentials: 'include'
      });
    } else {
      // Refresh failed, redirect to login
      window.location.href = '/login';
    }
  }
  
  return response;
};
```

## 🤝 Contributing

1. Fork the project
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📄 License

This project is licensed under the ISC License.