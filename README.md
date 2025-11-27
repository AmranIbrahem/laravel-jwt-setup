# Laravel JWT Auto Setup

🚀 **Automated JWT Authentication Setup for Laravel Applications**

A powerful Laravel package that automatically installs and configures JWT authentication with a single command, saving you hours of manual setup.

## ✨ Features

- ✅ **One-command installation** - Complete JWT setup with `php artisan jwt:auto-setup`
- ✅ **Automatic package installation** - Installs `tymon/jwt-auth` via Composer
- ✅ **Smart configuration** - Auto-configures auth guards and JWT settings
- ✅ **Model enhancement** - Updates User model with JWTSubject implementation
- ✅ **Complete file generation** - Creates controllers, requests, responses, and routes
- ✅ **Professional code structure** - Follows Laravel best practices
- ✅ **Error handling** - Comprehensive error reporting and rollback
- ✅ **Validation integration** - Custom form requests with validation
- ✅ **Standardized responses** - Consistent JSON response format

## 🚀 Installation

**You can install the package via Composer:**

```bash
composer require amranibrahem/jwt-setup
```

## 📖 Usage

**Run the auto-setup command:**
```bash
php artisan jwt:auto-setup
```

## What This Command Does:

📦 **Installs tymon/jwt-auth package**  
Automatically installs the required JWT package via Composer

📁 **Publishes JWT configuration files**  
Publishes all necessary configuration files for JWT setup

🔑 **Generates JWT secret key**  
Creates a secure JWT secret key for token signing

⚙️ **Updates auth configuration**  
Automatically configures auth guards in `config/auth.php`

👤 **Enhances User model with JWT methods**  
Updates the User model to implement JWTSubject interface

🛠 **Creates professional file structure:**

• **Response class** - Standardized JSON response format  
• **Form requests** - Register & Login validation classes  
• **AuthController** - Complete authentication logic  
• **API routes** - Ready-to-use authentication endpoints

## 🎯 Generated File Structure
```
app/
├── Http/
│   ├── Controllers/
│   │   └── AuthController.php
│   ├── Requests/
│   │   └── Auth/
│   │       ├── LoginRequest.php
│   │       └── RegisterRequest.php
│   └── Responses/
│       └── Response.php
└── Models/
└── User.php (updated)
```

## 🔌 API Endpoints

After setup, you'll have these ready-to-use endpoints:

### Public Routes
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login

### Protected Routes (Require JWT)
- `POST /api/auth/logout` - User logout
- `POST /api/auth/refresh` - Refresh JWT token

## 🎨 Code Examples

**Generated AuthController Methods**
```php
// Registration
public function register(RegisterRequest $request)
{
// Handles user registration with validation
// Returns: User data + JWT token
}

// Login
public function login(LoginRequest $request)
{
// Handles user authentication
// Returns: User data + JWT token
}

// Logout
public function logout(Request $request)
{
// Invalidates JWT token
// Returns: Success message
}
```
**Professional Response Format**

```json
{
"message": "Login successful",
"data": {
"id": 1,
"name": "John Doe",
"email": "john@example.com",
"created_at": "2023-01-01 12:00:00"
},
"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Enhanced User Model**

```php
<?php

namespace App\Models;

use Tymon\JWTAuth\Contracts\JWTSubject;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable implements JWTSubject
{
    // ... existing code ...
    
    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     */
    public function getJWTCustomClaims()
    {
        return [];
    }
}
```
## ⚙️ Configuration

### Manual Configuration (If Needed)
After running the setup, you can customize:

1. **JWT Configuration** - `config/jwt.php`
2. **Auth Guards** - `config/auth.php`
3. **Token Expiry** - Modify in JWT config
4. **Response Format** - Edit `App\Http\Responses\Response`

### Environment Variables
Add to your `.env` file:

```env
JWT_SECRET=your_generated_secret_here
```

## 🔒 Security Features

* ✅ Password hashing with bcrypt
* ✅ JWT token expiration
* ✅ Input validation with form requests
* ✅ Protected logout and refresh endpoints
* ✅ Token invalidation on logout

## 🛠 Troubleshooting

### Common Issues & Solutions

1. **"Class JWTSubject not found"**
    - Run: `composer dump-autoload`

2. **"Auth guard [api] is not defined"**
    - Check `config/auth.php` was updated correctly

3. **Token not working**
    - Verify JWT secret: `php artisan jwt:secret`

4. **Routes not found**
    - Ensure routes are added to `routes/api.php`

## ⚡ Comparison with Manual Setup

| Feature | Manual Setup | This Package |
|---------|--------------|--------------|
| Time Required | 30-60 minutes | **30 seconds** |
| Configuration | Manual editing | **Automatic** |
| Error Handling | Manual debugging | **Built-in** |
| Code Quality | Variable | **Consistent & Professional** |
| Best Practices | Research required | **Pre-implemented** |
| File Structure | Manual creation | **Auto-generated** |

## 🎯 Use Cases

- **🚀 Rapid Prototyping** - Get JWT auth running in seconds
- **🏢 Enterprise Projects** - Standardized authentication setup
- **👥 Team Projects** - Consistent codebase across developers
- **📚 Learning Laravel** - See professional JWT implementation
- **⚡ API Development** - Ready-to-use authentication system

## 🔄 Migration

After setup, run database migrations:

```bash
php artisan migrate
```

## 🐛 Reporting Issues

If you encounter any issues, please report them on the [GitHub issue tracker](https://github.com/amranibrahem/jwt-setup/issues).

## 🏆 Credits

- [Amran iBrahem](https://github.com/amranibrahem)
- Built on [tymon/jwt-auth](https://github.com/tymondesigns/jwt-auth)

## 💡 Why Use This Package?

- **⏱️ Save Time** - 30 seconds vs 30+ minutes manual setup
- **🔧 Zero Configuration** - Works out of the box
- **📈 Production Ready** - Professional code quality
- **🛡️ Secure** - Follows security best practices
- **🔍 Debuggable** - Comprehensive error messages
- **🔄 Consistent** - Same structure across all projects

## 🔗 Links

- [GitHub Repository](https://github.com/AmranIbrahem/laravel-jwt-setup)
- [Packagist](https://packagist.org/packages/amranibrahem/laravel-jwt-setup)
- [Issue Tracker](https://github.com/AmranIbrahem/laravel-jwt-setup/issues)

---

**⭐ Star us on GitHub if this package saved you time!**

**🚀 Happy coding with secure JWT authentication!**
