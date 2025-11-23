<?php

namespace AmranIbrahem\JWTSetup\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Exception;

class InstallJWTCommand extends Command
{
    protected $signature = 'jwt:auto-setup';
    protected $description = 'Automatically install and configure JWT authentication';

    public function handle()
    {
        $this->info('🚀 Starting JWT Auto Setup...');

        try {
            // 1. Install package
            $this->info('📦 Installing tymon/jwt-auth package...');
            shell_exec('composer require tymon/jwt-auth');

            // 2. Publish vendor files
            $this->info('📁 Publishing JWT configuration...');
            $this->call('vendor:publish', [
                '--provider' => 'Tymon\JWTAuth\Providers\LaravelServiceProvider'
            ]);

            // 3. Generate JWT secret
            $this->info('🔑 Generating JWT secret...');
            $this->call('jwt:secret');

            // 4. Update auth configuration
            $this->updateAuthConfig();

            // 5. Update User model
            $this->updateUserModel();

            // 6. Create Form Requests
            $this->createRegisterRequest();
            $this->createLoginRequest();

            // 7. Create routes
            $this->createRoutes();

            // 8. Create AuthController
            $this->createAuthController();

            $this->info('✅ JWT setup completed successfully!');
            $this->info('💡 Don\'t forget to run: php artisan migrate');

        } catch (Exception $e) {
            $this->error('❌ Error during setup: ' . $e->getMessage());
            $this->error('💡 Please check the documentation or try again');
            return 1;
        }

        return 0;
    }

    protected function updateAuthConfig()
    {
        try {
            $authConfigPath = config_path('auth.php');

            if (File::exists($authConfigPath)) {
                $config = include $authConfigPath;

                // Update guards
                if (!isset($config['guards']['api'])) {
                    $config['guards']['api'] = [
                        'driver' => 'jwt',
                        'provider' => 'users',
                    ];

                    $newConfig = "<?php\n\nreturn " . var_export($config, true) . ";\n";

                    if (File::put($authConfigPath, $newConfig) !== false) {
                        $this->info('✅ Updated auth.php configuration');
                    } else {
                        throw new Exception('Failed to write auth.php configuration');
                    }
                } else {
                    $this->info('✅ API guard already exists in auth.php');
                }
            } else {
                throw new Exception('auth.php configuration file not found');
            }
        } catch (Exception $e) {
            $this->warn('⚠️ Could not update auth configuration: ' . $e->getMessage());
        }
    }

    protected function updateUserModel()
    {
        try {
            $userModelPath = app_path('Models/User.php');

            if (File::exists($userModelPath)) {
                $content = File::get($userModelPath);

                // Check if JWT is already implemented
                if (str_contains($content, 'JWTSubject')) {
                    $this->info('✅ User model already has JWT implementation');
                    return;
                }

                // Add JWTSubject interface and methods
                $newContent = $this->addJWTToUserModel($content);

                if (File::put($userModelPath, $newContent) !== false) {
                    $this->info('✅ Updated User model with JWT methods');
                } else {
                    throw new Exception('Failed to update User model');
                }
            } else {
                throw new Exception('User model file not found at: ' . $userModelPath);
            }
        } catch (Exception $e) {
            $this->warn('⚠️ Could not update User model: ' . $e->getMessage());
        }
    }

    protected function addJWTToUserModel($content)
    {
        try {
            // Add use statement after namespace
            if (str_contains($content, 'namespace App\Models;')) {
                $content = str_replace(
                    'namespace App\Models;',
                    "namespace App\Models;\n\nuse Tymon\JWTAuth\Contracts\JWTSubject;",
                    $content
                );
            }

            // Implement interface
            if (str_contains($content, 'class User extends Authenticatable')) {
                $content = str_replace(
                    'class User extends Authenticatable',
                    'class User extends Authenticatable implements JWTSubject',
                    $content
                );
            }

            // Add JWT methods before the last closing brace
            $jwtMethods = "\n    /**\n     * Get the identifier that will be stored in the subject claim of the JWT.\n     */\n    public function getJWTIdentifier()\n    {\n        return \$this->getKey();\n    }\n\n    /**\n     * Return a key value array, containing any custom claims to be added to the JWT.\n     */\n    public function getJWTCustomClaims()\n    {\n        return [];\n    }";

            $lastBrace = strrpos($content, '}');
            if ($lastBrace !== false) {
                $content = substr($content, 0, $lastBrace) . $jwtMethods . "\n}";
            }

            return $content;
        } catch (Exception $e) {
            throw new Exception('Failed to modify User model content: ' . $e->getMessage());
        }
    }

    protected function createRegisterRequest()
    {
        try {
            $requestPath = app_path('Http/Requests/Auth/RegisterRequest.php');
            $directory = dirname($requestPath);

            if (!File::exists($directory)) {
                File::makeDirectory($directory, 0755, true);
            }

            if (!File::exists($requestPath)) {
                $registerRequestContent = '<?php

namespace App\Http\Requests\Auth;

use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Http\Exceptions\HttpResponseException;

class RegisterRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            "name" => "required|string|max:255",
            "email" => "required|email|unique:users,email",
            "password" => "required|string|min:6|confirmed",
        ];
    }

    /**
     * Handle a failed validation attempt.
     */
    protected function failedValidation(Validator $validator)
    {
        throw new HttpResponseException(response()->json([
            "success" => false,
            "message" => "Validation failed",
            "errors" => $validator->errors()->all(),
        ], 422));
    }
}';

                if (File::put($requestPath, $registerRequestContent) !== false) {
                    $this->info('✅ Created RegisterRequest');
                } else {
                    throw new Exception('Failed to create RegisterRequest');
                }
            } else {
                $this->info('✅ RegisterRequest already exists');
            }
        } catch (Exception $e) {
            $this->warn('⚠️ Could not create RegisterRequest: ' . $e->getMessage());
        }
    }

    protected function createLoginRequest()
    {
        try {
            $requestPath = app_path('Http/Requests/Auth/LoginRequest.php');
            $directory = dirname($requestPath);

            if (!File::exists($directory)) {
                File::makeDirectory($directory, 0755, true);
            }

            if (!File::exists($requestPath)) {
                $loginRequestContent = '<?php

namespace App\Http\Requests\Auth;

use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Http\Exceptions\HttpResponseException;

class LoginRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            "email" => "required|email",
            "password" => "required|string|min:6",
        ];
    }

    /**
     * Handle a failed validation attempt.
     */
    protected function failedValidation(Validator $validator)
    {
        throw new HttpResponseException(response()->json([
            "success" => false,
            "message" => "Validation failed",
            "errors" => $validator->errors()->all(),
        ], 422));
    }
}';

                if (File::put($requestPath, $loginRequestContent) !== false) {
                    $this->info('✅ Created LoginRequest');
                } else {
                    throw new Exception('Failed to create LoginRequest');
                }
            } else {
                $this->info('✅ LoginRequest already exists');
            }
        } catch (Exception $e) {
            $this->warn('⚠️ Could not create LoginRequest: ' . $e->getMessage());
        }
    }

    protected function createRoutes()
    {
        try {
            $routesPath = base_path('routes/api.php');

            if (File::exists($routesPath)) {
                $content = File::get($routesPath);

                if (!str_contains($content, 'AuthController')) {
                    $jwtRoutes = "\n\n// JWT Authentication Routes\nuse App\Http\Controllers\AuthController;\n\nRoute::group(['prefix' => 'auth'], function () {\n    // Public routes\n    Route::post('register', [AuthController::class, 'register']);\n    Route::post('login', [AuthController::class, 'login']);\n    \n    // Protected routes (require authentication)\n    Route::middleware('auth:api')->group(function () {\n        Route::post('logout', [AuthController::class, 'logout']);\n        Route::post('refresh', [AuthController::class, 'refresh']);\n    });\n});";

                    if (File::append($routesPath, $jwtRoutes) !== false) {
                        $this->info('✅ Added JWT routes to routes/api.php');
                    } else {
                        throw new Exception('Failed to write routes to api.php');
                    }
                } else {
                    $this->info('✅ JWT routes already exist in routes/api.php');
                }
            } else {
                throw new Exception('routes/api.php file not found');
            }
        } catch (Exception $e) {
            $this->warn('⚠️ Could not create routes: ' . $e->getMessage());
        }
    }

    protected function createAuthController()
    {
        try {
            $controllerPath = app_path('Http/Controllers/AuthController.php');

            if (!File::exists($controllerPath)) {
                $controllerContent = '<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Hash;
use App\Http\Requests\Auth\RegisterRequest;
use App\Http\Requests\Auth\LoginRequest;
use Exception;

class AuthController extends Controller
{
    public function register(RegisterRequest $request)
    {
        try {
            $validated = $request->validated();

            $user = User::create([
                "name" => $validated["name"],
                "email" => $validated["email"],
                "password" => Hash::make($validated["password"]),
            ]);

            $token = JWTAuth::fromUser($user);

            return response()->json([
                "success" => true,
                "message" => "User registered successfully",
                "user" => [
                    "id" => $user->id,
                    "name" => $user->name,
                    "email" => $user->email,
                    "created_at" => $user->created_at
                ],
                "token" => $token
            ], 201);

        } catch (Exception $e) {
            return response()->json([
                "success" => false,
                "message" => "Registration failed",
                "error" => $e->getMessage()
            ], 500);
        }
    }

    public function login(LoginRequest $request)
    {
        try {
            $validated = $request->validated();
            $credentials = [
                "email" => $validated["email"],
                "password" => $validated["password"]
            ];

            $user = User::where("email", $credentials["email"])->first();

            if (!$user) {
                return response()->json([
                    "success" => false,
                    "message" => "Email address not found",
                    "hint" => "Please check your email or register a new account"
                ], 401);
            }

            if (!Hash::check($credentials["password"], $user->password)) {
                return response()->json([
                    "success" => false,
                    "message" => "Incorrect password",
                    "hint" => "Please check your password or use forgot password"
                ], 401);
            }

            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json([
                    "success" => false,
                    "message" => "Authentication failed",
                    "hint" => "Please try again later"
                ], 401);
            }

            return response()->json([
                "success" => true,
                "message" => "Login successful",
                "token" => $token,
                "user" => [
                    "id" => $user->id,
                    "name" => $user->name,
                    "email" => $user->email,
                    "created_at" => $user->created_at
                ]
            ]);

        } catch (Exception $e) {
            return response()->json([
                "success" => false,
                "message" => "Login failed due to server error",
                "error" => $e->getMessage()
            ], 500);
        }
    }

    public function logout(Request $request)
    {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());

            return response()->json([
                "success" => true,
                "message" => "Successfully logged out"
            ]);

        } catch (Exception $e) {
            return response()->json([
                "success" => false,
                "message" => "Logout failed",
                "error" => $e->getMessage()
            ], 500);
        }
    }

    public function refresh(Request $request)
    {
        try {
            $newToken = JWTAuth::refresh(JWTAuth::getToken());

            return response()->json([
                "success" => true,
                "message" => "Token refreshed successfully",
                "token" => $newToken,
            ]);

        } catch (Exception $e) {
            return response()->json([
                "success" => false,
                "message" => "Token refresh failed",
                "error" => $e->getMessage()
            ], 500);
        }
    }
}';

                if (File::put($controllerPath, $controllerContent) !== false) {
                    $this->info('✅ Created AuthController');
                } else {
                    throw new Exception('Failed to create AuthController');
                }
            } else {
                $this->info('✅ AuthController already exists');
            }
        } catch (Exception $e) {
            $this->warn('⚠️ Could not create AuthController: ' . $e->getMessage());
        }
    }
}
