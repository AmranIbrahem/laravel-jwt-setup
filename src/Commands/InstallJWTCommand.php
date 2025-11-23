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

            // 6. Create routes
            $this->createRoutes();

            // 7. Create AuthController
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

    protected function createRoutes()
    {
        try {
            $routesPath = base_path('routes/api.php');

            if (File::exists($routesPath)) {
                $content = File::get($routesPath);

                if (!str_contains($content, 'AuthController')) {
                    $jwtRoutes = "\n\n// JWT Authentication Routes\nRoute::post('register', [AuthController::class, 'register']);\nRoute::post('login', [AuthController::class, 'login']);";

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
use Illuminate\Support\Facades\Validator;
use Exception;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                "name" => "required|string|max:255",
                "email" => "required|string|email|max:255|unique:users",
                "password" => "required|string|min:6|confirmed",
            ]);

            if ($validator->fails()) {
                return response()->json([
                    "success" => false,
                    "message" => "Validation failed",
                    "errors" => $validator->errors()
                ], 400);
            }

            $user = User::create([
                "name" => $request->name,
                "email" => $request->email,
                "password" => Hash::make($request->password),
            ]);

            $token = JWTAuth::fromUser($user);

            return response()->json([
                "success" => true,
                "message" => "User registered successfully",
                "user" => $user,
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

    public function login(Request $request)
    {
        try {
            $credentials = $request->only(["email", "password"]);

            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json([
                    "success" => false,
                    "message" => "Invalid credentials"
                ], 401);
            }

            return response()->json([
                "success" => true,
                "message" => "Login successful",
                "token" => $token
            ]);

        } catch (Exception $e) {
            return response()->json([
                "success" => false,
                "message" => "Login failed",
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
