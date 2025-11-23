<?php

namespace AmranIbrahem\JWTSetup\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;

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

        } catch (\Exception $e) {
            $this->error('❌ Error during setup: ' . $e->getMessage());
        }
    }

    protected function updateAuthConfig()
    {
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
                File::put($authConfigPath, $newConfig);
                $this->info('✅ Updated auth.php configuration');
            }
        }
    }

    protected function updateUserModel()
    {
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
            File::put($userModelPath, $newContent);
            $this->info('✅ Updated User model with JWT methods');
        }
    }

    protected function addJWTToUserModel($content)
    {
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
    }

    protected function createRoutes()
    {
        $routesPath = base_path('routes/api.php');

        $jwtRoutes = "\n\n// JWT Authentication Routes\nRoute::group(['prefix' => 'auth'], function () {\n    Route::post('register', [App\Http\Controllers\AuthController::class, 'register']);\n    Route::post('login', [App\Http\Controllers\AuthController::class, 'login']);\n    \n    Route::middleware('auth:api')->group(function () {\n        Route::post('logout', [App\Http\Controllers\AuthController::class, 'logout']);\n        Route::post('refresh', [App\Http\Controllers\AuthController::class, 'refresh']);\n        Route::get('me', [App\Http\Controllers\AuthController::class, 'me']);\n    });\n});";

        File::append($routesPath, $jwtRoutes);
        $this->info('✅ Added JWT routes to routes/api.php');
    }

    protected function createAuthController()
    {
        $controllerPath = app_path('Http/Controllers/AuthController.php');

        if (!File::exists($controllerPath)) {
            $controllerContent = '<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request \$request)
    {
        \$validator = Validator::make(\$request->all(), [
            "name" => "required|string|max:255",
            "email" => "required|string|email|max:255|unique:users",
            "password" => "required|string|min:6|confirmed",
        ]);

        if (\$validator->fails()) {
            return response()->json(\$validator->errors(), 400);
        }

        \$user = User::create([
            "name" => \$request->name,
            "email" => \$request->email,
            "password" => Hash::make(\$request->password),
        ]);

        \$token = JWTAuth::fromUser(\$user);

        return response()->json([
            "user" => \$user,
            "token" => \$token
        ], 201);
    }

    public function login(Request \$request)
    {
        \$credentials = \$request->only(["email", "password"]);

        if (!\$token = JWTAuth::attempt(\$credentials)) {
            return response()->json(["error" => "Unauthorized"], 401);
        }

        return response()->json([
            "token" => \$token
        ]);
    }

    public function me()
    {
        return response()->json(auth()->user());
    }

    public function logout()
    {
        auth()->logout();
        return response()->json(["message" => "Successfully logged out"]);
    }

    public function refresh()
    {
        return response()->json([
            "token" => auth()->refresh()
        ]);
    }
}';

            File::put($controllerPath, $controllerContent);
            $this->info('✅ Created AuthController');
        }
    }
}
