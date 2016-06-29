<?php

namespace Imrealashu\MultiAuthGenerator\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facade;
use Illuminate\Support\Facades\Artisan;

class MultiAuthNewCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'multiauth:new {authName}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generates new multi auth';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        $bar = $this->output->createProgressBar(10);

        $authName = $this->argument('authName');
//
        $this->comment(" *========================================================================================*");
        $this->comment('     .                           .   .    .     . .                 .         .  .    ');
        $this->comment('     |                           |   |\  /|     |_|_   o           / \       _|_ |    ');
        $this->comment('     |    .-.  .--..-..    ._.-. |   | \/ |.  . | |    .   ____   /___\  .  . |  |--. ');
        $this->comment('     |   (   ) |  (   )\  / (.-\' |   |    ||  | | |    |         /     \ |  | |  |  | ');
        $this->comment("     '---'`-'`-'   `-'`-`'   `--'`-  '    '`--`-`-`-'-' `-      '       ``--`-`-''  `-");
        $this->comment(" *========================================================================================*");

        

        $bar->start();

        //Creating Migration
        $this->info(' Creating Migration');
        $this->callSilent('make:migration', [
            'name' => 'create_'.str_plural(strtolower($authName)).'_table'
        ]);
        $bar->advance();
        
        $this->info(' Creating Model');
        //Creating model
        $this->createModel($authName);
        $bar->advance();
        
        $this->info(' Creating Middleware');
        //Creating Middleware
        $this->createMiddleware($authName);
        $bar->advance();
        
        $this->info(' Create Model');
        //Create Model
        $this->createModel($authName);
        $bar->advance();
        
        $this->info(' Modifying Migration');
        //Modifying Migration
        $this->modifyMigration($authName);
        $bar->advance();
        
        $this->info(' Modifying Auth');
        //Modifying Auth
        $this->modifyAuth($authName);
        $bar->advance();
        
        $this->info(' Modifying Kernel');
        //Modifying Kernel
        $this->modifyKernel($authName);
        $bar->advance();
        
        $this->info(' Adding Routes');
        //Adding Routes
        $this->createRoutes($authName);
        $bar->advance();
        
        $this->info(' Generating Controllers');
        //Generating Controllers
        $this->createControllers($authName);
        $bar->advance();
        
        $this->info(' Generating Views');
        //Generating Views
        $this->createViews($authName);
        $bar->finish();
        $this->info(' Completed Successfully!!');
        $this->output->newLine(1);

//        $this->info('Creating Auth for '.$authName);
//        $this->callSilent('make:model',[
//            'name' => ucwords($authName)
//        ]);
//        $this->info('Model '.$authName.' created!!');
//        $this->callSilent('make:migration', [
//            'name' => 'create_'.str_plural(strtolower($authName)).'_table'
//        ]);
//        $this->info('Migration '.$authName.' created!!');
//        $this->modifyMigration($authName);
//        $this->output->newLine(1);
//        $this->modifyAuth($authName);
//        $this->createMiddleware($authName);
//        $this->modifyKernel($authName);
//        $this->createControllers($authName);
//        $this->createViews($authName);
//        $this->createRoutes($authName);
    }
    private function modifyAuth($auth_name)
    {
        
        $plural_auth_name = str_plural($auth_name);
        $fname = config_path('auth.php');
        $fhandle = fopen($fname,"r");
        $content = fread($fhandle,filesize($fname));

        $content = str_replace("'guards' => [", "'guards' => [
        //Generated Guards By MultiAuthGenerator.
        '$auth_name' => [
            'driver' => 'session',
            'provider' => '$plural_auth_name',
        ],", $content);

        $content = str_replace("'providers' => [", "'providers' => [
        //Generated Providers By MultiAuthGenerator.
        '$plural_auth_name' => [
            'driver' => 'eloquent',
            'model' => App\\".ucwords($auth_name)."::class,
        ],", $content);


        $content = str_replace("'passwords' => [", "'passwords' => [
        //Generated Passwords By MultiAuthGenerator.
        '$plural_auth_name' => [
            'provider' => '$plural_auth_name',
            'email' => '".strtolower($auth_name)."_auth.emails.password',
            'table' => 'password_resets',
            'expire' => 60,
        ],
    ", $content);

        $fhandle = fopen($fname,"w");
        fwrite($fhandle,$content);
        fclose($fhandle);
    }
    private function modifyMigration($table_name)
    {
        $files = scandir(database_path('migrations'), SCANDIR_SORT_DESCENDING);
        file_put_contents(database_path('migrations/'.$files[0]),$this->schema($table_name));
    }
    private function modifyGuards($auth_name)
    {
        $plural_auth_name = str_plural($auth_name);
        $fname = config_path('auth.php');
        $fhandle = fopen($fname,"r");
        $content = fread($fhandle,filesize($fname));

        $content = str_replace("'guards' => [", "'guards' => [
        '$auth_name' => [
            'driver' => 'session',
            'provider' => '$plural_auth_name',
        ],", $content);

        $fhandle = fopen($fname,"w");
        fwrite($fhandle,$content);
        fclose($fhandle);
    }
    private function modifyProviders($auth_name)
    {
        $plural_auth_name = str_plural($auth_name);
        $fname = config_path('auth.php');
        $fhandle = fopen($fname,"r");
        $content = fread($fhandle,filesize($fname));

        $content = str_replace("'providers' => [", "'providers' => [
        '$plural_auth_name' => [
            'driver' => 'eloquent',
            'model' => App\\".ucwords($auth_name)."::class,
        ],", $content);

        $fhandle = fopen($fname,"w");
        fwrite($fhandle,$content);
        fclose($fhandle);    
    }
    private function modifyPasswords($auth_name)
    {
        $plural_auth_name = str_plural($auth_name);
        $fname = config_path('auth.php');
        $fhandle = fopen($fname,"r");
        $content = fread($fhandle,filesize($fname));

        $content = str_replace("'passwords' => [", "'passwords' => [
        '$plural_auth_name' => [
            'provider' => '$plural_auth_name',
            'email' => '".strtolower($auth_name)."_auth.emails.password',
            'table' => 'password_resets',
            'expire' => 60,
        ],
    ", $content);

        $fhandle = fopen($fname,"w");
        fwrite($fhandle,$content);
        fclose($fhandle);
    }
    private function createModel($auth_name){
        file_put_contents(app_path('/'.str_singular(ucwords($auth_name)).'.php'),$this->model($auth_name) );
    }
    private function createMiddleware($auth_name){
        file_put_contents(app_path('Http/Middleware/RedirectIfNot'.ucwords($auth_name)).'.php', trim($this->middleware($auth_name)));
    }
    private function createControllers($auth_name)
    {
        mkdir(app_path('Http/Controllers/'.ucwords($auth_name).'Auth',0777));
        copy(app_path('Http/Controllers/Auth/PasswordController.php'), app_path('Http/Controllers/'.ucwords($auth_name).'Auth/PasswordController.php'));
        file_put_contents(app_path('Http/Controllers/'.ucwords($auth_name).'Auth/AuthController.php'), $this->authController($auth_name));
        file_put_contents(app_path('Http/Controllers/'.ucwords($auth_name).'Controller.php'), $this->controller($auth_name));
    }
    private function createViews($auth_name)
    {
        mkdir(base_path('resources/views/'.$auth_name),0777);
        mkdir(base_path('resources/views/'.$auth_name.'/auth'),0777);
        mkdir(base_path('resources/views/'.$auth_name.'/auth/emails'),0777);
        mkdir(base_path('resources/views/'.$auth_name.'/auth/passwords'),0777);
        
        file_put_contents(base_path('resources/views/'.$auth_name.'/auth/login.blade.php'),$this->loginHTML($auth_name));
        file_put_contents(base_path('resources/views/'.$auth_name.'/dashboard.blade.php'),$this->dashboardHTML($auth_name));
        file_put_contents(base_path('resources/views/'.$auth_name.'/auth/register.blade.php'),$this->registerHTML($auth_name));
        file_put_contents(base_path('resources/views/'.$auth_name.'/auth/emails/password.blade.php'),$this->passwordHTML($auth_name));
        file_put_contents(base_path('resources/views/'.$auth_name.'/auth/passwords/email.blade.php'),$this->passwordEmailHTML($auth_name));
        file_put_contents(base_path('resources/views/'.$auth_name.'/auth/passwords/reset.blade.php'),$this->passwordResetHTML($auth_name));

    }
    private function createRoutes($auth_name)
    {
        file_put_contents(app_path('Http/routes.php'),$this->routes($auth_name).PHP_EOL,FILE_APPEND );
    }
    private function modifyKernel($auth_name)
    {
        $plural_auth_name = str_plural($auth_name);
        $fname = app_path('Http/Kernel.php');
        $fhandle = fopen($fname,"r");
        $content = fread($fhandle,filesize($fname));

        $content = str_replace("protected \$routeMiddleware = [", "protected \$routeMiddleware = [
        '".strtolower($auth_name)."' => \\App\\Http\\Middleware\\RedirectIfNot".ucwords($auth_name)."::class,", $content);

        $fhandle = fopen($fname,"w");
        fwrite($fhandle,$content);
        fclose($fhandle);
    }
    private function schema($table_name)
    {
        $table_name = str_plural($table_name);
        return "<?php
        
    use Illuminate\\Database\\Schema\\Blueprint;
    use Illuminate\\Database\\Migrations\\Migration;
    
    class Create".ucwords($table_name)."Table extends Migration
    {
        /**
         * Run the migrations.
         *
         * @return void
         */
        public function up()
        {
            Schema::create('$table_name', function (Blueprint \$table) {
                \$table->increments('id');
                \$table->string('name');
                \$table->string('email')->unique();
                \$table->string('password');
                \$table->rememberToken();
                \$table->timestamps();
            });
        }
    
        /**
         * Reverse the migrations.
         *
         * @return void
         */
        public function down()
        {
            Schema::drop('$table_name');
        }
    }
    ";
    }
    private function middleware($auth_name){
        return "<?php
namespace App\\Http\\Middleware;
use Closure;
use Illuminate\\Support\\Facades\\Auth;
class RedirectIfNotAdmin 
{
	/**
	 * Handle an incoming request.
	 *
	 * @param  \\Illuminate\\Http\\Request  \$request
	 * @param  \\Closure  \$next
	 * @param  string|null  \$guard
	 * @return mixed
	 */
	public function handle(\$request, Closure \$next, \$guard = '$auth_name')
	{
	    if (!Auth::guard(\$guard)->check()) {
	        return redirect('/');
	    }
	    return \$next(\$request);
	}
}
        ";
    }
    private function authController($auth_name)
    {
        return "<?php
namespace App\\Http\\Controllers\\".ucwords($auth_name)."Auth;
use App\\".ucwords($auth_name).";
use Validator;
use App\\Http\\Controllers\\Controller;
use Illuminate\\Foundation\\Auth\\ThrottlesLogins;
use Illuminate\\Foundation\\Auth\\AuthenticatesAndRegistersUsers;
class AuthController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Registration & Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles the registration of new users, as well as the
    | authentication of existing users. By default, this controller uses
    | a simple trait to add these behaviors. Why don't you explore it?
    |
    */
    use AuthenticatesAndRegistersUsers, ThrottlesLogins;
    /**
     * Where to redirect users after login / registration.
     *
     * @var string
     */
    protected \$redirectTo = '/$auth_name';
    protected \$guard = '$auth_name';
    /**
     * Create a new authentication controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        \$this->middleware(\$this->guestMiddleware(), ['except' => 'logout']);
    }
    public function showLoginForm(){
        if(view()->exists('auth.authenticate')){
            return view('auth.authenticate');
        }
        return view('admin.auth.login');
    }
    
    public function showRegistrationForm(){
        return view('admin.auth.register');
    }
    /**
     * Get a validator for an incoming registration request.
     *
     * @param  array  \$data
     * @return \\Illuminate\\Contracts\\Validation\\Validator
     */
    protected function validator(array \$data)
    {
        return Validator::make(\$data, [
            'name' => 'required|max:255',
            'email' => 'required|email|max:255|unique:".strtolower(str_plural($auth_name))."',
            'password' => 'required|min:6|confirmed',
        ]);
    }
    /**
     * Create a new user instance after a valid registration.
     *
     * @param  array  \$data
     * @return ".ucwords(str_plural($auth_name))."
     */
    protected function create(array \$data)
    {
        return Admin::create([
            'name' => \$data['name'],
            'email' => \$data['email'],
            'password' => bcrypt(\$data['password']),
        ]);
    }
}";    
    }
    private function controller($auth_name)
    {
        return "<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
use App\\Http\\Requests;
use Illuminate\\Support\\Facades\\Auth;
class ".ucwords($auth_name)."Controller extends Controller
{
    public function __construct(){
    	\$this->middleware('".$auth_name."');
    }
    public function index(){
    	// return Auth::guard('".$auth_name."')->user();
    	return view('".$auth_name.".dashboard');
    }
}";
    }
    private function loginHTML($auth_name){
        return "@extends('layouts.app')

@section('content')
<div class=\"container\">
    <div class=\"row\">
        <div class=\"col-md-8 col-md-offset-2\">
            <div class=\"panel panel-default\">
                <div class=\"panel-heading\">Login</div>
                <div class=\"panel-body\">
                    <form class=\"form-horizontal\" role=\"form\" method=\"POST\" action=\"{{ url('/".$auth_name."/login') }}\">
                        {{ csrf_field() }}

                        <div class=\"form-group{{ \$errors->has('email') ? ' has-error' : '' }}\">
                            <label class=\"col-md-4 control-label\">E-Mail Address</label>

                            <div class=\"col-md-6\">
                                <input type=\"email\" class=\"form-control\" name=\"email\" value=\"{{ old('email') }}\">

                                @if (\$errors->has('email'))
                                    <span class=\"help-block\">
                                        <strong>{{ \$errors->first('email') }}</strong>
                                    </span>
                                @endif
                            </div>
                        </div>

                        <div class=\"form-group{{ \$errors->has('password') ? ' has-error' : '' }}\">
                            <label class=\"col-md-4 control-label\">Password</label>

                            <div class=\"col-md-6\">
                                <input type=\"password\" class=\"form-control\" name=\"password\">

                                @if (\$errors->has('password'))
                                    <span class=\"help-block\">
                                        <strong>{{ \$errors->first('password') }}</strong>
                                    </span>
                                @endif
                            </div>
                        </div>

                        <div class=\"form-group\">
                            <div class=\"col-md-6 col-md-offset-4\">
                                <div class=\"checkbox\">
                                    <label>
                                        <input type=\"checkbox\" name=\"remember\"> Remember Me
                                    </label>
                                </div>
                            </div>
                        </div>

                        <div class=\"form-group\">
                            <div class=\"col-md-6 col-md-offset-4\">
                                <button type=\"submit\" class=\"btn btn-primary\">
                                    <i class=\"fa fa-btn fa-sign-in\"></i>Login
                                </button>

                                <!-- <a class=\"btn btn-link\" href=\"{{ url('/password/reset') }}\">Forgot Your Password?</a> -->
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection";
    }
    private function registerHTML($auth_name)
    {
        return "@extends('layouts.app')

@section('content')
<div class=\"container\">
    <div class=\"row\">
        <div class=\"col-md-8 col-md-offset-2\">
            <div class=\"panel panel-default\">
                <div class=\"panel-heading\">Register ".ucwords($auth_name)."</div>
                <div class=\"panel-body\">
                    <form class=\"form-horizontal\" role=\"form\" method=\"POST\" action=\"{{ url('/".$auth_name."/register') }}\">
                        {{ csrf_field() }}

                        <div class=\"form-group{{ \$errors->has('name') ? ' has-error' : '' }}\">
                            <label class=\"col-md-4 control-label\">Name</label>

                            <div class=\"col-md-6\">
                                <input type=\"text\" class=\"form-control\" name=\"name\" value=\"{{ old('name') }}\">

                                @if (\$errors->has('name'))
                                    <span class=\"help-block\">
                                        <strong>{{ \$errors->first('name') }}</strong>
                                    </span>
                                @endif
                            </div>
                        </div>

                        <div class=\"form-group{{ \$errors->has('email') ? ' has-error' : '' }}\">
                            <label class=\"col-md-4 control-label\">E-Mail Address</label>

                            <div class=\"col-md-6\">
                                <input type=\"email\" class=\"form-control\" name=\"email\" value=\"{{ old('email') }}\">

                                @if (\$errors->has('email'))
                                    <span class=\"help-block\">
                                        <strong>{{ \$errors->first('email') }}</strong>
                                    </span>
                                @endif
                            </div>
                        </div>

                        <div class=\"form-group{{ \$errors->has('password') ? ' has-error' : '' }}\">
                            <label class=\"col-md-4 control-label\">Password</label>

                            <div class=\"col-md-6\">
                                <input type=\"password\" class=\"form-control\" name=\"password\">

                                @if (\$errors->has('password'))
                                    <span class=\"help-block\">
                                        <strong>{{ \$errors->first('password') }}</strong>
                                    </span>
                                @endif
                            </div>
                        </div>

                        <div class=\"form-group{{ \$errors->has('password_confirmation') ? ' has-error' : '' }}\">
                            <label class=\"col-md-4 control-label\">Confirm Password</label>

                            <div class=\"col-md-6\">
                                <input type=\"password\" class=\"form-control\" name=\"password_confirmation\">

                                @if (\$errors->has('password_confirmation'))
                                    <span class=\"help-block\">
                                        <strong>{{ \$errors->first('password_confirmation') }}</strong>
                                    </span>
                                @endif
                            </div>
                        </div>

                        <div class=\"form-group\">
                            <div class=\"col-md-6 col-md-offset-4\">
                                <button type=\"submit\" class=\"btn btn-primary\">
                                    <i class=\"fa fa-btn fa-user\"></i>Register
                                </button>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection";
    }
    private function passwordHTML($auth_name)
    {
        return "Click here to reset your password: <a href=\"{{ \$link = url('password/reset', \$token).'?email='.urlencode(\$user->getEmailForPasswordReset()) }}\"> {{ \$link }} </a>
";
    }
    private function passwordEmailHTML($auth_name){
        return "
@extends('layouts.app')

<!-- Main Content -->
@section('content')
<div class=\"container\">
    <div class=\"row\">
        <div class=\"col-md-8 col-md-offset-2\">
            <div class=\"panel panel-default\">
                <div class=\"panel-heading\">Reset Password</div>
                <div class=\"panel-body\">
                    @if (session('status'))
                        <div class=\"alert alert-success\">
                            {{ session('status') }}
                        </div>
                    @endif

                    <form class=\"form-horizontal\" role=\"form\" method=\"POST\" action=\"{{ url('/password/email') }}\">
                        {{ csrf_field() }}

                        <div class=\"form-group{{ \$errors->has('email') ? ' has-error' : '' }}\">
                            <label class=\"col-md-4 control-label\">E-Mail Address</label>

                            <div class=\"col-md-6\">
                                <input type=\"email\" class=\"form-control\" name=\"email\" value=\"{{ old('email') }}\">

                                @if (\$errors->has('email'))
                                    <span class=\"help-block\">
                                        <strong>{{ \$errors->first('email') }}</strong>
                                    </span>
                                @endif
                            </div>
                        </div>

                        <div class=\"form-group\">
                            <div class=\"col-md-6 col-md-offset-4\">
                                <button type=\"submit\" class=\"btn btn-primary\">
                                    <i class=\"fa fa-btn fa-envelope\"></i>Send Password Reset Link
                                </button>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection";
    }
    private function passwordResetHTML($auth_name)
    {
        return "@extends('layouts.app')

@section('content')
<div class=\"container\">
    <div class=\"row\">
        <div class=\"col-md-8 col-md-offset-2\">
            <div class=\"panel panel-default\">
                <div class=\"panel-heading\">Reset Password</div>

                <div class=\"panel-body\">
                    <form class=\"form-horizontal\" role=\"form\" method=\"POST\" action=\"{{ url('/password/reset') }}\">
                        {{ csrf_field() }}

                        <input type=\"hidden\" name=\"token\" value=\"{{ \$token }}\">

                        <div class=\"form-group{{ \$errors->has('email') ? ' has-error' : '' }}\">
                            <label class=\"col-md-4 control-label\">E-Mail Address</label>

                            <div class=\"col-md-6\">
                                <input type=\"email\" class=\"form-control\" name=\"email\" value=\"{{ \$email or old('email') }}\">

                                @if (\$errors->has('email'))
                                    <span class=\"help-block\">
                                        <strong>{{ \$errors->first('email') }}</strong>
                                    </span>
                                @endif
                            </div>
                        </div>

                        <div class=\"form-group{{ \$errors->has('password') ? ' has-error' : '' }}\">
                            <label class=\"col-md-4 control-label\">Password</label>

                            <div class=\"col-md-6\">
                                <input type=\"password\" class=\"form-control\" name=\"password\">

                                @if (\$errors->has('password'))
                                    <span class=\"help-block\">
                                        <strong>{{ \$errors->first('password') }}</strong>
                                    </span>
                                @endif
                            </div>
                        </div>

                        <div class=\"form-group{{ \$errors->has('password_confirmation') ? ' has-error' : '' }}\">
                            <label class=\"col-md-4 control-label\">Confirm Password</label>
                            <div class=\"col-md-6\">
                                <input type=\"password\" class=\"form-control\" name=\"password_confirmation\">

                                @if (\$errors->has('password_confirmation'))
                                    <span class=\"help-block\">
                                        <strong>{{ \$errors->first('password_confirmation') }}</strong>
                                    </span>
                                @endif
                            </div>
                        </div>

                        <div class=\"form-group\">
                            <div class=\"col-md-6 col-md-offset-4\">
                                <button type=\"submit\" class=\"btn btn-primary\">
                                    <i class=\"fa fa-btn fa-refresh\"></i>Reset Password
                                </button>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection";
    }
    private function dashboardHTML($auth_name){
        return "@extends('layouts.app')

@section('content')
<a href=\"{{url('/".strtolower(str_singular($auth_name))."/logout')}}\"></a>
<div class=\"container\">
    <div class=\"row\">
        <div class=\"col-md-10 col-md-offset-1\">
            <div class=\"panel panel-default\">
                <div class=\"panel-heading\">Welcome ".ucwords($auth_name)."</div>

                <div class=\"panel-body\">
                    Your Application's Landing Page.
                </div>
            </div>
        </div>
    </div>
</div>
@endsection";
    }
    private function routes($auth_name){
        return "Route::group(['middleware' => ['web']], function () {
    //Login Routes...
    Route::get('/".$auth_name."/login','".ucwords($auth_name)."Auth\\AuthController@showLoginForm');
    Route::post('/".$auth_name."/login','".ucwords($auth_name)."Auth\\AuthController@login');
    Route::get('/".$auth_name."/logout','".ucwords($auth_name)."Auth\\AuthController@logout');
    // Registration Routes...
    Route::get('".$auth_name."/register', '".ucwords($auth_name)."Auth\\AuthController@showRegistrationForm');
    Route::post('".$auth_name."/register', '".ucwords($auth_name)."Auth\\AuthController@register');
    Route::get('/".$auth_name."', '".ucwords($auth_name)."Controller@index');
});  ";
    }
    private function model($auth_name){
        return "<?php

namespace App;

use Illuminate\\Foundation\\Auth\\User as Authenticatable;

class ".ucwords(str_singular($auth_name))." extends Authenticatable
{
    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected \$fillable = [
        'name', 'email', 'password',
    ];

    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected \$hidden = [
        'password', 'remember_token',
    ];
}
";
    }

    private function fileModifier($file_name, $search, $replace)
    {
        $fname = $file_name;
        $fhandle = fopen($fname,"r");
        if(flock($fhandle,LOCK_EX )){
            $content = fread($fhandle,filesize($fname));
            $content = str_replace($search, $replace, $content);
            $fhandle = fopen($fname,"w");
            fwrite($fhandle,$content);
            fflush($fhandle);
            flock($fhandle,LOCK_UN );
        }else{
            $this->info('couldnot get the lock');
        }
        fclose($fhandle);
    }
}
