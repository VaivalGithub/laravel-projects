<?php

namespace App\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Foundation\Support\Providers\RouteServiceProvider as ServiceProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;

class RouteServiceProvider extends ServiceProvider
{
    /**
     * The path to the "home" route for your application.
     *
     * This is used by Laravel authentication to redirect users after login.
     *
     * @var string
     */
    public const HOME = '/dashboard';

    /**
     * The controller namespace for the application.
     *
     * When present, controller route declarations will automatically be prefixed with this namespace.
     *
     * @var string|null
     */
    protected $namespace = 'App\\Http\\Controllers';


    /** 
    * @var string $adminNamespace 
    */
    protected $adminNamespace ='App\\Http\\Controllers\\Admin';

    /** 
    * @var string $apiNamespace 
    */
    protected $apiNamespace ='App\\Http\\Controllers\\Api';

    /**
     * Define your route model bindings, pattern filters, etc.
     *
     * @return void
     */
    public function boot()
    {
        $this->configureRateLimiting();

        $this->routes(function () {

            Route::prefix('api/v1')
                ->middleware('api', 'api_version:v1')
                ->namespace($this->apiNamespace . '\V1')
                ->group(base_path('routes/api/v1.php'));

            Route::prefix('api/v2')
                ->middleware('api', 'api_version:v2')
                ->namespace($this->apiNamespace . '\V2')
                ->group(base_path('routes/api/v2.php'));

            Route::middleware('web')
                ->namespace($this->namespace)
                ->group(base_path('routes/web/front.php'));
        });
    }


    /**
     * Configure the rate limiters for the application.
     *
     * @return void
     */
    protected function configureRateLimiting()
    {
        RateLimiter::for('api', function (Request $request) {
            return Limit::perMinute(60)->by(optional($request->user())->id ?: $request->ip());
        });
    }
}