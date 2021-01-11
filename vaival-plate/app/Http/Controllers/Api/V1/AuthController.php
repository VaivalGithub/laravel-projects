<?php

namespace App\Http\Controllers\Api\V1;

use Illuminate\Http\Request;
use App\Http\Controllers\Api\ApiController;
use App\Contracts\Repositories\User\UserRepositoryInterface;
use Illuminate\Auth\Events\Registered;
use Illuminate\Support\Facades\Auth;
use App\Http\Resources\V1\AuthResource;
use App\Traits\ResponseAPI;
use App\Models\User;
use Carbon\Carbon;
use Exception;
use Validator;
use DB, Str;

class AuthController extends ApiController
{
    use ResponseAPI;

    protected $userRepo;

    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct(UserRepositoryInterface $userRepo) {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
        $this->userRepo = $userRepo;
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */

    /**
    * @OA\Post(
    * path="/login",
    * summary="Sign in",
    * description="Login by email, password",
    * operationId="authLogin",
    * tags={"auth"},
    * @OA\RequestBody(
    *    required=true,
    *    description="Pass user credentials",
    *    @OA\JsonContent(
    *       required={"email","password"},
    *       @OA\Property(property="email", type="string", format="email", example="user1@mail.com"),
    *       @OA\Property(property="password", type="string", format="password", example="PassWord12345"),
    *       @OA\Property(property="persistent", type="boolean", example="true"),
    *    ),
    * ),
    * @OA\Response(
    *    response=422,
    *    description="Wrong credentials response",
    *    @OA\JsonContent(
    *       @OA\Property(property="message", type="string", example="Sorry, wrong email address or password. Please try again")
    *        )
    *     )
    * )
    */
    public function login(Request $request){
    	$validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return $this->error(__("Validation Failed"), $validator->errors(), HTTP_STATUS_VALIDATION_FAILED);
        }

        if (! $token = auth('api')->attempt($validator->validated())) {
            return $this->error(__("Unauthorized"), ['error' => 'Unauthorized'], HTTP_STATUS_UNAUTHENTICATED);
        }

        return $this->createNewToken($token);
    }

    /**
     * Register a User.
     *
     * @return \Illuminate\Http\JsonResponse
     */

    /**
    * @OA\Post(
    * path="/register",
    * summary="Sign up",
    * description="Register user with basic info",
    * operationId="authSignup",
    * tags={"auth"},
    * @OA\RequestBody(
    *    required=true,
    *    description="Post user info",
    *    @OA\JsonContent(
    *       required={"first_name","last_name","password","email","password","password_confirmation"},
    *       @OA\Property(property="first_name", type="string", format="string", example="furman"),
    *       @OA\Property(property="last_name", type="string", format="string", example="ali"),
    *       @OA\Property(property="email", type="string", format="email", example="user1@mail.com"),
    *       @OA\Property(property="password", type="string", format="password", example="PassWord12345"),
    *       @OA\Property(property="password_confirmation", type="string", format="password", example="PassWord12345"),
    *       @OA\Property(property="persistent", type="boolean", example="true"),
    *    ),
    * ),
    * @OA\Response(
    *    response=422,
    *    description="Wrong data response",
    *    @OA\JsonContent(
    *       @OA\Property(property="message", type="string", example="")
    *        )
    *     )
    * )
    */
    public function register(Request $request) {
        $validator = Validator::make($request->all(), [
            'first_name' => 'required|string|between:2,100',
            'last_name' => 'required|string|between:2,100',
            'email' => 'required|string|email|max:100|unique:users',
            'password' => 'required|string|confirmed|min:6',
        ]);

        if($validator->fails()){
            return $this->error(__("Validation Failed"), $validator->errors(), HTTP_STATUS_VALIDATION_FAILED);
        }

        DB::beginTransaction();
        try {
            $user = User::create(array_merge(
                $validator->validated(),
                [
                    'password' => bcrypt($request->password),
                    'verification_code' => Str::random(USER_VERIFICATION_TOKEN_LENGTH)
                ]
            ));

            event(new Registered($user));
            DB::commit();
        }
        catch (Exception $e) {
            DB::rollBack();
            throw $e;
        }

        return $this->success(__("User successfully registered"), $user, HTTP_STATUS_RECORD_CREATED);
    }


    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout() {
        auth()->logout();

        return response()->json(['message' => __('User successfully signed out')]);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh() {
        return $this->createNewToken(auth()->refresh());
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    /**
    * @OA\Get(
    * path="/user-profile",
    * summary="Get profile",
    * description="Get authenticated user profile",
    * operationId="getProfile",
    * tags={"auth","profile"},
    * @OA\Response(
    *    response=200,
    *    description="Get user profile",
    *    @OA\JsonContent(
    *       @OA\Property(property="message", type="string", example="")
    *        )
    *     )
    * )
    */
    public function userProfile() {

        $data = (new AuthResource(auth()->user()))->resolve();
        return $this->success(__("User profile"), $data);
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function createNewToken($token){

        $data = [
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth('api')->factory()->getTTL() * 60,
            // 'expires_in' => auth()->factory()->getTTL() * 60,
            'user' => auth()->user()
        ];
        return $this->success(__('Log in was accepted'), $data);
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function verifyEmail(Request $request)
    {

        // validate request
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'verification_code' => 'required|string'
        ]);

        if ($validator->fails()) {
            return $this->error(__("Validation Failed"), $validator->errors(), HTTP_STATUS_VALIDATION_FAILED);
        }


        // check if code is valid
        $user = User::where('email', $request->email)->where('verification_code', $request->verification_code)->first();

        if (!$user = $this->userRepo->getUserByEmailAndVerficationCode($request->email, $request->verification_code)) {
            return $this->error(__("The provided code is incorrect or expired"), NULL, HTTP_STATUS_FORBIDDEN);
        }

        // update user status
        $user->email_verified_at = Carbon::now();
        $user->save();

        return $this->success(__('User email verified'), $data);

    }

}