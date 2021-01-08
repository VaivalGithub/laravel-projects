<?php

namespace App\Http\Controllers\Api\V1;

use Illuminate\Http\Request;
use App\Http\Controllers\Api\ApiController;
use App\Contracts\Repositories\User\UserRepositoryInterface;
use Illuminate\Auth\Events\Registered;
use Illuminate\Support\Facades\Auth;
use App\Http\Resources\V1\UserResource;
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
    public function userProfile() {
        return response()->json(auth()->user());
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
// <?php

// namespace App\Http\Controllers\Api\v1;

// use App\Events\ResetPassword;
// use App\Events\UserDeactivated;
// use App\Http\Controllers\Controller;
// use App\Http\Resources\v1\Auth\UserResource;
// use App\Models\FcmToken;
// use App\Models\User;
// use Carbon\Carbon;
// use Illuminate\Auth\Events\Registered;
// use Illuminate\Http\Request;
// use Illuminate\Support\Facades\Auth;
// use Illuminate\Support\Facades\Validator;
// use Illuminate\Support\Str;
// use App\Events\EmailUpdate;
// use Hash;
// use Exception;
// use DB;

// class AuthController extends Controller
// {

//     public function register(Request $request)
//     {
//         $response = [];

//         // Validate resiter request
//         $validator = Validator::make($request->all(),
//             [
//                 'first_name' => 'required|string|max:100',
//                 'last_name' => 'required|string|max:100',
//                 'email' => 'required|string|email|max:255|unique:users',
//                 'password' => 'required|string|min:8|confirmed',
//             ]
//         );

//         if ($validator->fails()) {
//             $message = "The given data was invalid.";
//             list($response, $statusCode) = prepareFieldErrorResponse($validator->errors(), $message);
//             return response($response, $statusCode);
//         }

//         DB::beginTransaction();
//         try {
//             // create new user
//             $user = new User;
//             $user->first_name = $request->first_name;
//             $user->last_name = $request->last_name;
//             $user->email = $request->email;
//             $user->password = Hash::make($request->password);
//             $user->verification_code = Str::random(USER_VERIFICATION_TOKEN_LENGTH);
//             $user->save();

//             $user->profile()->create([]);

//             // fire register user event to process async tasks
//             event(new Registered($user));

//             // send verification email
//             $user->sendEmailVerificationNotification();
//             DB::commit();

//         } catch (Exception $ex) {
//             DB::rollBack();
//             throw $ex;
//         }


//         $response["message"] = "User has been registered successfully!";
//         list($response, $statusCode) = prepareSuccessResponse($response);

//         return response($response, $statusCode);
//     }

//     public function login(Request $request)
//     {

//         $response = [];

//         // validate login request
//         $validator = Validator::make($request->all(), [
//             'email' => 'required|email',
//             'password' => 'required|string',
//         ]);

//         if ($validator->fails()) {
//             $message = "The given data was invalid.";
//             list($response, $statusCode) = prepareFieldErrorResponse($validator->errors(), $message);
//             return response($response, $statusCode);
//         }


//         // check if user exists
//         $user = User::where('email', $request->email)->first();

//         // check if user provided valid password
//         if (!$user) {

//             $message = "The email you've entered doesn't match our records. Please check & try again";
//             list($response, $statusCode) = prepareNotFoundResponse($message);
//             return response($response, $statusCode);
//         }

//         // check if user provided valid password
//         if (!$user || !Hash::check($request->password, $user->password)) {

//             $message = "The provided credentials are incorrect";
//             list($response, $statusCode) = prepareUnAuthenticatedResponse($message);
//             return response($response, $statusCode);
//         }

//         // check if user status is active
//         if ($user->status == USER_STATUS_BANNED || $user->status == USER_STATUS_UNVERIFIED) {
//             $response['message'] = "User account is currently {$user->status}";
//             list($response, $statusCode) = prepareForbiddenResponse($response);
//             return response($response, $statusCode);
//         }

//         // activate user account on successfull login if inactive
//         if($user->status == USER_STATUS_INACTIVE){
//             $user->status = USER_STATUS_ACTIVE;
//             $user->save();
//         }

//         // generate  token and relevent data
//         $response['data'] = (new UserResource($user))->resolve();
//         list($response) = prepareSuccessResponse($response);

//         return response($response);
//     }

//     public function logout(Request $request)
//     {

//         $response = [];

//         $request->user()->currentAccessToken()->delete();

//         list($response) = prepareSuccessResponse($response);

//         return response($response);


//     }

//     public function forgotPassword(Request $request)
//     {

//         $response = [];

//         // validate reset data

//         $validator = Validator::make($request->all(), [
//             'email' => 'required|email'
//         ]);

//         if ($validator->fails()) {
//             $message = "The given data was invalid.";
//             list($response, $statusCode) = prepareFieldErrorResponse($validator->errors(), $message);
//             return response($response, $statusCode);
//         }


//         // check if email already exists

//         $user = User::where('email', $request->email)->first();
//         if (!$user) {

//             $message = "The email you've entered doesn't match our records. Please check & try again";
//             list($response, $statusCode) = prepareNotFoundResponse($message);
//             return response($response, $statusCode);

//         }

//         // generate token and set into reset passwords table
//         $token = $user->generateResetPasswordToken();

//         // send notification to user for reset password by token
//         $user->sendResetPasswordByTokenNotification($token);

//         $response["message"] = "Please check your email for reset token";
//         list($response, $statusCode) = prepareSuccessResponse($response);

//         return response($response, $statusCode);

//     }

//     public function reset(Request $request)
//     {

//         $response = [];

//         // validate reset data
//         $validator = Validator::make($request->all(), [
//             'email' => 'required_with:token|email',
//             'token' => 'required_without:old_password',
//             'old_password' => 'required_without:token|string|min:8',
//             'password' => 'required|confirmed|min:8'
//         ]);

//         if ($validator->fails()) {
//             $message = "The given data was invalid.";
//             list($response, $statusCode) = prepareFieldErrorResponse($validator->errors(), $message);
//             return response($response, $statusCode);
//         }

//         $user = null;

//         DB::beginTransaction();
//         try {
//             // If reset password from reset token request
//             if ($request->has('token')) {

//                 // check if token is expired
//                 $user = User::where('email', $request->email)->first();

//                 if (!$user) {
//                     $message = "The email you've entered doesn't match our records. Please check & try again";
//                     list($response, $statusCode) = prepareNotFoundResponse($message);
//                     return response($response, $statusCode);
//                 }

//                 $tokenExists = $user->validateResetPasswordToken($request->only(['email', 'token']));

//                 if (!$tokenExists) {
//                     $message = "The token you've entered doesn't match our records.!";
//                     list($response, $statusCode) = prepareNotFoundResponse($message);
//                     return response($response, $statusCode);
//                 }

//             } else {
//                 // If reset password from auth token request
//                 $user = Auth::guard('sanctum')->user();

//                 if (!$user) {
//                     $message = "Sorry we can't recognize you!. Please login again";
//                     list($response, $statusCode) = prepareNotFoundResponse($message);
//                     return response($response, $statusCode);
//                 }

//                 if (!Hash::check($request->old_password, $user->password)) {

//                     $message = "The provided credentials are incorrect";
//                     list($response, $statusCode) = prepareUnAuthenticatedResponse($message);
//                     return response($response, $statusCode);
//                 }

//                 $user->tokens()->where('id','!=', $user->currentAccessToken()->id)->delete();

//             }


//             // change the password
//             $user->password = Hash::make($request->password);
//             $user->save();

//             DB::commit();

//         } catch (Exception $ex) {
//             DB::rollBack();
//             throw $ex;
//         }

//         event(new ResetPassword($user));

//         $response["message"] = "Password has been changed successfully!";

//         list($response) = prepareSuccessResponse($response);

//         return response($response);
//     }

//     public function verifyResetToken(Request $request)
//     {
//         $response = [];

//         // validate reset data
//         $validator = Validator::make($request->all(), [
//             'email' => 'required|email',
//             'token' => 'required',
//         ]);

//         if ($validator->fails()) {
//             $message = "The given data was invalid.";
//             list($response, $statusCode) = prepareFieldErrorResponse($validator->errors(), $message);
//             return response($response, $statusCode);
//         }

//         // check if token is expired

//         $user = User::where('email', $request->email)->first();

//         if (!$user) {
//             $message = "The email you've entered doesn't match our records. Please check & try again";
//             list($response, $statusCode) = prepareNotFoundResponse($message);
//             return response($response, $statusCode);
//         }

//         $tokenExists = $user->validateResetPasswordToken($request->only(['email', 'token']));

//         if (!$tokenExists) {
//             $response["message"] = "The token you've entered doesn't match our records.!";
//             $response["status"] = 404;
//             return response($response, 404);
//         }

//         $response["message"] = "Your reset password token is valid!";
//         list($response) = prepareSuccessResponse($response);

//         return response($response);
//     }

//     public function resendVerification(Request $request)
//     {

//         $response = [];

//         // validate request
//         $validator = Validator::make($request->all(), [
//             'email' => 'required|email'
//         ]);

//         if ($validator->fails()) {
//             list($response, $statusCode) = prepareFieldErrorResponse($validator->errors());
//             return response($response, $statusCode);
//         }

//         // Find user by email
//         $user = User::where('email', $request->email)->first();

//         if (!$user) {
//             $message = "The email you've entered doesn't match our records. Please check & try again";
//             list($response, $statusCode) = prepareNotFoundResponse($message);
//             return response($response, $statusCode);
//         }

//         $user->verification_code = Str::random(USER_VERIFICATION_TOKEN_LENGTH);
//         $user->save();

//         // send verification code notification
//         $user->sendEmailVerificationNotification();

//         list($response) = prepareSuccessResponse($response);

//         return response($response);

//     }

//     public function resendEmailVerification(Request $request)
//     {

//         $response = [];

//         // validate request
//         $validator = Validator::make($request->all(), [
//             'email' => 'required|email'
//         ]);

//         if ($validator->fails()) {
//             list($response, $statusCode) = prepareFieldErrorResponse($validator->errors());
//             return response($response, $statusCode);
//         }

//         // Find user by email
//         $user = User::where('updated_email', $request->email)->first();

//         if (!$user) {
//             $message = "The email you've entered doesn't match our records. Please check & try again";
//             list($response, $statusCode) = prepareNotFoundResponse($message);
//             return response($response, $statusCode);
//         }

//         $user->verification_code = Str::random(USER_VERIFICATION_TOKEN_LENGTH);
//         $user->save();
//         // fire update email event to process async tasks
//         event(new EmailUpdate($user));

//         list($response) = prepareSuccessResponse($response);

//         return response($response);

//     }

//     public function verifyAccount(Request $request)
//     {

//         // validate request
//         $validator = Validator::make($request->all(), [
//             'email' => 'required|email',
//             'verification_code' => 'required|string'
//         ]);

//         if ($validator->fails()) {
//             $message = "The given data was invalid.";
//             list($response, $statusCode) = prepareFieldErrorResponse($validator->errors(), $message);
//             return response($response, $statusCode);
//         }


//         // check if code is valid
//         $user = User::where('email', $request->email)->where('verification_code', $request->verification_code)->first();

//         if (!$user) {
//             $response['message'] = "The provided code is incorrect or expired";
//             list($response, $statusCode) = prepareForbiddenResponse($response);
//             return response($response, $statusCode);
//         }

//         // update user status
//         $user->status = USER_STATUS_ACTIVE;
//         $user->email_verified_at = Carbon::now();
//         $user->save();

//         // generate  token and relevent data
//         $response['data'] = (new UserResource($user))->resolve();

//         list($response) = prepareSuccessResponse($response);

//         return response($response);

//     }

//     public function verifyEmail(Request $request)
//     {

//         // validate request
//         $validator = Validator::make($request->all(), [
//             'email' => 'required|email',
//             'verification_code' => 'required|string'
//         ]);

//         if ($validator->fails()) {
//             $message = "The given data was invalid.";
//             list($response, $statusCode) = prepareFieldErrorResponse($validator->errors(), $message);
//             return response($response, $statusCode);
//         }


//         // check if code is valid
//         $user = User::where('email', $request->email)->where('verification_code', $request->verification_code)->first();

//         if (!$user) {
//             $response['message'] = "The provided code is incorrect or expired";
//             list($response, $statusCode) = prepareForbiddenResponse($response);
//             return response($response, $statusCode);
//         }

//         // update user status
//         $user->email = $user->updated_email;
//         $user->updated_email = null;
//         $user->email_verified_at = Carbon::now();
//         $user->save();

//         // generate  token and relevent data
//         $response['data'] = (new UserResource($user))->resolve();

//         list($response) = prepareSuccessResponse($response);

//         return response($response);

//     }

//     public function registerFCM(Request $request)
//     {

//         $response = [];

//         // validate data
//         $validator = Validator::make(
//             $request->all(), [
//                 'device_id' => 'nullable|string',
//                 'device_token' => 'required|string',
//                 'device_os_id' => 'required|integer',
//                 'old_device_token' => 'nullable|string'
//             ]
//         );

//         if ($validator->fails()) {
//             $message = "The given data was invalid.";
//             list($response, $statusCode) = prepareFieldErrorResponse($validator->errors(), $message);
//             return response($response, $statusCode);
//         }

//         // find current access token
//         $currentAccessToken = $request->user()->currentAccessToken();

//         // check if fcm token exists with another token then delete that token
//         $existingAccessToken = $request->user()->tokens()->where('device_token', $request->device_token)->first();

//         if ($existingAccessToken && $currentAccessToken->id != $existingAccessToken->id) {
//             $existingAccessToken->delete();
//         }

//         // update fcm token with current token

//         $currentAccessToken->device_token = $request->device_token;
//         $currentAccessToken->device_os_id = $request->device_os_id;
//         $currentAccessToken->device_id = $request->device_id;
//         $currentAccessToken->save();

//         $response['message'] = "Device token has been updated successfuly!";
//         list($response) = prepareSuccessResponse($response);

//         return response($response);
//     }

//     public function deactivateAccount(Request $request)
//     {
//         $response = [];
//         // validate reset data
//         $validator = Validator::make($request->all(), [
//             'password' => 'required|min:8'
//         ]);

//         if ($validator->fails()) {
//             $message = "The given data was invalid.";
//             list($response, $statusCode) = prepareFieldErrorResponse($validator->errors(), $message);
//             return response($response, $statusCode);
//         }

//         // check if user provided valid password
//         if (!Hash::check($request->password, $request->user()->password)) {

//             $message = "The provided credentials are incorrect";
//             list($response, $statusCode) = prepareUnAuthenticatedResponse($message);
//             return response($response, $statusCode);
//         }

//         // retrive all teams
//         // retrive random user from team priority by admin
//         // make super admin to this user

//         // delete all users token
//         $request->user()->tokens()->delete();
//         $request->user()->status = USER_STATUS_INACTIVE;
//         $request->user()->save();

//         event(new UserDeactivated($request->user()));

//         list($response) = prepareSuccessResponse($response);
//         return response($response);
//     }

// }
