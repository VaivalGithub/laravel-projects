<?php

/** ===========================================================================
 * Response prepare  functions
 * ===========================================================================*/

if (! function_exists('prepareFieldErrorResponse')) {

    function prepareFieldErrorResponse($errors, $message = "")
    {
        $message = "The given data was invalid.";
        $response = [
            "message" => $message,
            "status" => HTTP_STATUS_BAD_REQUEST,
            "errors" => $errors
        ];
        return [$response, $response["status"]];
    }
}

if (! function_exists('prepareServerErrorResponse')) {

    function prepareServerErrorResponse($message = "")
    {
        if (App::environment() == "production" || App::environment() == "staging") {
            $message = "There is some error in processing your request, Please try latter";
        }
        $response = [
            "message" => $message,
            "status" => HTTP_STATUS_SERVER_ERROR
        ];
        return [$response, $response["status"]];
    }
}

if (! function_exists('prepareNotFoundResponse')) {

    function prepareNotFoundResponse($message = "")
    {
        $response = [
            "message" => $message,
            "status" => HTTP_STATUS_NOT_FOUND
        ];
        return [$response, $response["status"]];
    }
}

if (! function_exists('prepareSuccessResponse')) {

    function prepareSuccessResponse($response = [], $message = "")
    {
        if ($message == "") {
            $message = "Your request has been completed successfully";
        }

        $response = array_merge([
            'message' => $message,
            'data' => null,
        ], $response);
        return [$response, HTTP_STATUS_OK];
    }
}

if (! function_exists('prepareUnAuthenticatedResponse')) {

    function prepareUnAuthenticatedResponse($message = "")
    {
        $response = [
            "message" => $message,
            "status" => HTTP_STATUS_UNAUTHENTICATED
        ];
        return [$response, $response["status"]];
    }
}

if (! function_exists('prepareForbiddenResponse')) {

    function prepareForbiddenResponse($response)
    {
        $response = array_merge([
            'status' => HTTP_STATUS_FORBIDDEN
        ], $response);
        return [$response, $response["status"]];
    }
}

if (! function_exists('preparePreconditionFailedResponse')) {

    function preparePreconditionFailedResponse($response)
    {
        $response = array_merge([
            'status' => HTTP_PRECONDITION_FAILED
        ], $response);

        return [$response, $response["status"]];
    }
}

if (! function_exists('prepareResourceConflict')) {

    function prepareResourceConflict($response)
    {
        $response = array_merge([
            'status' => HTTP_STATUS_CONFLICT,
        ], $response);
        return [$response, $response['status']];
    }
}

if (! function_exists('prepareUnavailableForLegalReasons')) {

    function prepareUnavailableForLegalReasons($response)
    {
        $response = array_merge([
            'status' => HTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS,
        ], $response);
        return [$response, $response['status']];
    }
}


/** ===========================================================================
 * Upload path  functions
 * ===========================================================================*/

if (! function_exists('uploadPathUser')) {
    function uploadPathUser($userId, $subDirectory = "")
    {
        return UPLOAD_PATH_TEAM . $userId . $subDirectory;
    }
}

if (! function_exists('uploadPathUserAssets')) {

    function uploadPathUserAssets($userId)
    {
        return uploadPathUser($userId, '/assets');
    }
}

/** ===========================================================================
 * User functions
 * ===========================================================================*/

if (! function_exists('getUserAvatarPlaceholder')) {

    function getUserAvatarPlaceholder()
    {
        return asset('/assets/images/user-avatar-placeholder.jpg');
    }
}

/** ===========================================================================
 * Fcm functions
 * ===========================================================================*/

if (! function_exists('parsePushOptions')) {

    function parsePushOptions($options = [])
    {
        return array_merge([
            'service' => 'fcm',
        ], $options);
    }
}

/** ===========================================================================
 * General functions
 * ===========================================================================*/

if (! function_exists('isCollection')) {

    function isCollection($collection)
    {
        return $collection instanceof Illuminate\Support\Collection;
    }
}

if (! function_exists('carbon')) {

    function carbon($datetime)
    {
        if ($datetime instanceof \Carbon\Carbon) return $datetime;

        return new \Carbon\Carbon($datetime);
    }
}

if (! function_exists('generateUniqueFileName')) {

    function generateUniqueFileName($filename)
    {
        return \Illuminate\Support\Str::random(30) . "-" . time() . "-".  $filename;
    }
}

if (! function_exists('isFileExists')) {

    function isFileExists($file, $options = [])
    {

        $options = array_merge([
            'disk' => config('filesystems.default')
        ], $options);

        return Storage::disk($options['disk'])->exists($file);

    }
}


/**
 * Remove image from storage
 */
if (! function_exists('deleteImage')) {
    
    function deleteImage($file, $options = [])
    {
        $options = array_merge([
            'disk' => config('filesystems.default')
        ], $options);

        if (!Storage::disk($options['disk'])->exists($file)) {
            return false;
        }

        $result = Storage::disk($options['disk'])->delete($file);

        return true;
    }
}

