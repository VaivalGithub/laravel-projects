<?php


/** ===========================================================================
 * Http response codes
 * ===========================================================================*/

define('HTTP_STATUS_OK', 200);
define('HTTP_STATUS_RECORD_CREATED', 201);
define('HTTP_STATUS_BAD_REQUEST', 400);
define('HTTP_STATUS_UNAUTHENTICATED', 401);
define('HTTP_STATUS_FORBIDDEN', 403);
define('HTTP_STATUS_NOT_FOUND', 404);
define('HTTP_STATUS_SERVER_ERROR', 500);
define('HTTP_STATUS_CONFLICT', 409);
define('HTTP_PRECONDITION_FAILED', 412);
define('HTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS', 451);
define('HTTP_STATUS_VALIDATION_FAILED', 422);

/** ===========================================================================
 * Upload Paths
 * ===========================================================================*/

define('UPLOAD_USER_AVATAR_PATH', '/images/users/avatars/');
define('UPLOAD_TEAM_PATH', '/images/teams/');
define('UPLOAD_PATH_USER', '/uploads/users/');

/** ===========================================================================
 * User Constants
 * ===========================================================================*/

define('USER_STATUS_ACTIVE', 'active');
define('USER_STATUS_INACTIVE', 'inactive');
define('USER_STATUS_BANNED', 'banned');
define('USER_STATUS_UNVERIFIED','unverified');
define('USER_VERIFICATION_TOKEN_LENGTH', 6);
define('USER_RESET_PASSWORD_TOKEN_LENGTH', 6);
define('USER_INACTIVE_FIRST_NAME','Anonymous');
define('USER_INACTIVE_LAST_NAME','User');

/** ===========================================================================
 * Notification Type Constants
 * ===========================================================================*/

define('NOTIFICATION_ALERT_STATUS_ON', 1);
define('NOTIFICATION_ALERT_STATUS_OFF', 0);

/** ===========================================================================
 * Queue Constants
 * ===========================================================================*/
define('QUEUE_HIGH', 'high');
define('QUEUE_NORMAL', 'default');
define('QUEUE_LOW', 'low');

define('QUEUE_PRIORITY_EMAIL', QUEUE_HIGH);
define('QUEUE_EMAIL', QUEUE_NORMAL);

/** ===========================================================================
 * Roles
 * ===========================================================================*/
define('USER_ROLE_ADMIN', 1);
define('USER_ROLE_MANAGER', 2);
define('USER_ROLE_MEMBER', 3);

/** ===========================================================================
 * Permissions / Gates
 * ===========================================================================*/
define('PERM_ADMINISTRATOR','app-administrator');
define('PERM_MANAGER','team-manager');
define('PERM_MEMBER','team-member');

/** ===========================================================================
 * Pagination Size
 * ===========================================================================*/
define('PER_PAGE_NOTIFICATION', 10);
define('PER_PAGE_PENDING_INVITATION', 10);
define('PER_PAGE', 10);

/** ===========================================================================
 * Media Types
 * ===========================================================================*/
define('MEDIA_TYPE_TEXT','text');
define('MEDIA_TYPE_PHOTO','photo');
define('MEDIA_TYPE_AUDIO','audio');
define('MEDIA_TYPE_VIDEO','video');


/** ===========================================================================
 * General
 * ===========================================================================*/
define('DEVICE_OS_IOS',1);
define('DEVICE_OS_ANDROID',2);
define('DEVICE_OS_WEB',3);
define('DEVICE_OS_DESKTOP',4);
