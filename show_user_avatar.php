<?php
/**
 * show user avatar
 *
 * @copyright (c) 2004-15 bitweaver.org
 *
 * @package users
 * @subpackage functions
 */

/**
 * required setup
 */
global $gBitSystem, $gBitUser;

// application to display an image from the database with
// option to resize the image dynamically creating a thumbnail on the fly.
// you have to check if the user has permission to see this gallery
if (!isset($_REQUEST["user"])) {
	die;
}
$info = $gBitUser->get_user_avatar( $_REQUEST["user"] );
$type = $info["avatar_file_type"];
$content = $info["avatar_data"];
header ("Content-type: $type");
echo (string) $content;
