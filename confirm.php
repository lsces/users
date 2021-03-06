<?php
/**
 * $Header$
 *
 * Copyright (c) 2004 bitweaver.org
 * Copyright (c) 2003 tikwiki.org
 * Copyright (c) 2002-2003, Luis Argerich, Garland Foster, Eduardo Polidor, et. al.
 * All Rights Reserved. See below for details and a complete list of authors.
 * Licensed under the GNU LESSER GENERAL PUBLIC LICENSE. See http://www.gnu.org/copyleft/lesser.html for details
 *
 * $Id$
 * @package users
 * @subpackage functions
 */

/**
 * required setup
 */
require_once( '../kernel/setup_inc.php' );

if( !empty( $_REQUEST["v"] ) && strpos( $_REQUEST["v"], ':' ) ) {
	list( $userId, $provPass ) = explode( ':', $_REQUEST["v"] );
}

if( !empty( $userId ) && !empty( $provPass ) && $userInfo = $gBitUser->confirmRegistration( $userId, $provPass ) ) {
	$gBitSmarty->assign_by_ref( 'userInfo', $userInfo );
	$gBitSystem->display( 'bitpackage:users/change_password.tpl', 'Confirm Password Change' , array( 'display_mode' => 'display' ));
} else {
	$gBitSystem->fatalError( tra("This confirmation link is no longer valid.  Please Login or <a href=\"".USERS_PKG_URL."remind_password.php\">request a new password change</a>"), NULL, NULL, HttpStatusCodes::HTTP_GONE );
}
?>
