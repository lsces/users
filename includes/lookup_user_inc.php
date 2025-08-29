<?php
/**
 * $Header$
 *
 * @package users
 * @subpackage functions
 */

namespace Bitweaver\Users;
use Bitweaver\BitBase;
use Bitweaver\HttpStatusCodes;
use Bitweaver\KernelTools;
global $gQueryUser;

/**
 * This is a centralized include file to setup $gQueryUser var if you need to display detailed information about an arbitrary user.
 */
// fHomepage stuff is for backwards comability
if( isset( $_REQUEST['fHomepage'] )) {
	$_REQUEST['home'] = $_REQUEST['fHomepage'];
} elseif( isset( $_REQUEST['home'] )) {
	$_REQUEST['fHomepage'] = $_REQUEST['home'];
} elseif( isset($_REQUEST['content_id']) && BitBase::verifyId( $_REQUEST['content_id'] )) {
	$userInfo = $gBitUser->getUserInfo( [ 'content_id' => $_REQUEST['content_id'] ?? 0 ]);
	$_REQUEST['home'] = !empty( $userInfo['login'] ) ? $userInfo['login'] : null;
} elseif( isset($_REQUEST['user_id']) && BitBase::verifyId( $_REQUEST['user_id'] )) {
	$userInfo = $gBitUser->getUserInfo( array( 'user_id' => $_REQUEST['user_id'] ));
	$_REQUEST['home'] = !empty( $userInfo['login'] ) ? $userInfo['login'] : null;
}

if( isset( $_REQUEST['home'] )) {
	// this allows for a numeric user_id or alpha_numeric user_id
	$queryUserId = $gBitUser->lookupHomepage( $_REQUEST['home'] ); //, $gBitSystem->getConfig( 'users_case_sensitive_login' ) == 'y' );
	$userClass = $gBitSystem->getConfig( 'user_class', (defined('ROLE_MODEL') ) ?  '\Bitweaver\Users\RolePermUser' : '\Bitweaver\Users\BitPermUser' );
	$gQueryUser = new RolePermUser( $queryUserId );
	$gQueryUser->load( true );
	$gQueryUser->setCacheableObject( false );
} elseif( $gBitUser->isValid() ) {
	// We are looking at ourself, use our existing BitUser
	global $gBitUser;
	$gQueryUser = &$gBitUser;
}

if( !$gBitUser->hasPermission( 'p_users_admin' ) ) {
	if( $gQueryUser->mUserId != $gBitUser->mUserId && $gQueryUser->getPreference( 'users_information' ) == 'private' ) {
		// don't spit error for SEO reasons
		$gBitSmarty->assign( 'metaNoIndex', true );
		$gBitSystem->fatalError( KernelTools::tra( "This information is private" ) , null, null, HttpStatusCodes::HTTP_NOT_FOUND );
	}
}

if( $gQueryUser->isValid() ) {
	$gQueryUser->sanitizeUserInfo();
	$gBitSmarty->assign( 'gQueryUser', $gQueryUser );
	$gBitSmarty->assign( 'userInfo', $gQueryUser->mInfo );
	$gBitSmarty->assign( 'userPrefs', $gQueryUser->mPrefs );
	$gBitSmarty->assign( 'homepage_header', $gQueryUser->getPreference( 'homepage_header' ) );
}
