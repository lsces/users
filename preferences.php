<?php
namespace Bitweaver\Users;
use Bitweaver\KernelTools;
use function Bitweaver\Users\scramble_email;

/**
 * user preferences
 *
 * @copyright (c) 2004-15 bitweaver.org
 *
 * @package users
 * @subpackage functions
 */

/**
 * required setup
 */
require_once '../kernel/includes/setup_inc.php';

// User preferences screen
$gBitSystem->verifyFeature( 'users_preferences' );

$gBitUser->verifyRegistered();

$feedback = [];

// set up the user we're editing
if( !empty( $_REQUEST["view_user"] ) && $_REQUEST["view_user"] <> $gBitUser->mUserId ) {
	$gBitSystem->verifyPermission( 'p_users_admin' );
	$userClass = '\Bitweaver\Users\\'.$gBitSystem->getConfig( 'user_class', (defined('ROLE_MODEL') ) ?  'RolePermUser' : 'BitPermUser' );
	$editUser = new $userClass( $_REQUEST["view_user"] );
	$editUser->load( true );
	$gBitSmarty->assign('view_user', $_REQUEST["view_user"]);
	$watches = $editUser->getWatches();
	$gBitSmarty->assign('watches', $watches );
} else {
	$gBitUser->load( true );
	$editUser = &$gBitUser;
}

global $gQueryUserId;
$gQueryUserId = &$editUser->mUserId;

$parsedUrl = parse_url( $_SERVER["REQUEST_URI"] );

// settings only applicable when the wiki package is active
if( $gBitSystem->isPackageActive( 'wiki' )) {
	include_once WIKI_PKG_CLASS_PATH . 'BitPage.php';
	$parsedUrl1 = str_replace( USERS_PKG_URL."user_preferences", WIKI_PKG_URL."edit", $parsedUrl["path"] );
	$parsedUrl2 = str_replace( USERS_PKG_URL."user_preferences", WIKI_PKG_URL."index", $parsedUrl["path"] );
	$gBitSmarty->assign( 'url_edit', KernelTools::httpPrefix(). $parsedUrl1 );
	$gBitSmarty->assign( 'url_visit', KernelTools::httpPrefix(). $parsedUrl2 );
}

// custom user fields
if( $gBitSystem->isFeatureActive( 'custom_user_fields' )) {
	$customFields= explode( ',', $gBitSystem->getConfig( 'custom_user_fields' )  );
	$gBitSmarty->assign('customFields', $customFields );
}

// include preferences settings from other packages - these will be included as individual tabs
$includeFiles = $gBitSystem->getIncludeFiles( 'user_preferences_inc.php', 'user_preferences_inc.tpl' );
foreach( $includeFiles as $file ) {
	if( !empty( $file['php'] ) && is_file( $file['php'] ) ) {
		require_once $file['php'];
	}
}
$gBitSmarty->assign( 'includFiles', $includeFiles );

// fetch available languages
$gBitLanguage->mLanguage = $editUser->getPreference( 'bitlanguage', $gBitLanguage->mLanguage );
$gBitSmarty->assign( 'gBitLanguage', $gBitLanguage );

// allow users to set their preferred site style - this option is only available when users can set the site-wide theme
if( $gBitSystem->getConfig( 'users_themes' ) == 'y' ) {
	if( !empty( $_REQUEST['prefs'] )) {
		if( !empty( $_REQUEST['style'] ) && $_REQUEST['style'] != $gBitSystem->getConfig( 'style' ) ) {
			$editUser->storePreference( 'theme', $_REQUEST["style"] );
		} else {
			$editUser->storePreference( 'theme', null );
		}
		$assignStyle = $_REQUEST["style"];
	}
	$styles = $gBitThemes->getStyles( null, true, true );
	$gBitSmarty->assign( 'styles', $styles );

	if( !isset( $_REQUEST["style"] )) {
		$assignStyle = $editUser->getPreference( 'theme' );
	}
	$gBitSmarty->assign( 'assignStyle', $assignStyle );
}

// process the preferences form
if( isset( $_REQUEST["prefs"] )) {
	if ( !$editUser->store( $_REQUEST ) ) {
		$feedback['error'] = $editUser->mErrors;
	} else {
		// preferences
		$prefs = [
			'users_homepage'        => null,
			'site_display_utc'      => 'Local',
			'site_display_timezone' => 'UTC',
			'users_country'         => null,
			'users_information'     => 'public',
			'users_email_display'   => 'n',
		];

		if( $_REQUEST['site_display_utc'] != 'Fixed' ) {
			unset( $_REQUEST['site_display_timezone'] );
			$editUser->storePreference( 'site_display_timezone', null );
		} else {
			$editUser->storePreference( 'site_display_timezone', $_REQUEST['site_display_timezone'] );
		}

		// we don't have to store http:// in the db
		if( empty( $_REQUEST['users_homepage'] ) || $_REQUEST['users_homepage'] == 'http://' ) {
			unset( $_REQUEST['users_homepage'] );
		} elseif( !preg_match( '/^http:\/\//', $_REQUEST['users_homepage'] )) {
			$_REQUEST['users_homepage'] = 'http://'.$_REQUEST['users_homepage'];
		}

		foreach( $prefs as $pref => $default ) {
			if( !empty( $_REQUEST[$pref] ) && $_REQUEST[$pref] != $default ) {
				$editUser->storePreference( $pref, $_REQUEST[$pref] );
			} else {
				$editUser->storePreference( $pref, null );
			}
		}

		if( $gBitSystem->isFeatureActive( 'users_change_language' )) {
			$editUser->storePreference( 'bitlanguage', ( $_REQUEST['bitlanguage'] != $gBitLanguage->mLanguage ) ? $_REQUEST['bitlanguage'] : null );
		}

		/*/ toggles
		$toggles = []
		);

		foreach( $toggles as $toggle => $package ) {
			if( isset( $_REQUEST[$toggle] )) {
				$editUser->storePreference( $toggle, 'y', $package );
			} else {
				$editUser->storePreference( $toggle, null, $package );
			}
		}
		*/

		// process custom fields
		if( isset( $customFields ) && is_array( $customFields )) {
			foreach( $customFields as $f ) {
				if( isset( $_REQUEST['CUSTOM'][$f] )) {
					$editUser->storePreference( trim( $f ), trim( $_REQUEST['CUSTOM'][$f] ) );
				}
			}
		}

		// we need to reload the page for all the included user preferences
		if( isset( $_REQUEST['view_user'] )) {
			KernelTools::bit_redirect ( USERS_PKG_URL."preferences.php?view_user=$editUser->mUserId" );
		} else {
			KernelTools::bit_redirect ( USERS_PKG_URL."preferences.php" );
		}
	}
}

// change email address
if( isset( $_REQUEST['chgemail'] )) {
	// check user's password
	if( !$gBitUser->hasPermission( 'p_users_admin' ) && !$editUser->validate( $editUser->mUsername, $_REQUEST['pass'], '', '' )) {
		$gBitSystem->fatalError( KernelTools::tra("Invalid password.  Your current password is required to change your email address." ));
	}

	$org_email = $editUser->getField( 'email' );
	if( $editUser->changeUserEmail( $editUser->mUserId, $_REQUEST['email'] )) {
		$feedback['success'] = KernelTools::tra( 'Your email address was updated successfully' );

		/* this file really needs a once over
			we need to call services when various preferences are stored
			for now my need is when the email address is changed. when the 
			need expands to more we can look at cleaning up this file
			into something more sane. happy to help out at that time -wjames5
		 */
		$paramHash = $_REQUEST;
		$paramHash['org_email'] = $org_email;
		$editUser->invokeServices( 'content_store_function', $_REQUEST );
	} else {
		$feedback['error'] = $editUser->mErrors;
	}
}

// change user password
if( isset( $_REQUEST["chgpswd"] )) {
	if( $_REQUEST["pass1"] != $_REQUEST["pass2"] ) {
		$gBitSystem->fatalError( KernelTools::tra("The passwords didn't match" ));
	}
	if( !$gBitUser->hasPermission( 'p_users_admin' ) && !$editUser->validate( $editUser->getField( 'email' ), $_REQUEST["old"], '', '' )) {
		$gBitSystem->fatalError( KernelTools::tra( "Invalid old password" ));
	}
	//Validate password here
	$users_min_pass_length = $gBitSystem->getConfig( 'users_min_pass_length', 4 );
	if( strlen( $_REQUEST["pass1"] ) < $users_min_pass_length ) {
		$gBitSystem->fatalError( KernelTools::tra( "Password should be at least" ).' '.$users_min_pass_length.' '.KernelTools::tra( "characters long" ));
	}
	// Check this code
	if( $gBitSystem->isFeatureActive( 'users_pass_chr_num' )) {
		if (!preg_match_all("/[0-9]+/", $_REQUEST["pass1"], $parsedUrl ) || !preg_match_all("/[A-Za-z]+/", $_REQUEST["pass1"], $parsedUrl )) {
			$gBitSystem->fatalError( KernelTools::tra( "Password must contain both letters and numbers" ));
		}
	}
	if( $editUser->storePassword( $_REQUEST["pass1"] )) {
		$feedback['success'] = KernelTools::tra( 'The password was updated successfully' );
	}
}


// this should go in tidbits
if( isset( $_REQUEST['tasksprefs'] )) {
	$editUser->storePreference( 'tasks_max_records', $_REQUEST['tasks_max_records'] );
	if( isset( $_REQUEST['tasks_use_dates'] ) && $_REQUEST['tasks_use_dates'] == 'on' ) {
		$editUser->storePreference( 'tasks_use_dates', 'y' );
	} else {
		$editUser->storePreference( 'tasks_use_dates', 'n' );
	}
}

// get available languages
$languages = [];
$languages = $gBitLanguage->listLanguages();
$gBitSmarty->assign( 'languages', $languages );

// Get flags
$flags = [];
$h = opendir( USERS_PKG_PATH.'icons/flags/' );
while( $file = readdir( $h )) {
	if( strstr( $file, ".gif" )) {
		$flags[] = preg_replace( "/\.gif/", "", $file );
	}
}
closedir( $h );
sort( $flags );
$gBitSmarty->assign( 'flags', $flags );

$editUser->mInfo['users_homepage'] = $editUser->getPreference( 'users_homepage', '' );

$gBitSmarty->assign( 'editUser', $editUser );
$gBitSmarty->assign( 'gContent', $editUser ); // also assign to gContent to make services happy
$gBitSmarty->assign( 'feedback', $feedback );

/* This should come from BitDate->get_timezone_list but that seems to rely on a global from PEAR that does not exist. */
if ( version_compare( phpversion(), "5.2.0", ">=" ) ) {
	$user_timezones = \DateTimeZone::listIdentifiers();
} else {
	for($i=-12;$i<=12;$i++) {
		$user_timezones[$i * 60 * 60] = $i; // Stored offset needs to be in seconds.
	}
}
$gBitSmarty->assign( 'userTimezones', $user_timezones);

// email scrambling methods
$scramblingMethods = [ "n", "strtr", "unicode", "x" ];
$gBitSmarty->assign( 'scramblingMethods', $scramblingMethods );
$scramblingEmails = [
	KernelTools::tra( "no" ),
	scramble_email( $editUser->mInfo['email'], 'strtr' ),
	scramble_email( $editUser->mInfo['email'], 'unicode' ) . "-" . KernelTools::tra( "unicode" ),
	scramble_email( $editUser->mInfo['email'], 'x' ),
];
$gBitSmarty->assign( 'scramblingEmails', $scramblingEmails );

// edit services
$editUser->invokeServices( 'content_edit_function' );
$gBitSystem->display( 'bitpackage:users/user_preferences.tpl', 'Edit User Preferences' , [ 'display_mode' => 'display' ]);

