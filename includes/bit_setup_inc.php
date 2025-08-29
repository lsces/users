<?php
/**
 * @version $Header$
 * @package users
 */
use Bitweaver\Users\RolePermUser;
use Bitweaver\KernelTools;

global $gBitDbType, $gBitDbHost, $gBitDbUser, $gBitDbPassword, $gBitDbName, $gBitThemes;

$pRegisterHash = [
	'package_name' => 'users',
	'package_path' => dirname( dirname( __FILE__ ) ).'/',
	'activatable' => false,
	'required_package'=> true,
];

// fix to quieten down VS Code which can't see the dynamic creation of these ...
define( 'USERS_PKG_NAME', $pRegisterHash['package_name'] );
define( 'USERS_PKG_URL', BIT_ROOT_URL . basename( $pRegisterHash['package_path'] ) . '/' );
define( 'USERS_PKG_URI', BIT_ROOT_URL . basename( $pRegisterHash['package_path'] ) . '/' );

$gBitSystem->registerPackage( $pRegisterHash );

/* ---- services ----- */
define( 'CONTENT_SERVICE_USERS_FAVS', 'users_favorites' );
$gLibertySystem->registerService( CONTENT_SERVICE_USERS_FAVS,
	USERS_PKG_NAME,
	[
		'content_icon_tpl' => 'bitpackage:users/user_favs_service_icon_inc.tpl',
		'content_list_sql_function' => 'users_favs_content_list_sql',
		'content_user_collection_function' => 'users_collection_sql',
	],
	[
		'description' => KernelTools::tra( 'Provides a ajax service enabling users to bookmark any content as a favorite.' ),
	]
);

$gBitSystem->registerNotifyEvent( [ "user_registers" => KernelTools::tra( "A user registers" ) ] );

if( !defined( 'AVATAR_MAX_DIM' )) {
	define( 'AVATAR_MAX_DIM', 100 );
}
if( !defined( 'PORTRAIT_MAX_DIM' )) {
	define( 'PORTRAIT_MAX_DIM', 300 );
}
if( !defined( 'LOGO_MAX_DIM' )) {
	define( 'LOGO_MAX_DIM', 600 );
}

// a package can decide to override the default user class
$userClass = $gBitSystem->getConfig( 'user_class', (defined('ROLE_MODEL') ) ?  '\Bitweaver\Users\RolePermUser' : '\Bitweaver\Users\BitPermUser' );

// set session lifetime
if( $gBitSystem->isFeatureActive( 'site_session_lifetime' )) {
	ini_set( 'session.gc_maxlifetime', $gBitSystem->isFeatureActive( 'site_session_lifetime' ));
}

// is session data stored in DB or in filesystem?
if( $gBitSystem->isFeatureActive( 'site_store_session_db' ) && !empty( $gBitDbType )) {
	if( file_exists( EXTERNAL_LIBS_PATH.'adodb/session/adodb-session.php' )) {
		include_once EXTERNAL_LIBS_PATH . 'adodb/session/adodb-session.php';
	}

/*	if ( class_exists( 'ADODB_Session' ) ) {
		ADODB_Session::dataFieldName( 'session_data' );
		ADODB_Session::driver( $gBitDbType );
		ADODB_Session::host( $gBitDbHost );
		ADODB_Session::user( $gBitDbUser );
		ADODB_Session::password( $gBitDbPassword );
		ADODB_Session::database( $gBitDbName );
		ADODB_Session::table( BIT_DB_PREFIX.'sessions' );
		ini_set( 'session.save_handler', 'user' );
	}
*/
}

session_name( BIT_SESSION_NAME );
if( $gBitSystem->isFeatureActive( 'users_remember_me' )) {
	session_set_cookie_params( $gBitSystem->getConfig( 'site_session_lifetime', 0 ), $gBitSystem->getConfig( 'cookie_path', BIT_ROOT_URL ), $gBitSystem->getConfig( 'cookie_domain', '' ));
} else {
	session_set_cookie_params( $gBitSystem->getConfig( 'site_session_lifetime', 0 ), BIT_ROOT_URL, '' );
}

// just use a simple COOKIE (unique random string) that is linked to the users_cnxn table.
// This way, nuking rows in the users_cnxn table can log people out and is much more reliable than SESSIONS
global $gShellScript;
if( empty( $gShellScript ) ) {
	if (session_status() == PHP_SESSION_NONE) {
		session_start();
		if (empty($_SESSION['csp_nonce'])) {
			$_SESSION['csp_nonce'] = bin2hex(random_bytes(16));
		}
		$cspNonce = $_SESSION['csp_nonce'];
	}
}

// Init USER AGENT if empty so reliant methods don't need gobs of empty checking
if( !isset( $_SERVER['HTTP_USER_AGENT'] )) {
	$_SERVER['HTTP_USER_AGENT'] = "";
}

// load the user
global $gOverrideLoginFunction;
$siteCookie = RolePermUser::getSiteCookieName(); // $userClass::getSiteCookieName();

if( !empty( $gOverrideLoginFunction )) {
	$gBitUser = new RolePermUser(); // $userClass();
	$gBitUser->mUserId = $gOverrideLoginFunction();
	if( $gBitUser->mUserId ) {
		$gBitUser->load();
		$gBitUser->loadPermissions();
	}
} elseif( !empty( $_COOKIE[$siteCookie] ) ) {
	if( $gBitUser = RolePermUser::loadFromCache( $_COOKIE[$siteCookie] ) ) {
//		var_dump( 'load from cache' ); die;
	} else {
		$gBitUser = new RolePermUser();
		if( $gBitUser->mUserId = $gBitUser->getUserIdFromCookieHash( $_COOKIE[$siteCookie] ) ) {
			// we have user with this cookie.
			if( $gBitUser->load( true ) ) {
				// maybe do something...
			}
		}
	}
}

// if we still don't have a user loaded, we'll load the anonymous user
if( empty( $gBitUser ) || !$gBitUser->isValid() ) {

	if( !($gBitUser = RolePermUser::loadFromCache( ANONYMOUS_USER_ID ) ) ) { // $userClass::loadFromCache( ANONYMOUS_USER_ID ) ) ) {
//		if( $gBitUser->load( true ) ) {
$gBitUser = new RolePermUser();
			// maybe do something...
//		}
	}
}

$gBitSmarty->assign( 'gBitUser', $gBitUser );
// Set the custom header with the nonce value
if ( !$gBitUser->isRegistered() ) {
	header("X-CSP-Nonce: $cspNonce");
	$cspDirectives = [
		"default-src 'self'",
		"script-src 'nonce-$cspNonce' 'sha256-S99CWnPGUJ/vgQ8bHZsDaLwIKm+1Hg9ub8jZLI6f1/Q=' 'sha256-0WXB7AMgcS+xLiiMpUHQ+DGvJWInYJxuWys653a29ZE=' 'sha256-fYs400oRz/dgBlT1c/azhsoAzEr0obW//5RKb2MJzuk=' 'sha256-KlIhJzKdUgEy3yPJtkvuP0s8o7CNc2dkogmuN6JDhbA=' 'sha256-hphOYdb9WX9dW4pYcQdXa8E450mGtzl7k4kSIg1GOIo=' 'sha256-aoMVRw2ucpPYBXLlubmE7JroRgIqnRaBsYqVEZDqCZU=' 'sha256-CbFXIncEh2zmvNahVKWLX5U8qZOCB+SLiq4tpvKPuo4=' 'strict-dynamic' 'unsafe-eval' 'unsafe-hashes'",
		"style-src 'nonce-$cspNonce' 'sha256-kFAIUwypIt04FgLyVU63Lcmp2AQimPh/TdYjy04Flxs=' 'sha256-0EZqoz+oBhx7gF4nvY2bSqoGyy4zLjNF+SDQXGp/ZrY=' 'sha256-ZVjd2zfSTfAVh1y7eCcNk0SPGUQOP/H8vzrFJIVgg90=' 'sha256-J190NMj1lQxByFdlcNKRhhCCXiUM1r+jkSLWV+llFq4=' 'sha256-BtFkuTJeZaKF8Yq+TxnX0ul9r9PfZjZSFjnGN6WPlKQ=' 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' 'sha256-CpBM5JSFkNGGsPTpBLlT8YZs6iLghHxhCZJdNMnfnh4=' 'sha256-4phJwN0tL/ygVcuaCAWhoustE+HJDZLW5UQI4eUFPp8=' 'sha256-t6oewASd7J1vBg5mQtX4hl8bg8FeegYFM3scKLIhYUc=' 'sha256-2aWu0TvBcgs1/KaHywJ+/We8HuVKvHa4bPG9n23fN/I=' 'sha256-VXDM/lJYdk4BpdCUg/naqDj8ti+GKs0SZ8AJLc3k698=' 'sha256-h7qfp6iahc2crFUNooykEE411IXaaXOFZ8OB4kpGOf0=' 'sha256-FePUZaUvmD7uZkSy3DB3sfgvxqcggJmPmYjzgcM99kE=' 'sha256-eJOzNHAPfvDe5PZ6L0Av6TgmAexyPnw5S0hjhN45Pcw=' 'sha256-Jwm2I09DTLCg5XlmwQaT8zstSSvvnZ9n17x8kw/TBkE=' 'sha256-bGnJD/Fo4m+tE/x+1fgn17TdW+k1UQUdXnACfIm4TJc=' 'sha256-hphOYdb9WX9dW4pYcQdXa8E450mGtzl7k4kSIg1GOIo=' 'sha256-efTp7owq9MrTdSJFt54KABbw/1rE1C3dDKXRcKPlvd8=' 'sha256-BdubG9A59XWzmga/PvxzdL4u6NLBQrM5iY/uDn6bfNE=' 'sha256-ONZhBkNvCH59f9kAxZ+OSq/jBOXIwIUzl3AHlIugZME=' 'unsafe-hashes'  'self'",
		"img-src 'self' https://*.tile.openstreetmap.fr/osmfr/;",
		"font-src 'self'",
		"connect-src 'self'",
		"object-src 'none'",
		"base-uri 'none'",
		"form-action 'self'",
		"frame-ancestors 'none'",
	];
	$cspHeader = implode('; ', $cspDirectives);
	// Set the CSP header with a placeholder for the nonce
	header("Content-Security-Policy: $cspHeader");
}

$gBitSmarty->assign( 'gBitUser', $gBitUser );

// If we are processing a login then do not generate the challenge
// if we are in any other case then yes.
if( !empty( $_SERVER["REQUEST_URI"] ) && !strstr( $_SERVER["REQUEST_URI"], USERS_PKG_URL.'validate' )) {
	if( $gBitSystem->isFeatureActive( 'feature_challenge' )) {
		$_SESSION["challenge"] = $gBitUser->generateChallenge();
	}
}

if( $gBitSystem->isFeatureActive( 'users_domains' )) {
	$domain = substr( $_SERVER['HTTP_HOST'], 0, strpos( $_SERVER['HTTP_HOST'], '.' ));
	if( $domain && $domain != $gBitSystem->getConfig( 'users_default_domain', 'www' )) {
		if( $gBitSystem->mDomainInfo = $gBitUser->getUserDomain( $domain )) {
			if( empty( $_REQUEST['user_id'] )) {
				$_REQUEST['user_id'] = $gBitSystem->mDomainInfo['user_id'];
			} elseif( empty( $_REQUEST['home'] )) {
				$_REQUEST['home'] = $gBitSystem->mDomainInfo['login'];
			}

			if( !empty( $_REQUEST['lookup_user_id'] )) {
				$_REQUEST['lookup_user_id'] = $gBitSystem->mDomainInfo['user_id'];
			}
		}
	}
}

// users_themes='y' is for the entire site, 'h' is just for users homepage and is dealt with on users/index.php
if( !empty( $gBitSystem->mDomainInfo['style'] )) {
	$theme = $gBitSystem->mDomainInfo['style'];
} elseif( $gBitSystem->getConfig( 'users_themes' ) == 'y' ) {
	if( $gBitUser->isRegistered() && $gBitSystem->isFeatureActive( 'users_preferences' )) {
		if( $userStyle = $gBitUser->getPreference( 'theme' )) {
			$theme = $userStyle;
		}
	}
	if( isset( $_COOKIE['bw-theme'] )) {
		$theme = $_COOKIE['bw-theme'];
	}
}

if( !empty( $theme )) {
	$gBitThemes->setStyle( $theme );
}

// register 'my' menu
if( $gBitUser->isValid() && $gBitUser->isRegistered() ) {
	$menuHash = [
		'package_name'  => USERS_PKG_NAME,
		'index_url'     => ( $gBitSystem->isFeatureActive( 'users_preferences' ) ? $gBitSystem->getConfig( 'users_login_homepage', USERS_PKG_URL.'my.php' ) : '' ),
		'menu_title'    => 'My '.$gBitSystem->getConfig( 'site_menu_title', $gBitSystem->getConfig( 'site_title', 'Site' )),
		'menu_template' => 'bitpackage:users/menu_users.tpl',
	];
	$gBitSystem->registerAppMenu( $menuHash );
}

require_once USERS_PKG_CLASS_PATH.'BaseAuth.php';