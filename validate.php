<?php
/**
 * validate user login
 *
 * @copyright (c) 2004-17 bitweaver.org
 *
 * @package users
 * @subpackage functions
 */


namespace Bitweaver;
use Bitweaver\KernelTools;
use Bitweaver\Users\BitHybridAuthManager;
use Bitweaver\Users\RolePermUser;
use Bitweaver\Users\UserRepository;

/**
 * this is a dirty hack to allow admins to log in when we require a visit to the installer
 * used in kernel/setup_inc.php - xing - Friday Oct 03, 2008   16:44:48 CEST
 */
define( 'LOGIN_VALIDATE', true );

/**
 * required setup
 */
require_once '../kernel/includes/setup_inc.php';

global $gBitSystem;

$redirectUrl = false;

//Remember where user is logging in from and send them back later; using session variable for those of us who use WebISO services
//do not use session loginfrom with signin.php or register.php - only "inline" login forms display in perm denied fatals, etc.
if( isset( $_SERVER['HTTP_REFERER'] ) && strpos( $_SERVER['HTTP_REFERER'], USERS_PKG_DIR.'/login' ) === false && strpos( $_SERVER['HTTP_REFERER'], USERS_PKG_DIR.'/register' ) === false && strpos( $_SERVER['HTTP_REFERER'], USERS_PKG_DIR.'/validate' ) === false ) {
	$from = parse_url( $_SERVER['HTTP_REFERER'] );
	if( $_SERVER['HTTP_HOST'] == $from['host'] ) {
		// We have a referer  from this site, but not an authentication URL
		$_SESSION['loginfrom'] = (!empty($from['path']) ? $from['path'] : '').( !empty( $from['query'] ) ? '?'.$from['query'] : '' );
	}
} else {
	$_SESSION['loginfrom'] = null;
	$_SESSION['returnto'] = null;
}

if( !empty( $_REQUEST['provider'] ) ) {
	BitHybridAuthManager::loadSingleton();
	global $gBitHybridAuthManager;

	if( !empty( $_REQUEST['disconnect'] ) ) {
		if( $gBitUser->isRegistered() ) {
			$gBitHybridAuthManager->expungeUserProfile( $gBitUser->mUserId, $_REQUEST['provider'] );
		}
		\Bitweaver\bit_redirect( $_SESSION['loginfrom'] );
	} else {
		try {
			$auth = $gBitHybridAuthManager->authenticate( $_REQUEST['provider'], $gBitUser );
			if( $auth === false ) {
				// social auth failed
				throw new \Exception( 'social auth failed' );
			} elseif( $auth === true ) {
				// account was connected to current object
				throw new \Exception( 'account was connected to current object' );
			} elseif( BitBase::verifyId( $auth ) ) {
				$redirectUrl = $gBitUser->getPostLoginUrl();
			} elseif( is_object( $auth ) && is_a( $auth, 'Hybrid_User_Profile' ) ) {
				$_SESSION['returnto'] = null;
				// an unconnected authProfile was found
				$gBitSmarty->assign( 'authProfile', $auth );
				$tpl = 'bitpackage:users/validate_auth.tpl';
				if( !empty( $_REQUEST['auth_login'] ) ) {
					$user = $_REQUEST['user'] ?? false;
					$pass = $_REQUEST['pass'] ?? false;
					$challenge = $_REQUEST['challenge'] ?? false;
					$response = $_REQUEST['response'] ?? false;

					// if $referer is set, login() will return the user to whence he came
					$gBitUser->login( $user, $pass, $challenge, $response );
					if( $gBitUser->isRegistered() ) {
						$gBitHybridAuthManager->storeUserProfile( $gBitUser->mUserId, $_REQUEST['provider'], $auth->identifier, $auth );
						$redirectUrl = $gBitUser->getPostLoginUrl();
						$tpl = null;
					} else {
						$redirectUrl = null;
					}
				} else {
					if( $gBitUser->isRegistered() ) {
						$redirectUrl = $gBitUser->getPostLoginUrl();
						$tpl = null;
					} elseif( !empty( $_REQUEST['auth_new'] ) && !$gBitUser->isRegistered() ) {
						$pRegisterHash = $_REQUEST;
						$pRegisterHash['novalidation'] = true;
						foreach( array( 'displayName' => 'real_name', 'email'=>'email', 'emailVerified'=>'verified_email', 'gender'=>'customers_gender', 'firstName'=>'customers_firstname', 'lastName'=>'customers_lastname', 'phone'=>'customers_telephone' ) as $member=>$key ) {
							if( $auth->$member ) {
								$pRegisterHash[$key] = $auth->$member;
							}
						}
						if( $auth->birthMonth && $auth->birthDay ) {
							$pRegisterHash['customers_dob'] = ($auth->birthYear ? $auth->birthYear : 1900).'-'.$auth->birthMonth.'-'.$auth->birthDay;
						}
						$prefId = $gBitHybridAuthManager->getConfigName( $_REQUEST['provider'], 'id' );
                        $_SESSION['returnto'] = $_SERVER['SCRIPT_URI'].'?provider='.$_REQUEST['provider'].'&auth_login=1';
						include USERS_PKG_INCLUDE_PATH.'register_inc.php';
					}
				}
			}
		} catch( \Exception $e ) {
			// Display the recived error,
			// to know more please refer to Exceptions handling section on the userguide
			switch( $e->getCode() ){
				case 0 : $authError = 'Unspecified error.';
					break;
				case 1 : $authError = 'Hybriauth configuration error.';
					break;
				case 2 : $authError = 'Provider not properly configured.';
					break;
				case 3 : $authError = 'Unknown or disabled provider.';
					break;
				case 4 : $authError = 'Missing provider application credentials.';
					break;
				case 5 : $authError = 'Authentification failed. The user has canceled the authentication or the provider refused the connection.';
					break;
				case 6 : $authError = 'User profile request failed. Most likely the user is not connected to the provider and he should authenticate again.';
					break;
				case 7 : $authError = 'User not connected to the provider.';
					break;
				case 8 : $authError = 'Provider does not support this feature.';
					break;
				default: $authError = $e->getMessage();
					break;
			}
	 
			$gBitSmarty->assign( 'authError', $authError );
			$gBitSmarty->assign( 'authExpection', $e );
			bit_error_log( $authError );
			$tpl = 'bitpackage:users/validate_auth.tpl';
		}
	}
} else {

	$user = $_REQUEST['user'] ?? false;
	$pass = $_REQUEST['pass'] ?? false;
	$challenge = $_REQUEST['challenge'] ?? false;
	$response = $_REQUEST['response'] ?? false;

	// if $referer is set, login() will return the user to whence he came
	$redirectUrl = $gBitUser->login( $user, $pass, $challenge, $response );
}

if( !empty( $tpl ) ) {
	$gBitSystem->display( $tpl );
} elseif(( strpos( $redirectUrl, 'signin.php?' ) || strpos( $redirectUrl, 'remind_password.php' )) && strpos( $redirectUrl, 'signin.php?error=' ) == -1 ) {
// but if we came from a login page, let's go home (except if we got an error when login in)
	$redirectUrl = $gBitUser->getPostLoginUrl();
} else {
}

if( !empty( $redirectUrl ) ) {
	KernelTools::bit_redirect( $redirectUrl );
}

