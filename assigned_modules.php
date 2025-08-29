<?php
/**
 * assigned_modules
 *
 * @copyright (c) 2004-15 bitweaver.org
 *
 * @package users
 * @subpackage functions
 */

global $gEditMode;
$gEditMode = 'layout';

/**
 * required setup
 */
require_once '../kernel/includes/setup_inc.php';
use Bitweaver\KernelTools;

$gBitSystem->fatalError( 'This page is not functional and will be fixed asap.' );

$gBitSystem->verifyPermission('p_tidbits_configure_modules');

if( !$gBitUser->canCustomizeLayout() && !$gBitUser->canCustomizeTheme() ) {
	$gBitSmarty->assign('msg', KernelTools::tra("This feature is disabled").": user layout");
	$gBitSystem->display( 'error.tpl' , null, [ 'display_mode' => 'display' ] );
	die;
}

if (!$gBitUser->isRegistered()) {
	$gBitSmarty->assign('msg', KernelTools::tra("Permission denied: You are not logged in"));
	$gBitSystem->display( 'error.tpl' , null, [ 'display_mode' => 'display' ] );
	die;
}

include_once USERS_PKG_INCLUDE_PATH.'lookup_user_inc.php';

if ($gQueryUser->mUserId != $gBitUser->mUserId && !$gBitUser->object_has_permission($gBitUser->mUserId, $gQueryUser->mInfo['content_id'], 'bituser', 'p_users_admin')) {
	$gBitSmarty->assign('msg', KernelTools::tra('You do not have permission to edit this user\'s theme'));
	$gBitSystem->display('error.tpl', null, [ 'display_mode' => 'display' ] );
	die;
}

$_REQUEST['fLayout'] = HOMEPAGE_LAYOUT; //we hardcode to a single layout for all users.... for now >:-)
if (isset($_REQUEST['fSubmitSetTheme'] ) ) {
	if( $gBitUser->canCustomizeTheme() ) {
		$gQueryUser->storePreference( 'theme', !empty( $_REQUEST["style"] ) ? $_REQUEST["style"] : null );
		$assignStyle = $_REQUEST["style"];
	}
} elseif (isset($_REQUEST['fSubmitSetHeading'] ) ) {

	$homeHeader = substr( trim( $_REQUEST['homeHeaderData']), 0, 250 );
	$gQueryUser->storePreference( 'homepage_header', $homeHeader );
} elseif( isset( $_REQUEST["fSubmitAssign"] ) ) {

	$fAssign = &$_REQUEST['fAssign'];
	$fAssign['user_id'] = $gQueryUser->mUserId;
	$fAssign['layout'] = $_REQUEST['fLayout'];
	$gBitThemes->storeLayout( $fAssign );
	$gBitSmarty->assign( 'fAssign', $fAssign );
} elseif (isset($_REQUEST["fMove"])) {

	if( isset( $_REQUEST["fMove"] ) && isset( $_REQUEST["fModule"] ) ) {
		switch( $_REQUEST["fMove"] ) {
			case "unassign":
				$gBitThemes->unassignModule( $_REQUEST['fModule'], $gQueryUser->mUserId, $_REQUEST['fLayout'] );
				break;
			case "up":
				$gBitThemes->moduleUp( $_REQUEST['fModule'], $gQueryUser->mUserId, $_REQUEST['fLayout'] );
				break;
			case "down":
				$gBitThemes->moduleDown( $_REQUEST['fModule'], $gQueryUser->mUserId, $_REQUEST['fLayout'] );
				break;
			case "left":
				$gBitThemes->modulePosition( $_REQUEST['fModule'], $gQueryUser->mUserId, $_REQUEST['fLayout'], 'l' );
				break;
			case "right":
				$gBitThemes->modulePosition( $_REQUEST['fModule'], $gQueryUser->mUserId, $_REQUEST['fLayout'], 'r' );
				break;
		}
	}
}
$orders = [];
for ($i = 1; $i < 20; $i++) {
	$orders[] = $i;
}
$gBitSmarty->assign('orders', $orders);
$gBitSmarty->assign( 'homeHeaderData', $gQueryUser->getPreference( 'homepage_header' ) );
// get styles
if( $gBitUser->canCustomizeTheme() ) {
	$styles = $gBitThemes->getStyles( null, true, true );
	$gBitSmarty->assign( 'styles', $styles );
	if(!isset($_REQUEST["style"])){
		$assignStyle = $gQueryUser->getPreference( 'theme' );
	}
	$gBitSmarty->assign( 'assignStyle', $assignStyle );
}
$assignables = $gBitThemes->getAssignableModules();
if (count($assignables) > 0) {
	$gBitSmarty->assign('canassign', 'y');
} else {
	$gBitSmarty->assign('canassign', 'n');
}
$modules = $gBitSystem->getLayout( $gQueryUser->mUserId, HOMEPAGE_LAYOUT, false );
$gBitThemes->generateModuleNames( $modules );
//print_r($modules);
$gBitSmarty->assign('assignables', $assignables);
$layoutAreas = [ 'left'=>'l', 'center'=>'c', 'right'=>'r' ];
$gBitSmarty->assign( 'layoutAreas', $layoutAreas );
$gBitSmarty->assign('modules', $modules);
//print_r($modules);

$gBitSystem->display( 'bitpackage:users/user_assigned_modules.tpl', 'Edit Layout', [ 'display_mode' => 'display' ] );
