<?php
/**
 * @version $Header$
 * @package users
 * @subpackage functions
 *
 * Copyright (c) 2004 bitweaver.org
 * Copyright (c) 2003 tikwiki.org
 * Copyright (c) 2002-2003, Luis Argerich, Garland Foster, Eduardo Polidor, et. al.
 * All Rights Reserved. See below for details and a complete list of authors.
 * Licensed under the GNU LESSER GENERAL PUBLIC LICENSE. See http://www.gnu.org/copyleft/lesser.html for details
 *
 * $Id$
 */

/**
 * Initialization
 */
$check_req = (isset($_REQUEST["mc_unassign"])
           || isset($_REQUEST["mc_up"])
           || isset($_REQUEST["mc_down"])
           || isset($_REQUEST["mc_move"]));
if (!$gBitUser->hasPermission( 'p_tidbits_configure_modules' ) && $check_req) {
	$gBitSmarty->assign('msg', tra("You dont have permission to use this feature"));
	$gBitSystem->display( 'error.tpl' , NULL, array( 'display_mode' => 'display' ));
	die;
}
if ($site_user_assigned_modules != 'y' && $check_req) {
	$gBitSmarty->assign('msg', tra("This feature is disabled").": site_user_assigned_modules");
	$gBitSystem->display( 'error.tpl' , NULL, array( 'display_mode' => 'display' ));
	die;
}
if ( !$gBitUser->isRegistered() && $check_req) {
	$gBitSmarty->assign('msg', tra("You must log in to use this feature"));
	$gBitSystem->display( 'error.tpl' , NULL, array( 'display_mode' => 'display' ));
	die;
}
$url = $_SERVER["REQUEST_URI"];
if ($check_req) {
//    global $debugger;
//    $debugger->msg('Module control clicked: '.$check_req);
    // Make defaults if user still ot configure modules for himself
    if (!$usermoduleslib->user_has_assigned_modules($user))
        $usermoduleslib->create_user_assigned_modules($user);
    // Handle control icon click
	if (isset($_REQUEST["mc_up"]))
		$usermoduleslib->swap_up_user_module($_REQUEST["mc_up"], $user);
	elseif (isset($_REQUEST["mc_down"]))
		$usermoduleslib->swap_down_user_module($_REQUEST["mc_down"], $user);
	elseif (isset($_REQUEST["mc_move"]))
		$usermoduleslib->move_module($_REQUEST["mc_move"], $user);
	else
		$usermoduleslib->unassign_user_module($_REQUEST["mc_unassign"], $user);
    // Remove module movemet paramaters from an URL
    // \todo What if 'mc_xxx' arg was not at the end? (if smbd fix URL by hands...)
    //       should I handle this very special (hack?) case?
    $url = preg_replace('/(.*)(\?|&){1}(mc_up|mc_down|mc_move|mc_unassign)=[^&]*/','\1', $url);
}
// Fix locaton if parameter was removed...
if ($url != $_SERVER["REQUEST_URI"]) header('location: '.$url);
$gBitSmarty->assign('current_location', $url);
$gBitSmarty->assign('mpchar', (strpos($url, '?') ? '&' : '?'));
?>
