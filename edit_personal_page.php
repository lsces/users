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

$gBitUser->verifyRegistered();

// Check if the page has changed
if (isset($_REQUEST["fSavePage"])) {
	$gBitUser->store( $_REQUEST );
	header( "Location:".USERS_PKG_URL."index.php?home=".$gBitUser->mUsername );
	die;
}elseif( isset($_REQUEST["fCancel"]) ){
	header( "Location:".USERS_PKG_URL."index.php?home=".$gBitUser->mUsername );
	die;
}

// see if we should show the attachments tab at all
foreach( $gLibertySystem->mPlugins as $plugin ) {
	if( ( $plugin['plugin_type'] == 'storage' ) && ( $plugin['is_active'] == 'y' ) ) {
		$gBitSmarty->assign( 'show_attachments','y' );
	}
}

$gBitSmarty->assign('preview',0);
// If we are in preview mode then preview it!
if(isset($_REQUEST["preview"])) {
	$gBitSmarty->assign('preview',1);
	$gBitUser->mInfo['title'] = $_REQUEST["title"];
	if(isset($_REQUEST["description"])) {
		$gBitUser->mInfo['description'] = $_REQUEST["description"];
	}
	$gBitUser->mInfo['data'] = $_REQUEST["edit"];

	$parsed = $gBitUser->parseData($_REQUEST["edit"], (!empty( $_REQUEST['format_guid'] ) ? $_REQUEST['format_guid'] :
		( isset($gBitUser->mInfo['format_guid']) ? $gBitUser->mInfo['format_guid'] : 'tikiwiki' ) ) );
	$gBitUser->mInfo['parsed_data'] = $parsed;
	/* SPELLCHECKING INITIAL ATTEMPT */
	//This nice function does all the job!
	$gBitSmarty->assign_by_ref( 'pageInfo', $gBitUser->mInfo );
	$gBitUser->invokeServices( 'content_preview_function' );
}
else {
	$gBitUser->invokeServices( 'content_edit_function' );
}

$gBitSmarty->assign_by_ref( 'pageInfo', $gBitUser->mInfo );
$gBitSmarty->assign_by_ref( 'gContent', $gBitUser );

$gBitSmarty->assign( 'show_page_bar', 'y' );
$gBitSystem->setConfig( 'wiki_description', 'n' );

$gBitSystem->display( 'bitpackage:users/edit_personal_page.tpl', NULL, array( 'display_mode' => 'edit' ) );
?>
