<?php
// $Header: /cvsroot/bitweaver/_bit_users/admin/index.php,v 1.21 2007/11/13 19:01:46 joasch Exp $
// Copyright (c) 2002-2003, Luis Argerich, Garland Foster, Eduardo Polidor, et. al.
// All Rights Reserved. See copyright.txt for details and a complete list of authors.
// Licensed under the GNU LESSER GENERAL PUBLIC LICENSE. See license.txt for details.
// Initialization
require_once( '../../bit_setup_inc.php' );

function batchImportUsers() {
	global $gBitSmarty, $gBitUser, $gBitSystem;

	// get the delimiter if it's set - use comma if it not
	$delimiter = !empty( $_REQUEST['delimiter'] ) ? $_REQUEST['delimiter'] : ",";
	$fname = $_FILES['csvlist']['tmp_name'];
	$fhandle = fopen( $fname, "r" );

	//Get the field names
	$fields = fgetcsv( $fhandle, 1000, $delimiter );

	// is the file a valid CSV file?
	if( empty( $fields[0] ) ) {
		$gBitSystem->fatalError( tra( "The file is not a CSV file or has not a correct syntax" ));
	}

	//now load the users in a table
	while( !feof( $fhandle ) ) {
		if( $data = fgetcsv( $fhandle, 1000, $delimiter ) ) {
			for( $i = 0; $i < count( $fields ); $i++ ) {
				@$ar[$fields[$i]] = $data[$i];
			}
			$userRecords[] = $ar;
		}
	}
	fclose( $fhandle );

	// were there any users in the list?
	if( !is_array( $userRecords ) ) {
		$gBitSystem->fatalError( tra( "No records were found. Check the file please!" ));
	}
	// If we are going to email users, set static values only once
	if( empty( $_REQUEST['admin_noemail_user'] ) ) {
		$siteName = $gBitSystem->getConfig('site_title', $_SERVER['HTTP_HOST'] );
		$gBitSmarty->assign('siteName',$_SERVER["SERVER_NAME"]);
		$gBitSmarty->assign('mail_site',$_SERVER["SERVER_NAME"]);
	}
	// Process user array
	$added = 0;
	$i = 1;
	foreach( $userRecords as $userRecord ) {
		$newUser = new BitUser();
		//untested - spiderr
		if( $newUser->importUser( $userRecord ) ) {
			if( !empty( $userRecord['groups'] ) ) {
				// groups need to be separated by spaces since this is a csv file
				$groups = explode( " ", $userRecord['groups'] );
				foreach( $groups as $group ) {
					if( $groupId = $gBitUser->groupExists( $group, ROOT_USER_ID ) ) {
						$newUser->addUserToGroup( $newUser->mUserId, $groupId );
					}
				}
			}
			if( empty( $_REQUEST['admin_noemail_user'] ) ) {
				$gBitSmarty->assign('mail_user',$userRecord['login']);
				if( !empty( $_REQUEST['admin_verify_user'] ) && !empty($userRecord['user_store']['provpass']) ) {
					$apass = addslashes(substr(md5($gBitSystem->genPass()),0,25));
					$apass = $userRecord['user_store']['provpass'];
					$machine = httpPrefix().USERS_PKG_URL.'confirm.php';
					// Send the mail
					$gBitSmarty->assign('mail_machine',$machine);
					$gBitSmarty->assign('mailUserId',$newUser->mUserId);
					$gBitSmarty->assign('mailProvPass',$apass);
					$mail_data = $gBitSmarty->fetch('bitpackage:users/admin_validation_mail.tpl');
					mail($userRecord["email"], $siteName.' - '.tra('Your registration information'),$mail_data,"From: ".$gBitSystem->getConfig('site_sender_email')."\r\nContent-type: text/plain;charset=utf-8\r\n");
					$gBitSmarty->assign('showmsg','n');
					
					$newUser->mLogs['confirm'] = 'Validation email sent to ' . $userRecord['email'] . '.';
				} elseif( !empty( $userRecord['password'] ) ) {
					// Send the welcome mail
					$gBitSmarty->assign( 'mailPassword',$userRecord['password'] );
					$gBitSmarty->assign( 'mailEmail',$userRecord['email'] );
					$mail_data = $gBitSmarty->fetch('bitpackage:users/admin_welcome_mail.tpl');
					mail($userRecord["email"], tra( 'Welcome to' ).' '.$siteName,$mail_data,"From: ".$gBitSystem->getConfig('site_sender_email')."\r\nContent-type: text/plain;charset=utf-8\r\n");
					
					$newUser->mLogs['welcome'] = 'Welcome email sent to ' . $userRecord['email'] . '.';
				}
				$logHash['action_log']['title'] = $userRecord['login'];
				$newUser->storeActionLog( $logHash );
			}

			$added++;
		} else {
			$discarded[$i] = implode( ',', $newUser->mErrors );
		}
		unset( $newUser );
		$i++;
	}

	$gBitSmarty->assign( 'added', $added );
	if( @is_array( $discarded ) ) {
		$gBitSmarty->assign( 'discarded', count( $discarded ) );
		$gBitSmarty->assign_by_ref( 'discardlist', $discarded );
	}
}

$gBitSystem->verifyPermission( 'p_users_admin' );

$feedback = array();

// Process the form to add a user here
if (isset($_REQUEST["newuser"])) {
	$userClass = $gBitSystem->getConfig( 'user_class', 'BitPermUser' );
	$newUser = new $userClass();
	// Check if the user already exists
	if( $gBitUser->userExists( array( 'email' => $_REQUEST['email'] ))) {
		$feedback['error'] = 'The email address "'.$_REQUEST['email'].'" has already been registered.';
	} elseif( $newUser->store( $_REQUEST ) ) {
		$gBitSmarty->assign( 'addSuccess', "User Added Successfully" );
	} else {
		$gBitSmarty->assign_by_ref( 'newUser', $_REQUEST );
		$gBitSmarty->assign( 'errors', $newUser->mErrors );
	}
	// if no user data entered, check if it's a batch upload
} elseif( isset( $_REQUEST["batchimport"]) ) {
	if( $_FILES['csvlist']['size'] && is_uploaded_file($_FILES['csvlist']['tmp_name'] ) ) {
		batchImportUsers();
	}
} elseif( isset( $_REQUEST["assume_user"]) && $gBitUser->hasPermission( 'p_users_admin' ) ) {
	$assume_user = (is_numeric( $_REQUEST["assume_user"] )) ? array( 'user_id' => $_REQUEST["assume_user"] ) : array('login' => $_REQUEST["assume_user"]) ;
	$userInfo = $gBitUser->getUserInfo( $assume_user );
	if( isset( $_REQUEST["confirm"] ) ) {
		$gBitUser->verifyTicket();
		if( $gBitUser->assumeUser( $userInfo["user_id"] ) ) {
			header( 'Location: '.$gBitSystem->getDefaultPage() );
			die;
		}
	} else {
		$gBitSystem->setBrowserTitle( 'Assume User Identity' );
		$formHash['assume_user'] = $_REQUEST['assume_user'];
		$msgHash = array(
			'confirm_item' => tra( 'This will log you in as the user' )." <strong>$userInfo[real_name] ($userInfo[login])</strong>",
		);
		$gBitSystem->confirmDialog( $formHash,$msgHash );
	}
} elseif( !empty( $_REQUEST['find'] ) ) {
	$title = 'Find Users';
}

// Process actions here
// Remove user or remove user from group
if( isset( $_REQUEST["action"] ) ) {
	$formHash['action'] = $_REQUEST['action'];
	if( !empty( $_REQUEST['batch_user_ids'] ) && is_array( $_REQUEST['batch_user_ids'] ) ) {
		$gBitUser->verifyTicket();
		if( isset( $_REQUEST["confirm"] ) ) {
			$delUsers = $errDelUsers = "";
			$userClass = $gBitSystem->getConfig( 'user_class', 'BitPermUser' );
			foreach( $_REQUEST['batch_user_ids'] as $uid ) {
				$expungeUser = new $userClass( $uid );
				$userInfo = $gBitUser->getUserInfo( array( 'user_id' => $uid ) );
				if( $expungeUser->load() && $expungeUser->expunge() ) {
					$delUsers .= "<li>{$userInfo['real_name']} ({$userInfo['login']})</li>";
				} else {
					$errDelUsers .= "<li>{$userInfo['real_name']} ({$userInfo['login']})</li>";
				}
			}

			if( !empty( $delUsers ) ) {
				$feedback['success'][] = tra( 'Users deleted' ).": <ul>$delUsers</ul>";
			} elseif( !empty( $errDelUsers ) ) {
				$feedback['error'][] = tra( 'Users not deleted' ).": <ul>$errDelUsers</ul>";
			}
		} else {
			foreach( $_REQUEST['batch_user_ids'] as $uid ) {
				$userInfo = $gBitUser->getUserInfo( array( 'user_id' => $uid ) );
				$formHash['input'][] = '<input type="hidden" name="batch_user_ids[]" value="'.$uid.'"/>'."{$userInfo['real_name']} ({$userInfo['login']})";
			}
			$gBitSystem->setBrowserTitle( 'Delete users' );
			$msgHash = array(
				'confirm_item' => tra( 'Are you sure you want to remove these users?' ),
				'warning' => tra( 'This will permentally delete these users' ),
			);
			$gBitSystem->confirmDialog( $formHash, $msgHash );
		}
	} elseif( $_REQUEST["action"] == 'delete' ) {
		$gBitUser->verifyTicket();
		$formHash['user_id'] = $_REQUEST['user_id'];
		$userInfo = $gBitUser->getUserInfo( array( 'user_id' => $_REQUEST["user_id"] ) );
		if( !empty( $userInfo['user_id'] ) ) {
			if( isset( $_REQUEST["confirm"] ) ) {
				$userClass = $gBitSystem->getConfig( 'user_class', 'BitPermUser' );
				$expungeUser = new $userClass( $_REQUEST["user_id"] );
				if( $expungeUser->load() && $expungeUser->expunge() ) {
					$feedback['success'][] = tra( 'User deleted' )." <strong>{$userInfo['real_name']} ({$userInfo['login']})</strong>";
				}
			} else {
				$gBitSystem->setBrowserTitle( 'Delete user' );
				$msgHash = array(
					'confirm_item' => tra( 'Are you sure you want to remove the user?' ),
					'warning' => tra( 'This will permentally delete the user' )." <strong>$userInfo[real_name] ($userInfo[login])</strong>",
				);
				$gBitSystem->confirmDialog( $formHash,$msgHash );
			}
		} else {
			$feedback['error'][] = tra( 'User not found' );
		}
	}
	if ($_REQUEST["action"] == 'removegroup') {
		$gBitUser->removeUserFromGroup($_REQUEST["user"], $_REQUEST["group"]);
	}
}

// get default group and pass it to tpl
foreach( $gBitUser->getDefaultGroup() as $defaultGroupId => $defaultGroupName ) {
	$gBitSmarty->assign('defaultGroupId', $defaultGroupId );
	$gBitSmarty->assign('defaultGroupName', $defaultGroupName );
}

// override default max_records
$_REQUEST['max_records'] = !empty( $_REQUEST['max_records'] ) ? $_REQUEST['max_records'] : 20;
$gBitUser->getList( $_REQUEST );
$gBitSmarty->assign_by_ref('users', $_REQUEST["data"]);
$gBitSmarty->assign_by_ref('usercount', $_REQUEST["cant"]);
if (isset($_REQUEST["numrows"])) {
	$_REQUEST['listInfo']["numrows"] = $_REQUEST["numrows"];
} else {
	$_REQUEST['listInfo']["numrows"] = 10;
}
$_REQUEST['listInfo']["URL"] = USERS_PKG_URL."admin/index.php";
$gBitSmarty->assign_by_ref('listInfo', $_REQUEST['listInfo']);

$gBitUser->invokeServices( 'content_edit_function' );

// Get groups (list of groups)
$grouplist = $gBitUser->getGroups('', '', 'group_name_asc');
$gBitSmarty->assign( 'grouplist', $grouplist );
$gBitSmarty->assign( 'feedback', $feedback );

$gBitSmarty->assign( (!empty( $_REQUEST['tab'] ) ? $_REQUEST['tab'] : 'userlist').'TabSelect', 'tdefault' );

// Display the template
$gBitSystem->display( 'bitpackage:users/users_admin.tpl', (!empty( $title ) ? $title : 'Edit Users' ) );
?>
