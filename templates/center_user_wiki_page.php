<?php

require_once( WIKI_PKG_PATH.'BitPage.php' );

global $wikilib, $user, $gQueryUser;

include_once( USERS_PKG_PATH.'lookup_user_inc.php' );

$data = $gQueryUser->parseData();
$gBitSmarty->assign_by_ref( 'parsed', $data );

?>
