<?php
/**
 * @version $Header$
 */
global $gBitInstaller;

$infoHash = array(
	'package'      => USERS_PKG_NAME,
	'version'      => str_replace( '.php', '', basename( __FILE__ )),
	'description'  => "Redefine user groups to user roles to tidy up conflict with other uses of group.",
	'post_upgrade' => NULL,
);

$gBitInstaller->registerPackageUpgrade( $infoHash, array(

array( 'QUERY' =>
	array( 'SQL92' => array(
		"UPDATE `".BIT_DB_PREFIX."users_permissions` SET `perm_name`='p_users_create_personal_roles' WHERE `perm_name`='p_users_create_personal_groups'",
		"UPDATE `".BIT_DB_PREFIX."users_role_permissions` SET `perm_name`='p_users_create_personal_roles' WHERE `perm_name`='p_users_create_personal_groups'",
		"UPDATE `".BIT_DB_PREFIX."users_permissions` SET `perm_name`='p_users_assign_role_members' WHERE `perm_name`='p_users_assign_group_members'",
		"UPDATE `".BIT_DB_PREFIX."users_role_permissions` SET `perm_name`='p_users_assign_role_members' WHERE `perm_name`='p_users_assign_group_members'",
		"UPDATE `".BIT_DB_PREFIX."users_permissions` SET `perm_name`='p_users_assign_role_perms' WHERE `perm_name`='p_users_assign_group_perms'",
		"UPDATE `".BIT_DB_PREFIX."users_role_permissions` SET `perm_name`='p_users_assign_role_perms' WHERE `perm_name`='p_users_assign_group_perms'",
		"UPDATE `".BIT_DB_PREFIX."users_permissions` SET `perm_name`='p_users_role_subroles' WHERE `perm_name`='p_users_group_subgroups'",
		"UPDATE `".BIT_DB_PREFIX."users_role_permissions` SET `perm_name`='p_users_role_subroles' WHERE `perm_name`='p_users_group_subgroups'",
)),

array( 'PHP' => '
	// make sure plugins are up to date.
	global $gBitDb;
	$gBitDb->query( "UPDATE `".BIT_DB_PREFIX."users_users` SET `pass_due`=NULL" );
'
)

));
?>
