<?php
/**
 * $Header$
 *
 * Lib for user administration, roles and permissions
 * This lib uses pear so the constructor requieres

 * Copyright (c) 2004 bitweaver.org
 * Copyright (c) 2003 tikwiki.org
 * Copyright (c) 2002-2003, Luis Argerich, Garland Foster, Eduardo Polidor, et. al.
 * All Rights Reserved. See below for details and a complete list of authors.
 * Licensed under the GNU LESSER GENERAL PUBLIC LICENSE. See http://www.gnu.org/copyleft/lesser.html for details
 *
 * $Id$
 * @package users
 */

/**
 * required setup
 */
namespace Bitweaver\Users;
use Bitweaver\BitBase;
use Bitweaver\KernelTools;
use Bitweaver\Liberty\LibertyContent;

/**
 * Class that holds all information for a given user
 *
 * @author   spider <spider@steelsun.com>
 * @version  $Revision$
 * @package  users
 * @subpackage  RolePermUser
 */
#[\AllowDynamicProperties]
class RolePermUser extends RoleUser {

	public $mPerms;
	public $mGroups;
	public $mPermsOverride;

	/**
	 * RolePermUser Initialise class
	 * 
	 * @param numeric $pUserId User ID of the user we wish to load
	 * @param numeric $pContentId Content ID of the user we wish to load
	 * @access public
	 * @return void
	 */
	function __construct( $pUserId=null, $pContentId=null ) {
		parent::__construct( $pUserId, $pContentId );

		// Permission setup
		$this->mAdminContentPerm = 'p_users_admin';
	}

	public function __sleep() {
		return array_merge( parent::__sleep(), [ 'mPerms' ] );
	}

	public function __wakeup() {
		parent::__wakeup();
		if( empty( $this->mPerms ) ) {
			$this->loadPermissions();
		}
	}

	/**
	 * assumeUser Assume the identity of anothre user - Only admins may do this
	 * 
	 * @param numeric $pUserId User ID of the user you want to hijack
	 * @access public
	 * @return bool true on success, false on failure - mErrors will contain reason for failure
	 */
	function assumeUser( $pUserId ) {
		global $gBitUser;
		$ret = false;

		// make double sure the current logged in user has permission, check for p_users_admin, not admin, as that is all you need for assuming another user.
		// this enables creating of a non technical site adminstrators role, eg customer support representatives.
		if( $gBitUser->hasPermission( 'p_users_admin' ) ) {
			$assumeUser = new RolePermUser( $pUserId );
			$assumeUser->loadPermissions();
			if( $assumeUser->isAdmin() ) {
				$this->mErrors['assume_user'] = KernelTools::tra( "User administrators cannot be assumed." );
			} else {
				$this->mDb->query( "UPDATE `".BIT_DB_PREFIX."users_cnxn` SET `user_id`=?, `assume_user_id`=? WHERE `cookie`=?", [ $pUserId, $gBitUser->mUserId, $_COOKIE[$this->getSiteCookieName()] ] );
				$ret = true;
			}
		}

		return $ret;
	}

	/**
	 * load
	 *
	 *		- bool $pFull Load all permissions
	 *		- string $pUserName User login name
	 * @return bool true on success, false on failure - mErrors will contain reason for failure
	 */
	public function load( ...$extraParams ): bool {
		if( RoleUser::load( ...$extraParams ) ) {
			if( !empty($extraParams[0]) && $extraParams[0] ) {
				unset( $this->mPerms );
				$this->loadRoles();
				$this->loadPermissions();
			}
		}
		return $this->mUserId != null;
	}

	/**
	 * sanitizeUserInfo Used to remove sensitive information from $this->mInfo when it is unneccessary (i.e. $gQueryUser)
	 * 
	 * @access public
	 * @return void
	 */
	function sanitizeUserInfo() {
		if( !empty( $this->mInfo )) {
			$unsanitary = [ 'provpass', 'hash', 'challenge', 'user_password' ];
			foreach( array_keys( $this->mInfo ) as $key ) {
				if( in_array( $key, $unsanitary )) {
					unset( $this->mInfo[$key] );
				}
			}
		}
	}

	/**
	 * store 
	 * 
	 * @param array $pParamHash 
	 * @return bool true on success, false on failure - mErrors will contain reason for failure
	 */
	public function store( array &$pParamHash): bool {
		global $gBitSystem;
		// keep track of newUser before calling base class
		$newUser = !$this->isRegistered();
		$this->StartTrans();
		if( RoleUser::store( $pParamHash ) && $newUser ) {
			$defaultRoles = $this->getDefaultRole();
			$this->addUserToRole( $this->mUserId, $defaultRoles );
			if( $gBitSystem->isFeatureActive( 'users_eponymous_roles' ) ) {
				// Create a role just for this user, for permissions assignment.
				$roleParams = [
					'user_id' => $this->mUserId,
					'name'    => $pParamHash['user_store']['login'],
					'desc'    => "Personal role for ".( !empty( $pParamHash['user_store']['real_name'] ) ? $pParamHash['user_store']['real_name'] : $pParamHash['user_store']['login'] )
				];
				if( $this->storeRole( $roleParams ) ) {
					$this->addUserToRole( $this->mUserId, $roleParams['role_id'] );
				}
			}
			$this->load( true );

			// store any uploaded images, this can stuff mErrors, so we want to do this as the very last thing.
			$pParamHash['upload']['thumbnail'] = false;   // i don't think this does anything - perhaps replace it by setting thumbnail_sizes
			$this->storeImages( $pParamHash );
		}
		$this->CompleteTrans();
		return count( $this->mErrors ) == 0;
	}

	/**
	 * roleExists work out if a given role exists
	 * 
	 * @param string $pRoleName
	 * @param numeric $pUserId 
	 * @access public
	 * @return bool true on success, false on failure - mErrors will contain reason for failure
	 */
	function roleExists( $pRoleName, $pUserId = ROOT_USER_ID ) {
		static $sRoles = [];
		if( !isset( $sRoles[$pUserId][$pRoleName] ) ) {
			$bindVars = [ $pRoleName ];
			$whereSql = '';
			if( $pUserId != '*' ) {
				$whereSql = 'AND `user_id`=?';
				$bindVars[] = $pUserId;
			}
			$query = "
				SELECT ur.`role_name`, ur.`role_id`,  ur.`user_id`
				FROM `".BIT_DB_PREFIX."users_roles` ur
				WHERE `role_name`=? $whereSql";
			if( $result = $this->mDb->getAssoc( $query, $bindVars ) ) {
				if( empty( $sRoles[$pUserId] ) ) {
					$sRoles[$pUserId] = [];
				}
				$sRoles[$pUserId][$pRoleName] = $result[$pRoleName];
			} else {
				$sRoles[$pUserId][$pRoleName]['role_id'] = null;
			}
		}
		return $sRoles[$pUserId][$pRoleName]['role_id'];
	}

	/**
	 * removes user and associated private data
	 *
	 * @access public
	 * @return bool always true - some expunge overrides may retrun false
	 */
	public function expunge(): bool {
		global $gBitSystem, $gBitUser;
		$this->clearFromCache();
		if( $this->isValid() ) {
			$this->StartTrans();
			if( $this->mUserId == $gBitUser->mUserId ) {
				$this->mDb->RollbackTrans();
				$gBitSystem->fatalError( KernelTools::tra( 'You cannot delete yourself' ) );
			} elseif( $this->mUserId != ANONYMOUS_USER_ID ) {
				$userTables = [
					'users_roles_map',
				];

				foreach( $userTables as $table ) {
					$query = "DELETE FROM `".BIT_DB_PREFIX.$table."` WHERE `user_id` = ?";
					$result = $this->mDb->query( $query, [ $this->mUserId ] );
				}

				if( parent::expunge() ) {
					$this->CompleteTrans();
				} else {
					$this->mDb->RollbackTrans();
				}
			} else {
				$this->mDb->RollbackTrans();
				$gBitSystem->fatalError( KernelTools::tra( 'The anonymous user cannot be deleted' ) );
			}
		}
		return true;
	}

	public function isInGroup( $pGroupMixed ) { return false; }
	public function groupExists( $pGroupMixed ) { return false; }

	// =-=-=-=-=-=-=-=-=-=-=-= Role Functions =-=-=-=-=-=-=-=-=-=-=-=-=-=-=
	/**
	 * loadRoles load roles into $this->mRoles
	 * 
	 * @param boolean $pForceRefresh 
	 * @access public
	 * @return void
	 */
	function loadRoles( $pForceRefresh = false ) {
		if( $this->isValid() ) {
			$this->mRoles = $this->getRoles( 0, $pForceRefresh );
		}
	}

	/**
	 * isInRole work out if a given user is assigned to a role
	 * 
	 * @param mixed $pRoleMixed Role ID or Role Name (deprecated)
	 * @access public
	 * @return bool true on success, false on failure - mErrors will contain reason for failure
	 */
	function isInRole( $pRoleMixed ) {
		$ret = false;
		if( $this->isAdmin() ) {
			$ret = true;
		} if( $this->isValid() ) {
			if( empty( $this->mRoles ) ) {
				$this->loadRoles();
			}
			$ret = preg_match( '/A-Za-z/', $pRoleMixed )
				? in_array( $pRoleMixed, $this->mRoles )
				: isset( $this->mRoles[$pRoleMixed] );
		}
		return $ret;
	}

	/**
	 * getAllRoless Get a list of all Roles
	 * 
	 * @param array $pListHash List Hash
	 * @access public
	 * @return array of roles
	 */
	public function getAllRoles( &$pListHash ) {
		if( empty(  $pListHash['sort_mode'] ) || $pListHash['sort_mode'] == 'name_asc' ) {
			$pListHash['sort_mode'] = 'role_name_asc';
		}
		LibertyContent::prepGetList( $pListHash );
		$sortMode = $this->mDb->convertSortmode( $pListHash['sort_mode'] );
		if( !empty( $pListHash['find_roles'] ) ) {
			$mid = " AND UPPER(`role_name`) like ?";
			$bindvars[] = "%".strtoupper( $pListHash['find_roles'] )."%";
		} elseif( !empty( $pListHash['find'] ) ) {
			$mid = " AND  UPPER(`role_name`) like ?";
			$bindvars[] = "%".strtoupper( $pListHash['find'] )."%";
		} else {
			$mid = '';
			$bindvars = [];
		}

		if( !empty( $pListHash['hide_root_roles'] )) {
			$mid .= ' AND `user_id` <> '.ROOT_USER_ID;
		} elseif( !empty( $pListHash['only_root_roles'] )) {
			$mid .= ' AND `user_id` = '.ROOT_USER_ID;
		}

		if( !empty( $pListHash['user_id'] ) ){
			$mid .= ' AND `user_id` = ? ';
			$bindvars[] = $pListHash['user_id'];
		}
		if( !empty( $pListHash['is_public'] ) ) {
			$mid .= ' AND `is_public` = ?';
			$bindvars[] = $pListHash['is_public'];
		}
		if( !empty( $pListHash['visible'] ) && !$this->isAdmin() ){
			global $gBitUser;
			$mid .= ' AND `user_id` = ? OR `is_public` = ? ';
			$bindvars[] = $gBitUser->mUserId;
			$bindvars[] = 'y';

		}

		$mid =  preg_replace('/^ AND */',' WHERE ', $mid);

		$query = "
			SELECT `user_id`, `role_id`, `role_name` , `role_desc`, `role_home`, `is_default`, `is_public`
			FROM `".BIT_DB_PREFIX."users_roles` $mid
			ORDER BY $sortMode";
		$ret = [];
		if( $rs = $this->mDb->query( $query, $bindvars ) ) {
			while( $row = $rs->fetchRow() ) {
				$roleId = $row['role_id'];
				$ret[$roleId] = $row;
				$ret[$roleId]['perms'] = $this->getRolePermissions( [ 'role_id' => $roleId ]);
			}
		}

		$pListHash['cant'] = $this->mDb->getOne( "SELECT COUNT(*) FROM `".BIT_DB_PREFIX."users_roles` $mid", $bindvars );

		return $ret;
	}

	/**
	 * getAllUserRoles
	 * 
	 * @param numeric $pUserId 
	 * @access public
	 * @return array of roles a user belongs to
	 */
	function getAllUserRoles( $pUserId = null ) {
		if( empty( $pUserId ) ) {
			$pUserId = $this->mUserId;
		}

		$sql = "
			SELECT ur.`role_id` AS `hash_key`, ur.* FROM `".BIT_DB_PREFIX."users_roles` ur
			WHERE `user_id`=?
			ORDER BY ur.`role_name` ASC";
		return $this->mDb->getAssoc( $sql, [ $pUserId ] );
	}
	
	public function getAllGroups( &$pListHash ) {
		return [];
	}

	function getAllUserGroups( $pUserId = null ) {
		return [];
	}
	/**
	 * expungeRole remove a role
	 * 
	 * @param numeric $pRoleId
	 * @access public
	 * @return bool true on success, false on failure
	 */
	function expungeRole( $pRoleId ) {
		// we cannot remove the anonymous role
		if( $pRoleId != ANONYMOUS_TEAM_ID ) {
			$query = "DELETE FROM `".BIT_DB_PREFIX."users_roles_map` WHERE `role_id` = ?";
			$result = $this->mDb->query( $query, [ $pRoleId ] );
			$query = "DELETE FROM `".BIT_DB_PREFIX."users_role_permissions` WHERE `role_id` = ?";
			$result = $this->mDb->query( $query, [ $pRoleId ] );
			$query = "DELETE FROM `".BIT_DB_PREFIX."users_roles` WHERE `role_id` = ?";
			$result = $this->mDb->query( $query, [ $pRoleId ] );
			return true;
		}
		return false;
	}

	/**
	 * getDefaultRole get the default role of a given user
	 * 
	 * @param array $pRoleId pass in a Role ID to make conditional function
	 * @return array Default Role ID if one is set
	 */
	public static function getDefaultRole( $pRoleId = null ) {
		global $gBitDb;
		$bindvars = [];
		$whereSql = '';
		if( BitBase::verifyId( $pRoleId )) {
			$whereSql = "AND `role_id`=? ";
			$bindvars = [ $pRoleId ];
		}
		return $gBitDb->getAssoc( "SELECT `role_id`, `role_name` FROM `".BIT_DB_PREFIX."users_roles` WHERE `is_default` = 'y' $whereSql ", $bindvars );
	}

	/**
	 * getRoleUsers Get a list of users who share a given role id
	 * 
	 * @param int $pRoleId
	 * @return array list of users who are in the role id
	 */
	public function getRoleUsers( $pRoleId ) {
		$ret = [];
		if( BitBase::verifyId( $pRoleId )) {
			$query = "
				SELECT uu.`user_id` AS hash_key, uu.`login`, uu.`real_name`, uu.`user_id`
				FROM `".BIT_DB_PREFIX."users_users` uu
				INNER JOIN `".BIT_DB_PREFIX."users_roles_map` ur ON (uu.`user_id`=ur.`user_id`)
				WHERE `role_id`=?";
			$ret = $this->mDb->getAssoc( $query, [ $pRoleId ]);
		}
		return $ret;
	}

	/**
	 * getHomeRole get the URL where a user of that role should be sent
	 * 
	 * @param int $pRoleId
	 * @access public
	 * @return bool true on success, false on failure - mErrors will contain reason for failure
	 */
	public function getGroupHome( $pRoleId ) {
		return $this->getRoleHome( $pRoleId );
	}
	public function getRoleHome( $pRoleId ) {
		$ret = false;
		if( BitBase::verifyId( $pRoleId )) {
			$query = "SELECT `role_home` FROM `".BIT_DB_PREFIX."users_roles` WHERE `role_id`=?";
			$ret = $this->mDb->getOne( $query,[ $pRoleId ] );
		}
		return $ret;
	}

	/**
	 * storeUserDefaultRole
	 * 
	 * @param int $pUserId 
	 * @param int $pRoleId
	 * @access public
	 * @return bool true on success, false on failure
	 */
	function storeUserDefaultRole( $pUserId, $pRoleId ) {
		if( BitBase::verifyId( $pUserId ) && BitBase::verifyId( $pRoleId )) {
			$query = "UPDATE `".BIT_DB_PREFIX."users_users` SET `default_role_id` = ? WHERE `user_id` = ?";
			return $this->mDb->query( $query, [ $pRoleId, $pUserId ] );
		}
		return false;
	}

	/**
	 * batchAssignUsersToRole assign all users to a given role
	 * 
	 * @param int $pRoleId
	 * @access public
	 * @return void
	 */
	function batchAssignUsersToRole( $pRoleId ) {
		if( BitBase::verifyId( $pRoleId )) {
			$users = $this->getRoleUsers( $pRoleId );
			$result = $this->mDb->getCol( "SELECT uu.`user_id` FROM `".BIT_DB_PREFIX."users_users` uu" );
			foreach( $result as $userId ) {
				if( empty( $users[$userId] ) && $userId != ANONYMOUS_USER_ID ) {
					$this->addUserToRole( $userId, $pRoleId );
				}
			}
		}
	}

	/**
	 * batchSetUserDefaultRole
	 * 
	 * @param int $pRoleId
	 * @return void
	 */
	public function batchSetUserDefaultRole( $pRoleId ) {
		if( BitBase::verifyId( $pRoleId )) {
			$users = $this->getRoleUsers($pRoleId);
			foreach( array_keys( $users ) as $userId ) {
				$this->storeUserDefaultRole( $userId, $pRoleId );
			}
		}
	}

	/**
	 * getRoleInfo
	 * 
	 * @param int $pRoleId
	 * @return array role information
	 */
	public function getRoleInfo( $pRoleId ) {
		$ret = [];
		if( BitBase::verifyId( $pRoleId )) {
			$sql = "SELECT * FROM `".BIT_DB_PREFIX."users_roles` WHERE `role_id` = ?";
			$ret = $this->mDb->getRow( $sql, [ $pRoleId ] );

			$listHash = [
				'role_id' => $pRoleId,
				'sort_mode' => 'up.perm_name_asc',
			];
			$ret["perms"] = $this->getRolePermissions( $listHash );

			$sql = "SELECT COUNT(*) FROM `".BIT_DB_PREFIX."users_roles_map` WHERE `role_id` = ?";
			$ret['num_members'] = $this->mDb->getOne( $sql, [ $pRoleId ] );
		}
		return $ret;
	}

	/**
	 * addUserToRole Adds user pUserId to role(s) pRoleMixed.
	 * 
	 * @param int $pUserId User ID
	 * @param mixed $pRoleMixed A single role ID or an array of role IDs
	 * @return array|bool Either an ADO RecordSet (success) or false (failure).
	 */
	public static function addUserToRole( ?int $pUserId, array|int $pRoleMixed ): array|bool {
		global $gBitUser;
		$result = false;
		if( BitBase::verifyId( $pUserId ) && !empty( $pRoleMixed )) {
			$result = true;
			$addRoles = [];
			if( is_array( $pRoleMixed ) ) {
				$addRoles = array_keys( $pRoleMixed );
			} elseif(BitBase::verifyId($pRoleMixed) ) {
				$addRoles = [ $pRoleMixed ];
			}
			$currentUserRoles = $gBitUser->getRoles( $pUserId );
			foreach( $addRoles AS $roleId ) {
				$isInRole = false;
				if( $currentUserRoles ) {
					foreach( $currentUserRoles as $curRoleId => $curRoleInfo ) {
						if( $curRoleId == $roleId ) {
							$isInRole = true;
						}
					}
				}
				if( !$isInRole ) {
					$query = "INSERT INTO `".BIT_DB_PREFIX."users_roles_map` (`user_id`,`role_id`) VALUES(?,?)";
					$result = $gBitUser->mDb->query( $query, [ $pUserId, $roleId ] );
				}
			}
		}
		$gBitUser->clearFromCache();
		return $result;
	}

	/**
	 * removeUserFromRole
	 * 
	 * @param int $pUserId 
	 * @param int $pRoleId
	 * @access public
	 * @return void
	 */
	function removeUserFromRole( $pUserId, $pRoleId ) {
		if( BitBase::verifyId( $pUserId ) && BitBase::verifyId( $pRoleId )) {
			$query = "DELETE FROM `".BIT_DB_PREFIX."users_roles_map` WHERE `user_id` = ? AND `role_id` = ?";
			$result = $this->mDb->query( $query, [ $pUserId, $pRoleId ] );
			$default = $this->getDefaultRole();
			if( $pRoleId == key( $default )) {
				$query = "UPDATE `".BIT_DB_PREFIX."users_users` SET `default_role_id` = null WHERE `user_id` = ?";
				$this->mDb->query( $query, [ $pUserId ] );
			}
		}
		$this->clearFromCache();
	}

	/**
	 * verifyRole
	 * 
	 * @param array $pParamHash 
	 * @access public
	 * @return bool true on success, false on failure - mErrors will contain reason for failure
	 */
	function verifyRole( &$pParamHash ) {
		if( !empty($pParamHash['role_id'] )) {
			if( @$this->verifyId( $pParamHash['role_id'] )) {
				$pParamHash['role_store']['role_id'] = $pParamHash['role_id'];
			} else {
				$this->mErrors['roles'] = 'Unknown Role';
			}
		}

		if( !empty( $pParamHash["name"] )) {
			$pParamHash['role_store']['role_name'] = substr( $pParamHash["name"], 0, 30 );
		}
		if( !empty( $pParamHash["desc"] )) {
			$pParamHash['role_store']['role_desc'] = substr( $pParamHash["desc"], 0, 255 );;
		}
		$pParamHash['role_store']['role_home']              = !empty( $pParamHash["home"] )                    ? $pParamHash["home"]                    : '';
		$pParamHash['role_store']['is_default']              = !empty( $pParamHash["is_default"] )              ? $pParamHash["is_default"]              : null;
		$pParamHash['role_store']['user_id']                 = @$this->verifyId( $pParamHash["user_id"] )       ? $pParamHash["user_id"]                 : $this->mUserId;
		$pParamHash['role_store']['is_public']               = !empty( $pParamHash['is_public'] )               ? $pParamHash['is_public']               : null;
		$pParamHash['role_store']['after_registration_page'] = !empty( $pParamHash['after_registration_page'] ) ? $pParamHash['after_registration_page'] : '';
		return count( $this->mErrors ) == 0;
	}

	/**
	 * storeRole
	 * 
	 * @param array $pParamHash 
	 * @access public
	 * @return bool true on success, false on failure - mErrors will contain reason for failure
	 */
	function storeRole( &$pParamHash ) {
		global $gBitSystem, $gBitUser;
		if ($this->verifyRole( $pParamHash)) {
			$this->StartTrans();
			if( empty( $pParamHash['role_id'] ) ) {
				$pParamHash['role_id'] = $this->mDb->GenID( 'users_roles_id_seq' );
				$pParamHash['role_store']['role_id'] = $pParamHash['role_id'];
				$result = $this->mDb->associateInsert( BIT_DB_PREFIX.'users_roles', $pParamHash['role_store'] );
			} else {
				$sql = "SELECT COUNT(*) FROM `".BIT_DB_PREFIX."users_roles` WHERE `role_id` = ?";
				$roleExists = $this->mDb->getOne($sql, [ $pParamHash['role_id'] ] );
				if ($roleExists) {
					$result = $this->mDb->associateUpdate( BIT_DB_PREFIX.'users_roles', $pParamHash['role_store'], [ "role_id" => $pParamHash['role_id'] ] );
				} else {
					// A role_id was specified but that role does not exist yet
					$pParamHash['role_store']['role_id'] = $pParamHash['role_id'];
					$result = $this->mDb->associateInsert(BIT_DB_PREFIX.'users_roles', $pParamHash['role_store']);
				}
			}

			if( isset( $_REQUEST['batch_set_default'] ) and $_REQUEST['batch_set_default'] == 'on' ) {
				$gBitUser->batchSetUserDefaultRole( $pParamHash['role_id'] );
			}
			$this->CompleteTrans();
		}
		return count( $this->mErrors ) == 0;
	}

	/**
	 * getRoleNameFromId
	 * 
	 * @param array $pRoleId 
	 * @param array $pColumns 
	 * @access public
	 * @return string of role name
	 */
	public static function getRoleNameFromId( $pRoleId ): string {
		$ret = '';
		if( static::verifyId( $pRoleId ) ) {
			global $gBitDb;
			$ret = $gBitDb->getOne( "SELECT `role_name` FROM `".BIT_DB_PREFIX."users_roles` WHERE `role_id`=?", [ $pRoleId ] );
		}
		return $ret;
	}

	/**
	 * getRoleUserData
	 * 
	 * @param array $pRoleId
	 * @param array $pColumns 
	 * @return array of role data
	 */
	public function getRoleUserData( $pRoleId, $pColumns ) {
		$ret = [];
		if( @$this->verifyId( $pRoleId ) && !empty( $pColumns ) ) {
			if( is_array( $pColumns ) ) {
				$col = implode( ',', $pColumns );
				$exec = 'getAssoc';
			} else {
				$col = '`'.$pColumns.'`';
				$exec = 'getArray';
			}
			$query = "
				SELECT $col
				FROM `".BIT_DB_PREFIX."users_users` uu
					INNER JOIN `".BIT_DB_PREFIX."users_roles_map` urm ON (uu.`user_id`=urm.`user_id`)
				WHERE urm.`role_id` = ?";
			$ret = $this->mDb->$exec( $query, [ $pRoleId ]);
		}
		return $ret;
	}

	// =-=-=-=-=-=-=-=-=-=-=-= PERMISSION FUNCTIONS =-=-=-=-=-=-=-=-=-=-=-=-=-=-=
	/**
	 * loadPermissions 
	 * 
	 * @return bool true on success, false if no perms were loaded
	 */
	public function loadPermissions( $pForceReload=false ) {
		if( $this->isValid() && (empty( $this->mPerms ) || $pForceReload) ) {
			$this->mPerms = [];
			// the double up.`perm_name` is intentional - the first is for hash key, the second is for hash value
			$query = "
				SELECT up.`perm_name` AS `hash_key`, up.`perm_name`, up.`perm_desc`, up.`perm_level`, up.`package`
				FROM `".BIT_DB_PREFIX."users_permissions` up
					INNER JOIN `".BIT_DB_PREFIX."users_role_permissions` urp ON ( urp.`perm_name`=up.`perm_name` )
					INNER JOIN `".BIT_DB_PREFIX."users_roles` ur ON ( ur.`role_id`=urp.`role_id` )
					LEFT OUTER JOIN `".BIT_DB_PREFIX."users_roles_map` urm ON ( urm.`role_id`=urp.`role_id` AND urm.`user_id` = ? )
				WHERE ur.`role_id`= ".ANONYMOUS_TEAM_ID." OR urm.`role_id`=ur.`role_id`";
			$this->mPerms = $this->mDb->getAssoc( $query, [ $this->mUserId ] );
			// Add in override permissions
			if( !empty( $this->mPermsOverride ) ) {
				foreach( $this->mPermsOverride as $key => $val ) {
					$this->mPerms[$key] = $val;
				}
			}
		}
		return count( $this->mPerms );
	}

	/**
	 * getUnassignedPerms 
	 * 
	 * @return array of permissions that have not been assigned to any role yet
	 */
	public function getUnassignedPerms() {
		$query = "SELECT up.`perm_name` AS `hash_key`, up.*
			FROM `".BIT_DB_PREFIX."users_permissions` up
				LEFT OUTER JOIN `".BIT_DB_PREFIX."users_role_permissions` urp ON( up.`perm_name` = urp.`perm_name` )
			WHERE urp.`role_id` IS null AND up.`perm_name` <> ?
			ORDER BY `package`, up.`perm_name` ASC";
		return $this->mDb->getAssoc( $query, [ '' ] );
	}

	/**
	 * isAdmin 
	 * 
	 * @param array $pCheckTicket 
	 * @return bool true on success, false on failure - mErrors will contain reason for failure
	 */
	public function isAdmin() {
		// we can't use hasPermission here since it turn into an endless loop
		return !empty( $this->mPerms['p_admin'] );
	}

	/**
	 * verifyPermission check if a user has a given permission and if not 
	 * it will display the error template and die()
	 * @param $pPermission value of a given permission
	 * @return void
	 */
	public function verifyPermission( $pPermission, $pMsg = null ) {
		global $gBitSmarty, $gBitSystem, ${$pPermission};
		if( empty( $pPermission ) || $this->hasPermission( $pPermission ) ) {
			return;
		} else {
			$gBitSystem->fatalPermission( $pPermission, $pMsg );
		}
	}

	public function getGroupPermissions( $pParamHash = null ) {
		$this->getRolePermissions( $pParamHash );
	}

	/**
	 * getRolePermissions
	 * 
	 * @param array $pRoleId Role id, if unset, all roles are returned
	 * @param string $pPackage permissions to give role, if unset, all permissions are returned
	 * @param string $find search for a particular permission
	 * @param array $pSortMode sort mode of return hash
	 * @return array
	 */
	public function getRolePermissions( $pParamHash = null ) {
		global $gBitSystem;
		$ret = $bindVars = [];
		$whereSql = $selectSql = $fromSql = '';

		$sortMode = !empty( $pParamHash['sort_mode'] ) 
			? $this->mDb->convertSortmode( $pParamHash['sort_mode'] ) 
			: 'up.`package`, up.`perm_name` ASC';

		if( !empty( $pParamHash['package'] )) {
			$whereSql = ' WHERE `package`= ? ';
			$bindVars[] = $pParamHash['package'];
		}

		if( BitBase::verifyId( $pParamHash['role_id'] ?? 0 ) ) {
			$selectSql = ', urp.`perm_value` AS `hasPerm` ';
			$fromSql = ' INNER JOIN `'.BIT_DB_PREFIX.'users_role_permissions` urp ON ( urp.`perm_name`=up.`perm_name` ) ';
			if( $whereSql ) {
				$whereSql .= " AND  urp.`role_id`=?";
			} else {
				$whereSql .= " WHERE urp.`role_id`=?";
			}

			$bindVars[] = $pParamHash['role_id'];
		}

		if( !empty( $pParamHash['find'] )) {
			if( $whereSql ) {
				$whereSql .= " AND `perm_name` like ?";
			} else {
				$whereSql .= " WHERE `perm_name` like ?";
			}
			$bindVars[] = '%'.$pParamHash['find'].'%';
		}

		// the double up.`perm_name` is intentional - the first is for hash key, the second is for hash value
		$query = "
			SELECT up.`perm_name` AS `hash_key`, up.`perm_name`, up.`perm_desc`, up.`perm_level`, up.`package` $selectSql
			FROM `".BIT_DB_PREFIX."users_permissions` up $fromSql $whereSql
			ORDER BY $sortMode";
		$perms = $this->mDb->getAssoc( $query, $bindVars );

		// weed out permissions of inactive packages
		$ret = [];
		foreach( $perms as $key => $perm ) {
			if( $gBitSystem->isPackageActive( $perm['package'] )) {
				$ret[$key] = $perm;
			}
		}

		return $ret;
	}

	/**
	 * assignLevelPermissions Assign the permissions of a given level to a given role
	 * 
	 * @param int $pRoleId Role we want to assign permissions to
	 * @param string  $pLevel permission level we wish to assign from
	 * @param string $pPackage limit set of permissions to a given package
	 * @return void
	 */
	public function assignLevelPermissions( $pRoleId, $pLevel, $pPackage = '') {
		if( BitBase::verifyId( $pRoleId ) && !empty( $pLevel )) {
			$bindvars = [ $pLevel ];
			$whereSql = '';
			if( !empty( $pPackage ) ) {
				$whereSql = ' AND `package`=?';
				array_push( $bindvars, $pPackage );
			}
			$query = "SELECT `perm_name` FROM `".BIT_DB_PREFIX."users_permissions` WHERE `perm_level` = ? $whereSql";
			if( $result = $this->mDb->query( $query, $bindvars ) ) {
				while( $row = $result->fetchRow() ) {
					$this->assignPermissionToRole( $row['perm_name'], $pRoleId );
				}
			}
		}
	}

	/**
	 * getPermissionPackages Get a list of packages that have their own set of permissions
	 * 
	 * @access public
	 * @return array of packages
	 */
	function getPermissionPackages() {
		return $this->mDb->getCol( "SELECT DISTINCT(`package`) FROM `".BIT_DB_PREFIX."users_permissions` ORDER BY `package`" );
	}

	/**
	 * assignPermissionToRole
	 * 
	 * @param string $perm 
	 * @param int $pRoleId
	 * @return void
	 */
	public function assignPermissionToRole( $pPerm, $pRoleId ) {
		if( BitBase::verifyId( $pRoleId ) && !empty( $pPerm )) {
			$query = "DELETE FROM `".BIT_DB_PREFIX."users_role_permissions` WHERE `role_id` = ? AND `perm_name` = ?";
			$result = $this->mDb->query( $query, [ $pRoleId, $pPerm ] );
			$query = "INSERT INTO `".BIT_DB_PREFIX."users_role_permissions`(`role_id`, `perm_name`) VALUES(?, ?)";
			$result = $this->mDb->query( $query, [ $pRoleId, $pPerm ] );
		}
	}

	/**
	 * removePermissionFromRole
	 * 
	 * @param string $pPerm Perm name
	 * @param int $pRoleId Role ID
	 * @return void
	 */
	public function removePermissionFromRole( $pPerm, $pRoleId ) {
		if( BitBase::verifyId( $pRoleId ) && !empty( $pPerm )) {
			$query = "DELETE FROM `".BIT_DB_PREFIX."users_role_permissions` WHERE `perm_name` = ? AND `role_id` = ?";
			$result = $this->mDb->query($query, [$pPerm, $pRoleId ] );
		}
	}

	/**
	 * storeRegistrationChoice
	 * 
	 * @param mixed $pRoleMixed A single role ID or an array of role IDs
	 * @param string $pValue Value you wish to store - use null to delete a value
	 * @return array|null ADO record set on success, false on failure
	 */
	public function storeRegistrationChoice( $pRoleMixed, $pValue = null ) {
		if( !empty( $pRoleMixed )) {
			$bindVars[] = $pValue;
			if( is_array( $pRoleMixed )) {
				$mid = implode( ',', array_fill( 0, count( $pRoleMixed ),'?' ));
				$bindVars = array_merge( $bindVars, $pRoleMixed );
			} else {
				$bindVars[] = $pRoleMixed;
				$mid = 'LIKE ?';
			}
			$query = "UPDATE `".BIT_DB_PREFIX."users_roles` SET `is_public`= ? where `role_id` IN ($mid)";
			return $this->mDb->query( $query, $bindVars );
		}
		return null;
	}

	/**
	 * Grant a single permission to a given value
	 */
	public function setPermissionOverride( $pPerm, $pValue = null ) {
		if( $this->isAdmin() ) {
			$this->mPerms[$pPerm] = true;
			$this->mPermsOverride[$pPerm] = true;
		} elseif( $this->isValid() ) {
			if( $pValue == 'y' || $pValue == true ) {
				$this->mPermsOverride[$pPerm] = true;
				$this->mPerms[$pPerm] = true;
			} else {
				unset( $this->mPermsOverride[$pPerm] );
				unset( $this->mPerms[$pPerm] );
			}
		}
	}
}