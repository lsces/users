<?php
/**
 * @package users
 */

global $gBitInstaller;

$gBitInstaller->registerPackageUpgrade(
	[
		'package'     => USERS_PKG_NAME,
		'version'     => '5.0.1',
		'description' => 'Add users_auth_map table for OAuth/external authentication provider support.',
	],
	[
		[ 'DATADICT' => [
			[ 'CREATE' => [
				'users_auth_map' => "
					user_id I4 PRIMARY,
					provider C(64) PRIMARY,
					provider_identifier C(64) NOTNULL,
					last_login I8,
					profile_json X
				",
			]],
			[ 'CREATEINDEX' => [
				'users_auth_user_idx'           => [ 'users_auth_map', 'user_id',                    null ],
				'users_auth_provider_ident_idx' => [ 'users_auth_map', 'provider,provider_identifier', [ 'UNIQUE' ] ],
			]],
		]],
	]
);

$constraints = [
	'users_auth_map' => [ 'users_auth_user_ref' => 'FOREIGN KEY (`user_id`) REFERENCES `' . BIT_DB_PREFIX . 'users_users` (`user_id`)' ],
];
foreach( array_keys( $constraints ) as $tableName ) {
	$gBitInstaller->registerSchemaConstraints( USERS_PKG_NAME, $tableName, $constraints[$tableName] );
}
