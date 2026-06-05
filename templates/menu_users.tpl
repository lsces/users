{strip}
{if !$icons_only}
	{assign var=location value=menu}
{/if}
{if $packageMenuTitle}<a class="dropdown-toggle" data-toggle="dropdown" href="#"> {tr}{$packageMenuTitle}{/tr} <b class="caret"></b></a>{/if}
<ul class="{$packageMenuClass}">
	{if $gBitUser->isRegistered()}
		<li><a class="item" href="{$gBitSystem->getConfig('users_login_homepage',"`$smarty.const.USERS_PKG_URL`my.php")}">{biticon ipackage="icons" iname="go-next" iexplain="My Personal Page"}My Personal Page</a></li>
		{if $gBitUser->hasPermission( 'p_users_view_user_homepage' )}
			<li><a class="item" href="{$gBitUser->getDisplayUrl()}">{biticon ipackage="icons" iname="go-home" iexplain="My Profile"}My Profile</a></li>
		{/if}
		{if $gBitUser->hasPermission( 'p_users_edit_user_homepage' )}
			<li><a class="item" href="{$smarty.const.USERS_PKG_URL}edit_personal_page.php">{biticon ipackage="icons" iname="edit" iexplain="Edit My Homepage"}Edit My Homepage</a></li>
		{/if}
		{if $gBitSystem->isFeatureActive( 'users_preferences' )}
			<li><a class="item" href="{$smarty.const.USERS_PKG_URL}preferences.php">{biticon ipackage="icons" iname="internet-mail" iexplain="Preferences"}Preferences</a></li>
		{/if}
		{if $gBitUser->hasPermission( 'p_users_create_personal_groups' )}
			<li><a class="item" href="{$smarty.const.USERS_PKG_URL}my_groups.php">{biticon ipackage="icons" iname="system-users" iexplain="My Groups"}My Groups</a></li>
		{/if}
		{if $gBitUser->hasPermission( 'p_users_create_personal_roles' )}
			<li><a class="item" href="{$smarty.const.USERS_PKG_URL}my_roles.php">{biticon ipackage="icons" iname="system-users" iexplain="My Roles"}My Roles</a></li>
		{/if}
		{if $gBitSystem->isFeatureActive( 'users_watches' )}
			<li><a class="item" href="{$smarty.const.USERS_PKG_URL}watches.php">{biticon ipackage="icons" iname="emblem-important" iexplain="My Watches"}My Watches</a></li>
		{/if}
		{if $gBitSystem->isPackageActive( 'messages' ) && $gBitUser->hasPermission( 'p_messages_send' )}
			<li><a class="item" {if $unreadMsgs}title="{tr}You have unread messages{/tr}"{/if} href="{$smarty.const.MESSAGES_PKG_URL}message_box.php">{biticon ipackage="icons" iname="internet-mail" iexplain="Message Box"}{if $unreadMsgs}<strong> [{$unreadMsgs}]</strong>{/if}</a></li>
			<li><a class="item" href="{$smarty.const.MESSAGES_PKG_URL}compose.php">{biticon ipackage="icons" iname="internet-mail" iexplain="Compose Message"}Compose Message</a></li>
		{/if}
		{if $gBitSystem->isPackageActive( 'gatekeeper' )}
			<li><a class="item" href="{$smarty.const.GATEKEEPER_PKG_URL}">{biticon ipackage="icons" iname="lock" iexplain="Security Settings"}Security Settings</a></li>
		{/if}
		{if $gBitSystem->isPackageActive( 'quota' )}
			<li><a class="item" href="{$smarty.const.QUOTA_PKG_URL}">{biticon ipackage="icons" iname="drive-harddisk" iexplain="My quota and usage"}My quota and usage</a></li>
		{/if}
		{if $gBitUser->hasPermission( 'p_liberty_attach_attachments' )}
			<li><a class="item" href="{$smarty.const.LIBERTY_PKG_URL}attachments.php">{biticon ipackage="icons" iname="stock_attach" iexplain="My Files"}My Files</a></li>
		{/if}
		{if $gBitUser->hasPermission('p_liberty_list_content')}
			<li><a class="item" href="{$smarty.const.LIBERTY_PKG_URL}list_content.php">{biticon ipackage="icons" iname="view-list-text" iexplain="List Site Content"}List Site Content</a></li>
		{/if}
		{if $gBitUser->hasPermission('p_users_view_user_list')}
			<li><a class="item" href="{$smarty.const.USERS_PKG_URL}index.php">{biticon ipackage="icons" iname="system-users" ipackage="icons" iexplain="List Site Users"}List Site Users</a></li>
		{/if}
		<li><a class="item" href="{$smarty.const.USERS_PKG_URL}logout.php">{biticon ipackage="icons" iname="system-log-out" iexplain="Log out"}Log out</a></li>
	{else}
		<li><a class="item" href="{$smarty.const.USERS_PKG_URL}signin.php">{biticon ipackage="icons" iname="system-users" iexplain="Login"}Login</a></li>
		{if $gBitSystem->isFeatureActive('users_allow_register')}
			<li><a class="item" href="{$smarty.const.USERS_PKG_URL}register.php">{biticon ipackage="icons" iname="user-desktop" iexplain="Register"}Register</a></li>
		{/if}
	{/if}
</ul>
{/strip}
