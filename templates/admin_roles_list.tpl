{strip}
<div class="listing users">
	<div class="header">
		<h1>{tr}List of existing roles{/tr}</h1>
	</div>

	<div class="body">
		{smartlink ititle="Add a new role" ipackage=users ifile="admin/edit_role.php" action=create}

		<div class="navbar">
			<ul>
				<li>{biticon ipackage="icons" iname="emblem-symbolic-link" iexplain="sort by"}</li>
				<li>{smartlink ititle="Name" isort="role_name" offset=$offset idefault=1}</li>
				<li>{smartlink ititle="Description" isort="role_desc" offset=$offset}</li>
				<li>{smartlink ititle="Home Page" isort="role_home" offset=$offset}</li>
			</ul>
		</div><!-- end .navbar -->

		{formfeedback success=$successMsg error=$errorMsg}

		<ul class="clear data">
			{foreach from=$roleList key=roleId item=grp}
				<li class="item {cycle values='odd,even'}">
					<div class="floaticon">
						{smartlink ititle="Edit" ipackage="users" ifile="admin/edit_role.php" ibiticon="icons/accessories-text-editor" role_id=$roleId}
						{smartlink ititle="Role Members" ipackage="users" ifile="admin/edit_role.php" ibiticon="icons/system-users" members=$roleId}
						{if $roleId ne $smarty.const.ANONYMOUS_ROLE_ID}
							{smartlink ititle="Batch assign" ipackage="users" ifile="admin/edit_role.php" ibiticon="icons/application-x-executable" batch_assign=$roleId}
							{smartlink ititle="Remove" ipackage="users" ifile="admin/edit_role.php" ibiticon="icons/edit-delete" action=delete role_id=$roleId}
						{/if}
					</div>

					<h2>{$grp.role_name}</h2>
					<div style="float:left;width:30%;">
						{$grp.role_desc}<br />
						{if $grp.is_default eq 'y'}<small class="warning">*{tr}Default role{/tr}*</small><br/>{/if}
						{if $grp.role_home}{tr}Home Page{/tr}:<strong> {$grp.role_home}</strong><br />{/if}
					</div>

					<div style="float:right;width:70%;">
						{tr}Permissions{/tr}
						<ul class="small">
							{foreach from=$grp.perms key=permName item=perm}
								<li>{$perm.perm_desc}</li>
							{foreachelse}
								<li>{tr}none{/tr}</li>
							{/foreach}
						</ul>
					</div>
					<div class="clear"></div>
				</li>
			{/foreach}
		</ul>
		{pagination}
	</div><!-- end .body -->
</div><!-- end .users -->
{/strip}
