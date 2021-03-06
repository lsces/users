{* $Header$ *}
{strip}

<div class="floaticon">{bithelp}</div>
<div class="display my">
	<div class="header">
		<h1>{tr}My {$gBitSystem->getConfig('site_title')|default:'Site'}{/tr}</h1>
	</div>

	{include file="bitpackage:users/my_bitweaver_bar.tpl"}

	<div class="body">

{*
	this is where we should add the following tabs:
	file manager
	quota manager - currently on separate page, but i believe this would be good in here.
	listing of submitted / edited stuff - similar to the old tiki personal tiki stuff.
*}

		{jstabs}
			{jstab title="My Navigation Pane"}
				<table width="100%" class="menutable">
					<tr>
						{assign var="i" value="1"}
						{foreach key=key item=menu from=$gBitSystem->mAppMenu}
							{if $menu.menu_title && $menu.index_url && $menu.menu_template && !$menu.is_disabled}
								<td style="width:33%;vertical-align:top;">
									{box class="`$key`menu menu box" ipackage=$key iname="pkg_`$key`" iexplain="$key" iclass="menuicon" title=$menu.menu_title}
										{include file=$menu.menu_template}
									{/box}
								</td>
								{if not ($i++ mod 3)}
									</tr><tr>
								{/if}
							{/if}
						{/foreach}
					</tr>
				</table>
			{/jstab}

			{jstab title="My Information"}
				{legend legend="User Information"}
					{include file="bitpackage:users/user_information_inc.tpl" userData=$gBitUser}

					{if $gBitUser->mInfo.avatar_url}
						<div class="row">
							{formlabel label="Avatar"}
							{forminput}
								<img src="{$gBitUser->mInfo.avatar_url}" alt="{tr}avatar{/tr}" />
							{/forminput}
						</div>
					{/if}

					{if $gBitUser->mInfo.portrait_url}
						<div class="row">
							{formlabel label="Portrait"}
							{forminput}
								<img src="{$gBitUser->mInfo.portrait_url}" alt="{tr}portrait{/tr}" />
							{/forminput}
						</div>
					{/if}

					{if $gBitUser->mInfo.logo_url}
						<div class="row">
							{formlabel label="Logo"}
							{forminput}
								<img src="{$gBitUser->mInfo.logo_url}" alt="{tr}logo{/tr}" />
							{/forminput}
						</div>
					{/if}

					{formhelp note="If you wish to change any of this information, please visit your personal preferences page" link="users/preferences.php/Personal Preferences"}
				{/legend}
			{/jstab}
		{if $contentList}
			{jstab title="My Content"}
				{include file="bitpackage:liberty/list_content_inc.tpl"}
			{/jstab}
		{/if}
		{/jstabs}
	</div><!-- end .body -->
</div><!-- end .my -->

{/strip}
