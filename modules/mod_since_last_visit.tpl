{* $Header$ *}
{if $gBitUser->isRegistered()}
	{bitmodule title="$moduleTitle" name="since_last_visit"}
		{tr}Since your last visit on{/tr}<br />
		<b>{$nvi_info.lastVisit|bit_short_datetime|replace:"[":""|replace:"]":""}</b><br />
		{$nvi_info.images} {tr}new images{/tr}<br />
		{$nvi_info.pages} {tr}wiki pages changed{/tr}<br />
		{$nvi_info.files} {tr}new files{/tr}<br />
		{$nvi_info.comments} {tr}new comments{/tr}<br />
		{$nvi_info.users} {tr}new users{/tr}<br />
	{/bitmodule}
{/if}
