{strip}

<div class="display login">
	<div class="header">
		<h1>{tr}Register as a new user{/tr}</h1>
		{if $showmsg eq 'y'}<h2>{$msg}</h2>{/if}
	</div>

	<div class="body">
		<p>{tr}If you are already registered, please{/tr} <a href="{$smarty.const.USERS_PKG_URL}login.php">{tr}login{/tr}</a></p>
		{form enctype="multipart/form-data" legend="Please fill in the following details"}
			{if $notrecognized eq 'y'}
				<input type="hidden" name="login" value="{$reg.login}"/>
				<input type="hidden" name="password" value="{$reg.password}"/>
				<input type="hidden" name="novalidation" value="yes"/>

				<div class="row">
					{formfeedback error=$errors.validate}
					{formlabel label="Username" for="email"}
					{forminput}
						<input type="text" size="50" name="email" id="email" value="{$reg.email}"/>
					{/forminput}
				</div>

				<div class="row submit">
					<input type="submit" name="register" value="{tr}register{/tr}" />
				</div>
			{elseif $showmsg ne 'y'}
				{if $gBitSystem->isFeatureActive( 'reg_real_name' )}
					<div class="row">
						{formlabel label="Real name" for="real_name"}
						{forminput}
							<input type="text" name="real_name" id="real_name" />
						{/forminput}
					</div>
				{/if}

				<div class="row">
					{formfeedback error=$errors.login}
					{formlabel label="Username" for="login"}
					{forminput}
						<input type="text" name="login" id="login" value="{$reg.login}" /> <acronym title="{tr}Required{/tr}">*</acronym>
						{formhelp note="Your username can only contain numbers, characters, and underscores."}
					{/forminput}
				</div>

				<div class="row">
					{formfeedback error=$errors.email}
					{formlabel label="Email" for="email"}
					{forminput}
						<input type="text" size="50" name="email" id="email" value="{$reg.email}" /> <acronym title="{tr}Required{/tr}">*</acronym>
					{/forminput}
				</div>

				{if $gBitSystem->mPrefs.use_register_passcode eq 'y'}
					<div class="row">
						{formfeedback error=$errors.passcode}
						{formlabel label="Passcode to register<br />(not your user password)" for="passcode"}
						{forminput}
							<input type="password" name="passcode" id="passcode" /> <acronym title="{tr}Required{/tr}">*</acronym>
						{/forminput}
					</div>
				{/if}

				{if $gBitSystem->isFeatureActive( 'validate_user' )}
					<div class="row">
						{formfeedback warning="A confirmation email will be sent to you with instructions how to login"}
					</div>
				{else}
					<div class="row">
						{formfeedback error=$errors.password}
						{formlabel label="Password" for="pass"}
						{forminput}
							<input id="pass1" type="password" name="password" value="{$reg.password}" /> <acronym title="{tr}Required{/tr}">*</acronym>
						{/forminput}
					</div>

					<div class="row">
						{formlabel label="Repeat password" for="password2"}
						{forminput}
							<input id="password2" type="password" name="password2" /> <acronym title="{tr}Required{/tr}">*</acronym>
						{/forminput}
					</div>

					{if $gBitSystem->isFeatureActive( 'user_password_generator' )}
						<div class="row">
							{formlabel label="<a href=\"javascript:genPass('genepass','pass1','pass2');\">{tr}Generate a password{/tr}</a>" for="email"}
							{forminput}
								<input id="genepass" type="text" />
								{formhelp note="You can use this link to create a random password. Make sure you make a note of it somewhere to log in to this site in the future."}
							{/forminput}
						</div>
					{/if}
				{/if}

				{if $gBitSystem->isFeatureActive( 'reg_real_name' ) or $gBitSystem->isFeatureActive( 'reg_homepage' ) or $gBitSystem->isFeatureActive( 'reg_country' ) or $gBitSystem->isFeatureActive( 'reg_language' ) or $gBitSystem->isFeatureActive( 'reg_portrait' )}
					{legend legend="Optional Details"}
						{if $gBitSystem->isFeatureActive( 'reg_homepage' )}
							<div class="row">
								{formlabel label="HomePage" for="homePage"}
								{forminput}
									<input size="50" type="text" name="prefs[homePage]" id="homePage" />
									{formhelp note="If you have a personal or professional homepage, enter it here."}
								{/forminput}
							</div>
						{/if}

						{if $gBitSystem->isFeatureActive( 'reg_country' )}
							<div class="row">
								{formlabel label="Country" for="country"}
								{forminput}
									<select name="prefs[country]" id="country">
										<option value="" />
										{sortlinks}
											{section name=ix loop=$flags}
												<option value="{$flags[ix]|escape}" {if $userPrefs.flag eq $flags[ix]}selected="selected"{/if}>{tr}{$flags[ix]|replace:'_':' '}{/tr}</option>
											{/section}
										{/sortlinks}
									</select>
									{formhelp note=""}
								{/forminput}
							</div>
						{/if}

						{if $gBitSystem->isFeatureActive( 'reg_language' )}
							<div class="row">
								{formlabel label="Language" for="language"}
								{forminput}
									<select name="prefs[bitlanguage]" id="language">
										{foreach from=$languages key=langCode item=lang}
											<option value="{$langCode}"{if $gBitLanguage->mLanguage eq $langCode} selected="selected"{/if}>
												{$lang.full_name}
											</option>
										{/foreach}
									</select>
									{formhelp note="Pick your preferred site language."}
								{/forminput}
							</div>
						{/if}

						{if $gBitSystem->isFeatureActive( 'reg_portrait' )}
							<div class="row">
								{formlabel label="Self Portrait" for="fPortraitFile"}
								{forminput}
									<input name="fPortraitFile" id="fPortraitFile" type="file" />
									{formhelp note="Upload a personal photo to be displayed on your personal page."}
								{/forminput}
							</div>
						{/if}
					{/legend}
				{/if}

				{section name=f loop=$customFields}
					<div class="row">
						{formlabel label="$customFields[f]}
						{forminput}
							<input type="text" name="CUSTOM[{$customFields[f]|escape}" />
						{/forminput}
					</div>
				{/section}

				{if $gBitSystem->mPrefs.rnd_num_reg eq 'y'}
					<hr />

					<div class="row">
						{formfeedback error=$errors.rnd_num_reg}
						{formlabel label="Your registration code"}
						{forminput}
							<img src="{$smarty.const.USERS_PKG_URL}random_num_img.php" alt="{tr}Random Image{/tr}"/>
						{/forminput}
					</div>

					<div class="row">
						{formlabel label="Registration code" for="regcode"}
						{forminput}
							<input type="text" maxlength="8" size="8" name="regcode" id="regcode" /> <acronym title="{tr}Required{/tr}">*</acronym>
							{formhelp note="Please copy the code above into this field. This is a security feature to avoid automatic registration by bots."}
						{/forminput}
					</div>
				{/if}

				<div class="row submit">
					<input type="submit" name="register" value="{tr}Register{/tr}" />
				</div>
			{/if}
		{/form}
	</div><!-- end .body -->
</div><!-- end .login -->

{/strip}
