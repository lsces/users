{* Flag country select widget.
   Params: fsName (input name), fsValue (current alpha-3 code), fsId (unique element id)
   Optional: fsSize (small|medium|large, default small) *}
{assign var=_fsSizes value=['small'=>['w'=>21,'h'=>16],'medium'=>['w'=>32,'h'=>24],'large'=>['w'=>43,'h'=>32]]}
{assign var=_fsDims value=$_fsSizes[$fsSize|default:'small']}
{assign var=_fsStyle value="width:{$_fsDims.w}px;line-height:1.6em;vertical-align:middle;border:1px solid #000"}
{assign var=_fsVal value=$fsValue|default:''}
{assign var=fsFlagCode value=$countryFlags[$_fsVal]|default:''}
<div class="bw-flag-select" id="{$fsId}">
	<input type="hidden" name="{$fsName}" value="{$_fsVal|escape}">
	<button type="button" class="bw-flag-trigger form-control" style="text-align:left;cursor:pointer">
		{if $fsFlagCode}<span class="fi fi-{$fsFlagCode}" style="{$_fsStyle};margin-right:6px"></span>{/if}<span class="bw-flag-label">{$countries[$_fsVal]|default:''|escape}</span>
		<span class="caret" style="float:right;margin-top:8px"></span>
	</button>
	<div class="bw-flag-dropdown panel panel-default" style="display:none;position:absolute;z-index:1050;min-width:300px">
		<div class="panel-body" style="padding:6px">
			<input type="text" class="bw-flag-search form-control input-sm" placeholder="{tr}Search{/tr}...">
		</div>
		<ul class="bw-flag-list list-unstyled" style="max-height:280px;overflow-y:auto;margin:0;padding:0 0 4px">
			<li data-value="" data-label="" style="padding:4px 10px"><em>{tr}None{/tr}</em></li>
			{foreach $countries as $code => $name}
				{assign var=fc value=$countryFlags[$code]|default:''}
				<li data-value="{$code|escape}" data-label="{$name|escape}" style="padding:3px 10px;cursor:pointer">
					{if $fc}<span class="fi fi-{$fc}" style="{$_fsStyle};margin-right:6px"></span>{/if}{$name|escape}
				</li>
			{/foreach}
		</ul>
	</div>
</div>
{literal}
<script>
(function($) {
	$(document).ready(function() {
		$('.bw-flag-select').each(function() {
			var $w = $(this), $input = $w.find('input[type=hidden]'),
				$trigger = $w.find('.bw-flag-trigger'), $label = $w.find('.bw-flag-label'),
				$dd = $w.find('.bw-flag-dropdown'), $search = $w.find('.bw-flag-search'),
				$items = $w.find('.bw-flag-list li');

			$trigger.on('click', function(e) {
				e.stopPropagation();
				$('.bw-flag-dropdown').not($dd).hide();
				$dd.toggle();
				if ($dd.is(':visible')) { $search.val('').trigger('input').focus(); }
			});

			$search.on('input', function() {
				var q = $(this).val().toLowerCase();
				$items.each(function() {
					$(this).toggle(!q || $(this).data('label').toLowerCase().indexOf(q) !== -1);
				});
			});

			$items.on('click', function() {
				var val = $(this).data('value'), lbl = $(this).data('label');
				$input.val(val);
				$label.text(lbl);
				var $fi = $(this).find('.fi');
				$trigger.find('.fi').remove();
				if ($fi.length) { $trigger.prepend($fi.clone().css('margin-right', '6px')); }
				$dd.hide();
			});

			$(document).on('click.bwflag', function() { $dd.hide(); });
			$dd.on('click', function(e) { e.stopPropagation(); });
		});
	});
}(jQuery));
</script>
{/literal}
