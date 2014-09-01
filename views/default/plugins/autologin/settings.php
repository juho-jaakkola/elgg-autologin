<?php

$expiry_label = elgg_echo('autologin:setting:expiry');
$expiry_input = elgg_view('input/text', array(
	'name' => 'params[expiry]',
	'value' => $vars['entity']->expiry,
));

$validity_label = elgg_echo('autologin:setting:validity');
$validity_input = elgg_view('input/text', array(
	'name' => 'params[validity]',
	'value' => $vars['entity']->validity,
));

echo <<<HTML
	<div>
		<label>$expiry_label</label>
		$expiry_input
	</div>
	<div>
		<label>$validity_label</label>
		$validity_input
	</div>
HTML;
