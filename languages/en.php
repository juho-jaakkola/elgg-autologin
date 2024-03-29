<?php

$english = array(
	'autologin:setting:expiry' => 'Days before unused autologin tokens expire',
	'autologin:setting:validity' => 'Hours that token is valid after using it (0 = token expires immediately)',
	'autologin:error:expiredtoken' => 'The token has expired. Please login manually.',
	'autologin:message:success' => 'Automatic login.',
	'autologin:cron:deletefailed' => 'Autologin: CRON failed to delete autologin token (metadata id %s).',
	'autologin:error:passwordrequired' => 'You need to provide your current password to change the email address.',
	'item:object:autologin_token' => 'Autologin token',
);

add_translation('en', $english);
