<?php
/**
 * Autologin
 *
 * Provide email messages with code for automatic login.
 * 
 * @package Autologin
 */

function autologin_init () {
	elgg_register_plugin_hook_handler('email', 'system', 'autologin_email_handler', 1000);

	elgg_register_plugin_hook_handler('cron', 'daily', 'autologin_remove_expired_user_tokens');

	// Set high priority because this has to be called before the default email save function.
	elgg_register_plugin_hook_handler('usersettings:save', 'user', 'autologin_usersettings_handler', 1);

	autologin_check();
}

/**
 * Add autologin token to urls found from email body.
 * 
 * @param string $hook
 * @param string $type
 * @param string $value
 * @param array $params
 */
function autologin_email_handler ($hook, $type, $value, $params) {
	$to = $params['to'];
	$from = $params['from'];
	$subject = $params['subject'];
	$body = $params['body'];

	$user = get_user_by_email($to);
	$user = $user[0];

	// Do not send tokens to admins
	if ($user->isAdmin()) {
		return null;
	}

	$url = elgg_get_site_url();
	
	// Escape regex control characters from the url
	$escaped_url = preg_replace(array('/\//', '/\./'), array('\/', '\.'), $url);

	// Search for urls in the email message body
	// Allowed url characters are [\w\d:#@%/;$()~_?\+-=\\\.&]
	preg_match_all("/($escaped_url)[\w\d:#@%\/\;\$()~_?\+=-\\\.&]*/", $body, $result);
	
	if (isset($result[0])) {
		// Function str_replace() replaces all occurrences of the
		// search string so we need to remove duplicates
		$matches = array_unique($result[0]);

		$token = autologin_create_token($user);

		// Add the token to each url found from message body
		foreach ($matches as $url) {
			// Check if url already has parameters
			$separator = "?";
			if (preg_match("/\?/", $url)) {
				$separator = "&";
			}
			$new_url = "{$url}{$separator}c=$token";

			// Replace the old url with the new one
			$body = str_replace($url, $new_url, $body);
		}

		$header_eol = "\r\n";
		if (isset($CONFIG->broken_mta) && $CONFIG->broken_mta) {
			// Allow non-RFC 2822 mail headers to support some broken MTAs
			$header_eol = "\n";
		}

		// Windows is somewhat broken, so we use just address for to and from
		if (strtolower(substr(PHP_OS, 0, 3)) == 'win') {
			// strip name from to and from
			if (strpos($to, '<')) {
				preg_match('/<(.*)>/', $to, $matches);
				$to = $matches[1];
			}
			if (strpos($from, '<')) {
				preg_match('/<(.*)>/', $from, $matches);
				$from = $matches[1];
			}
		}

		$headers = "From: $from{$header_eol}"
			. "Content-Type: text/plain; charset=UTF-8; format=flowed{$header_eol}"
			. "MIME-Version: 1.0{$header_eol}"
			. "Content-Transfer-Encoding: 8bit{$header_eol}";

		// Sanitise subject by stripping line endings
		$subject = preg_replace("/(\r\n|\r|\n)/", " ", $subject);
		if (is_callable('mb_encode_mimeheader')) {
			$subject = mb_encode_mimeheader($subject, "UTF-8", "B");
		}

		// Format message
		$body = html_entity_decode($body, ENT_COMPAT, 'UTF-8'); // Decode any html entities
		$body = elgg_strip_tags($body); // Strip tags from message
		$body = preg_replace("/(\r\n|\r)/", "\n", $body); // Convert to unix line endings in body
		$body = preg_replace("/^From/", ">From", $body); // Change lines starting with From to >From

		return mail($to, $subject, wordwrap($body), $headers);
	}

	// Don't do anything
	return $value;
}

/**
 * Obtain a token for a user.
 *
 * @param object $user ElggUser 
 *
 * @return bool
 */
function autologin_create_token ($user) {
	$site_guid = elgg_get_site_entity()->getGUID();
	$time = time();
	$token_code = md5(rand() . microtime() . $user->username . $time . $site_guid);
	
	elgg_set_ignore_access(true);
	
	$token = new ElggObject();
	$token->subtype = 'autologin_token';
	$token->owner_guid = $user->getGUID();
	$token->container_guid = $user->getGUID();
	$token->token = $token_code;
	// Prevent being visible for example in www.example.com/export/default/<guid>/
	$token->access_id = ACCESS_PRIVATE;
	$id = $token->save();

	if ($id) {
		$return = $token->token;
	} else {
		$return = false;
	}
	
	elgg_set_ignore_access(false);
	
	return $return;
}

/**
 * Check if user came to Elgg using an url with autologin token.
 * 
 * @return boolean
 */
function autologin_check () {
	if (!elgg_is_logged_in()) {
		global $CONFIG;

		$token = get_input('c');

		if (!$token) {
			return false;
		}

		$now = time();

		$expiry_days = (int) elgg_get_plugin_setting('expiry', 'autologin');
		$expiry = $now - (60*60*24*$expiry_days);

		$validity_hours = (int) elgg_get_plugin_setting('validity', 'autologin');
		$validity = $now - (60*60*$validity_hours);

		// Access is private so we'll have to ignore access
		$ia = elgg_set_ignore_access(true);
		$tokens = elgg_get_entities_from_metadata(array(
			'type' => 'object',
			'subtype' => 'autologin_token',
			'metadata_name_value_pairs' => array('token' => $token),
			'wheres' => array(
				"e.time_created > $expiry",
				"e.time_updated > $validity"
			),
		));
		elgg_set_ignore_access($ia);

		if (empty($tokens[0])) {
			// Token has most likely expired
			
			// @todo There is propably no need to view the message?
			//register_error(elgg_echo('autologin:error:expiredtoken'));
			return false;
		}
		
		$token = $tokens[0];
		$user = $token->getOwnerEntity();

		// Log in the user
		if (login($user)) {
			system_message(elgg_echo('autologin:message:success'));
			
			$validity_hours = (int) elgg_get_plugin_setting('validity', 'autologin');

			if (empty($validity_hours)) {
				// Remove token immediately
				$token->delete();
			} else {
				// Save timestamp of first use so we know when token becomes invalid
				if ($token->time_created === $token->time_updated) {
					$token->save();
				}
			}
		} else {
			// Fail if we couldn't log the user in
			return false;
		}

		return true;
	}
}

/**
 * Remove expired user tokens
 */
function autologin_remove_expired_user_tokens ($hook, $type, $return, $params) {
	$expiry_days = elgg_get_plugin_setting('expiry', 'autologin');
	$expiry = time() - (60*60*24*$expiry_days);

	elgg_set_ignore_access(true);

	// Get expired unused tokens
	$tokens = elgg_get_entities(array(
		'type' => 'object',
		'subtype' => 'autologin_token',
		'wheres' => array("e.time_created < $expiry"),
		'limit' => false,
	));

	// Delete tokens
	foreach ($tokens as $token) {
		$guid = $token->getGUID();

		if (!$token->delete()) {
			elgg_add_admin_notice('autologin', elgg_echo('autologin:cron:deletefailed', array($guid)));
		}
	}

	$validity_hours = (int) elgg_get_plugin_setting('validity', 'autologin');
	$validity = time() - (60*60*$validity_hours);
	
	// Get expired used tokens
	$tokens = elgg_get_entities(array(
		'type' => 'object',
		'subtype' => 'autologin_token',
		'wheres' => array("e.time_updated < $validity"),
		'limit' => false,
	));

	foreach ($tokens as $token) {
		$guid = $token->getGUID();

		// Delete tokens
		if (!$token->delete()) {
			elgg_add_admin_notice('autologin', elgg_echo('autologin:cron:deletefailed', array($guid)));
		}
	}
	
	elgg_set_ignore_access(false);
}

/**
 * Require password when changing email address.
 * 
 * If autologin token is accidentally exposed, this prevents the
 * perpetrator from gaining full control over the user account.
 */
function autologin_usersettings_handler ($hook, $type, $return, $params) {
	$email = get_input('email');
	$user_id = get_input('guid');
	$current_password = get_input('current_password');

	if (!$user_id) {
		$user = elgg_get_logged_in_user_entity();
	} else {
		$user = get_entity($user_id);
	}

	// Continue only if user is changing email
	if (!$email || $email === $user->email) {
		return null;
	}

	// Allow admins to change email
	if (elgg_is_admin_logged_in()) {
		return null;
	}

	// Require password
	if (!$current_password) {
		register_error(elgg_echo('autologin:error:passwordrequired'));
		// Plugin hook stacks can't be stopped so do a forward instead
		forward(REFERER);
	}

	// Check the password
	try {
		pam_auth_userpass(array(
			'username' => $user->username,
			'password' => $current_password
		));
	} catch (LoginException $e) {
		// Invalid password
		register_error(elgg_echo('user:password:fail:incorrect_current_password'));
		// Plugin hook stacks can't be stopped so do a forward instead
		forward(REFERER);
	}
}

elgg_register_event_handler('init', 'system', 'autologin_init');
