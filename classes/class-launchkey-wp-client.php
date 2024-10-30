<?php
/**
 * @package launchkey
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */
interface LaunchKey_WP_Client {
	/**
	 * Register actions and callbacks with WP Engine
	 */
	public function register_actions();
}