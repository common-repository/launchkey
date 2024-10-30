<?php
/*
  Plugin Name: LaunchKey
  Plugin URI: https://wordpress.org/plugins/launchkey/
  Description:  DEPRECATED: On March 1, 2018, this WordPress plugin will be deprecated along with other LaunchKey SDKs, services, and resources that leverage versions v1 / v2 of the LaunchKey API. To avoid a service disruption, you must disable and uninstall your LaunchKey WordPress plugin prior to March 1. For more information, see: https://www.iovation.com/launchkey-legacy-deprecation.
  Version: 1.4.6
  Author: iovation, Inc.
  Text Domain: launchkey
  Author URI: https://launchkey.com
  License: GPLv2 Copyright (c) 2017 iovation, Inc.
 */

/**
 * Base URL for the LaunchKey API. Only change this if you have been instructed to by either iovation support or an
 * iovation integration engineer. Changing this to an incorrect value will prevent the Plugin from working.
 */
$launchkey_api_base_url = "https://api.launchkey.com";

/**
 * !!! WARNING !!! WARNING !!! WARNING !!! WARNING !!! WARNING !!! WARNING !!!
 *
 * Changing this value to false will make your site vulnerable to Man-in-the-Middle attacks.
 * @see https://en.wikipedia.org/wiki/Man-in-the-middle_attack
 *
 * An alternative to changing this would be to update your CA bundle file located at
 * "wp-includes/certificates/ca-bundle.crt". The easiest way to do this is to update WordPress itself.
 *
 * !!! WARNING !!! WARNING !!! WARNING !!! WARNING !!! WARNING !!! WARNING !!!
 */
$validate_ssl_certificates = true;


/**
 * Load the auto-loader for PSR0/4 based dependencies
 * @see http://www.php-fig.org/psr/psr-0/
 * @see http://www.php-fig.org/psr/psr-4/
 */
require_once __DIR__ . '/vendor/autoload.php';

/**
 * Configure AES encryption that will be used for encrypting and decrypting the secret settings for the LaunchKey
 * WordPress Plugin. Changing this value after configuring the LaunchKey WordPress plugin will invalidate its
 * configuration as it will no longer be able to decrypt its configuration.
 */
$crypt_aes = new \phpseclib\Crypt\AES();

/**
 * Use an MD5 hash of the auth key as the crypto key.  The crypto key is used as it would normally affect all auth
 * procedures as it is used as a salt for passwords.  An md5 hash is used as it will be a constant value based on
 * the AUTH_KEY but guaranteed to be exactly thirty-two (32) characters as is needed by AES-CBC-256 encryption.
 */
$crypt_aes->setKey( md5( AUTH_KEY ) );

/**
 * The "facade" is used to make global functions testable in an effort to provide quality code without backwards
 * compatibility breaks
 */
$facade = new LaunchKey_WP_Global_Facade();

/**
 * Make the global database variable available to be passed to the bootstrap.
 */
global $wpdb;

/**
 * Bootstraps the plugin
 */
$bootstrap = new LaunchKey_WP_Bootstrap(
		$wpdb,
		$facade,
		$crypt_aes,
		$launchkey_api_base_url,
		$validate_ssl_certificates,
		__FILE__
);
$bootstrap->run();
