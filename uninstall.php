<?php
/*
 * LaunchKey Uninstall - Securely remove all associated data.
 *
 * Uninstall will require new settings to be setup and the re-pairing of users if the plugin is re-installed in the future.
 */

//if uninstall not called from WordPress exit
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

require_once 'vendor/autoload.php';

//remove launchkey options
delete_option( LaunchKey_WP_Admin::OPTION_KEY );
delete_option( LaunchKey_WP_Configuration_Wizard::EASY_SETUP_OPTION );

//remove user pairings and auth data
delete_metadata( 'user', 0, 'launchkey_username',    '', true );
delete_metadata( 'user', 0, 'launchkey_user',        '', true );
delete_metadata( 'user', 0, 'launchkey_auth',        '', true );
delete_metadata( 'user', 0, 'launchkey_authorized',  '', true );
delete_metadata( 'user', 0, 'launchkey_sso_session', '', true );

// Drop sessions table
global $wpdb;
$table = $wpdb->prefix . "launchkey_sso_sessions";
$wpdb->query("DROP TABLE IF EXISTS {$table}");
