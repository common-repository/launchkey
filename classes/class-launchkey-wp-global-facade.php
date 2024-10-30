<?php

/**
 * @package launchkey
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 *
 * WordPress facade encapsulating global functions
 *
 * The class is used to provide a mockable object for testing within other classes in the plugin.
 *
 * @since 1.0.0
 *
 * @method null add_action() add_action( string $tag, callback $function_to_add, int $priority = 10, int $accepted_args = 1 )
 * @method null add_filter() add_filter( string $tag, callback $function_to_add, int $priority = 10, int $accepted_args = 1 )
 * @method null remove_all_filters() remove_all_filters( string $tag, mixed $priority = false )
 * @method bool is_user_logged_in()
 * @method bool is_admin()
 * @method string plugin_basename() plugin_basename( string $file )
 * @method bool load_plugin_textdomain() load_plugin_textdomain( string $domain, string $deprecated = false, string $plugin_rel_path = false )
 * @method int|string current_time() current_time( string $type, bool $gmt )
 *
 * @method array get_users() get_users( array $args = array() )
 * @method WP_User wp_get_current_user() wp_get_current_user()
 * @method int|WP_Error wp_update_user() wp_update_user( mixed $userdata )
 * @method mixed get_user_meta() get_user_meta( int $user_id, string $key = '', bool $single = false )
 * @method int|bool update_user_meta() update_user_meta( int $user_id, string $meta_key, mixed $meta_value, mixed $prev_value = '' )
 * @method bool delete_user_meta() delete_user_meta( int $user_id, string $meta_key, mixed $meta_value = '' )
 * @method null wp_set_auth_cookie( int $user_id, bool $remember = false, mixed $secure = '' )
 * @method string wp_create_nonce() wp_create_nonce( string $action = - 1 )
 * @method bool|int wp_verify_nonce() wp_verify_nonce( string $nonce, string $action = - 1 )
 * @method bool current_user_can() current_user_can( string $capability )
 * @method null wp_logout() wp_logout()
 * @method WP_User get_user_by() get_user_by( string $field, mixed $value )
 *
 * @method mixed get_option() get_option( string $option, mixed $default = false )
 * @method mixed get_network_option() get_network_option( string $option, mixed $default = false )
 * @method mixed get_site_option() get_site_option( string $option, mixed $default = false )

 * @method bool add_option() add_option( string $option, mixed $value = '', string $deprecated = '', string $autoload = 'yes' )
 * @method bool update_option() update_option( string $option, mixed $value, string $autoload = null )
 * @method bool update_site_option() update_site_option( string $option, mixed $value, string $autoload = null )
 * @method bool delete_option() delete_option( string $option )
 * @method null register_setting() register_setting( string $option_group, string $option_name, callable $sanitize_callback = '' )
 *
 * @method null add_shortcode() add_shortcode( string $tag, callable $func )
 * @method array shortcode_atts() shortcode_atts( array $pairs, array $atts, string $shortcode = '' )
 * @method null add_settings_section() add_settings_section( string $id, string $title, string $callback, string $page )
 * @method bool|string add_options_page() add_options_page( string $page_title, string $menu_title, string $capability, string $menu_slug, callback $function = '' )
 * @method string _e() _e( string $text, string $domain = 'default' )
 * @method string __() __( string $text, string $domain = 'default' )
 *
 * @method bool wp_redirect() wp_redirect( string $location, int $status = 302 )
 * @method string wp_login_url() wp_login_url( string $redirect = '', bool $force_reauth = false )
 * @method string admin_url() admin_url( string $path = '', string $scheme = 'admin' )
 * @method string wp_guess_url wp_guess_url()
 * @method null wp_die() wp_die ( mixed $message = '', mixed $title = '', mixed $args = array() )
 * @method null wp_send_json() wp_send_json ( mixed $response )
 *
 * @method WP_Error|array wp_remote_get() wp_remote_get( string $url, array $args = array() )
 * @method WP_Error|array wp_remote_request() wp_remote_request( string $url, array $args = array() )
 *
 * @method null _echo() echo ( string $text )
 * @method bool setcookie() setcookie( string $name, string $value = null, int $expire = 0, string $path = null, string $domain = null, bool $secure = false, bool $httponly = false )
 * @method null wp_enqueue_style() wp_enqueue_style( string $handle, mixed $src = false, array $deps = array(), mixed $ver = false, string $media = 'all' )
 * @method string plugins_url() plugins_url( string $path = '', string $plugin = '' )
 * @method bool is_wp_error() is_wp_error( mixed $thing )
 * @method null add_settings_error() add_settings_error( string $setting, string $code, string $message, string $type = 'error' )
 * @method null add_settings_field() add_settings_field( string $id, string $title, callable $callback, string $page, string $section = 'default', array $args = array() )
 * @method bool is_multisite() is_multisite()
 * @method string dirname() dirname( string $dir )
 * @method string wp_hash_password() wp_hash_password( string $password )
 */
class LaunchKey_WP_Global_Facade {
	/**
	 * Wrapper for native PHP echo command.
	 *
	 * The wrapper will simply call the native PHP echo command.  It exists for testability.  It is preceded by an
	 * underscore as "echo" is a reserved word and could not be used for the method name.
	 *
	 * @since 1.0.0
	 * @see echo
	 *
	 * Get the current language
	 * @return null|string
	 */
	public function _echo( $text ) {
		echo $text;
	}

	/**
	 * Wrapper for native PHP exit command.
	 *
	 * The wrapper will simply call the native PHP exit command.  It exists for testability.  It is preceded by an
	 * underscore as "exit" is a reserved word and could not be used for the method name.
	 *
	 * @since 1.0.0
	 * @see exit
	 *
	 * @codeCoverageIgnore
	 */
	public function _exit() {
		exit();
	}

	/**
	 * Wrapper for native WordPress settings_fields function.
	 *
	 * The wrapper will capture and return the output from the native settings_fields function.
	 *
	 * @since 1.0.0
	 * @see settings_fields
	 *
	 * @param $option_group
	 *
	 * @return string
	 */
	public function settings_fields( $option_group ) {
		$data = '';
		ob_start( function ( $buffer ) use ( &$data ) {
			$data .= $buffer;
		} );
		settings_fields( $option_group );
		ob_end_clean();

		return $data;
	}

	/**
	 * Wrapper for native WordPress settings_errors function.
	 *
	 * The wrapper will capture and return the output from the native settings_errors function.
	 *
	 * @since 1.0.0
	 * @see settings_errors
	 *
	 * @param string $setting slug title of a specific setting who's errors you want.
	 * @param bool $sanitize Whether to re-sanitize the setting value before returning errors.
	 * @param bool $hide_on_update If set to true errors will not be shown if the settings page has already been
	 * submitted.
	 *
	 * @return string
	 */
	public function settings_errors( $setting = '', $sanitize = false, $hide_on_update = false ) {
		$data = '';
		ob_start( function ( $buffer ) use ( &$data ) {
			$data .= $buffer;
		} );
		settings_errors( $setting, $sanitize, $hide_on_update );
		ob_end_clean();

		return $data;
	}

	/**
	 * Wrapper for native WordPress do_settings_sections function.
	 *
	 * The wrapper will capture and return the output from the native do_settings_sections function.
	 *
	 * @since 1.0.0
	 * @see do_settings_sections
	 *
	 * @param $page
	 *
	 * @return string
	 */
	public function do_settings_sections( $page ) {
		$data = '';
		ob_start( function ( $buffer ) use ( &$data ) {
			$data .= $buffer;
		} );
		do_settings_sections( $page );
		ob_end_clean();

		return $data;
	}

	/**
	 * Wrapper for native WordPress submit_button function.
	 *
	 * The wrapper will capture and return the output from the native submit_button function.
	 *
	 * @since 1.0.0
	 * @see submit_button
	 *
	 * @param null $text
	 * @param string $type
	 * @param string $name
	 * @param bool $wrap
	 * @param null $other_attributes
	 *
	 * @return string
	 */
	public function submit_button(
		$text = null,
		$type = 'primary',
		$name = 'submit',
		$wrap = true,
		$other_attributes = null
	) {
		$data = '';
		ob_start( function ( $buffer ) use ( &$data ) {
			$data .= $buffer;
		} );
		submit_button( $text, $type, $name, $wrap, $other_attributes );
		ob_end_clean();

		return $data;
	}

	/**
	 * Get the WordPress database object
	 *
	 * @since 1.0.0
	 * @return wpdb
	 * @global $wpdb
	 */
	public function get_wpdb() {
		global $wpdb;

		return $wpdb;
	}

	/**
	 * Default facade method
	 *
	 * Directly calls the global method without any change to input or output
	 *
	 * @param string $name Method name
	 * @param array $arguments Method arguments
	 *
	 * @return mixed
	 *
	 * @since 1.0.0
	 */
	public function __call( $name, array $arguments = array() ) {
		return call_user_func_array( $name, $arguments );
	}

	/**
	 * Clear the settings errors
	 *
	 * Allows for clearing of settings errors.
	 *
	 * @since 1.0.0
	 */
	public function clear_settings_errors() {
		global $wp_settings_errors;
		$wp_settings_errors = array();
	}

	/**
	 * Get the hook suffix
	 *
	 * @link https://codex.wordpress.org/Administration_Menus#Page_Hook_Suffix
	 *
	 * @return string
	 *
	 * @since 1.0.0
	 */
	public function get_hook_suffix() {
		global $hook_suffix;

		return $hook_suffix;
	}

	/**
	 * Is WordPress in debug log mode?
	 *
	 * @return bool
	 *
	 * @since 1.0.0
	 */
	public function is_debug_log() {
		return defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG;
	}
}
