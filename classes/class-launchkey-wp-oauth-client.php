<?php

/**
 * OAuth client
 *
 * Client class for implementing LaunchKey authentication utilizing the LaunchKey OAuth API
 *
 * @package launchkey
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 * @since 1.0.0
 */
class LaunchKey_WP_OAuth_Client implements LaunchKey_WP_Client {

	/**
	 * @var LaunchKey_WP_Global_Facade
	 */
	private $wp_facade;

	/**
	 * @var LaunchKey_WP_Template
	 */
	private $template;

	/**
	 * @var bool
	 */
	private $is_multi_site;

	/**
	 * LaunchKey_WP_OAuth_Client constructor.
	 *
	 * @param LaunchKey_WP_Global_Facade $wp_facade
	 * @param LaunchKey_WP_Template $template
	 * @param bool $is_multi_site
	 * @param string $base_url
	 */
	public function __construct(
		LaunchKey_WP_Global_Facade $wp_facade,
		LaunchKey_WP_Template $template,
		$is_multi_site,
		$base_url = "https://oauth.launchkey.com"
	) {
		$this->wp_facade     = $wp_facade;
		$this->template      = $template;
		$this->is_multi_site = $is_multi_site;
		$this->base_url      = $base_url;
	}

	/**
	 * Register actions and callbacks with WP Engine
	 *
	 * @since 1.0.0
	 */
	public function register_actions() {
		$this->wp_facade->add_action( 'login_form', array( &$this, 'launchkey_form' ) );
		$this->wp_facade->add_action( 'wp_login', array( &$this, 'launchkey_pair' ), 1, 2 );
		$this->wp_facade->add_action( 'wp_logout', array( &$this, 'launchkey_logout' ), 1, 2 );
		$this->wp_facade->add_shortcode( 'launchkey_login', array( $this, 'launchkey_shortcode' ) );

		if ( $this->wp_facade->is_admin() ) {
			$this->register_admin_actions();
		}
	} //end register_actions

	/**
	 * Perform a LaucnhKey OAuth based logout
	 *
	 * @since 1.0.0
	 */
	public function launchkey_logout() {
		$options = $this->get_option();
		if ( isset( $_COOKIE['launchkey_access_token'] ) ) {
			$this->wp_facade->wp_remote_get(
				$this->base_url . '/logout?access_token=' . $_COOKIE['launchkey_access_token'],
				array(
					'httpversion' => '1.1',
					'sslverify'   => $options[ LaunchKey_WP_Options::OPTION_SSL_VERIFY ],
					'timeout'     => $options[ LaunchKey_WP_Options::OPTION_REQUEST_TIMEOUT ],
					'headers'     => array( 'Connection' => 'close' )
				)
			);
			$expire_time = $this->wp_facade->current_time( 'timestamp', true ) - 60;
			$this->wp_facade->setcookie( 'launchkey_user', '1', $expire_time, COOKIEPATH, COOKIE_DOMAIN );
			$this->wp_facade->setcookie( 'launchkey_access_token', '1', $expire_time, COOKIEPATH, COOKIE_DOMAIN );
			$this->wp_facade->setcookie( 'launchkey_refresh_token', '1', $expire_time, COOKIEPATH, COOKIE_DOMAIN );
			$this->wp_facade->setcookie( 'launchkey_expires', '1', $expire_time, COOKIEPATH, COOKIE_DOMAIN );
		}
	} //end launchkey_logout

	/**
	 * Function to render a {@see launchkey_form} via a WordPress short code
	 *
	 * [id="id-value" class="class-value" style="style-value" hide="true" ]
	 *
	 *   A hide value of "true" or the user being logged in will not show the form
	 *
	 * @link https://codex.wordpress.org/Shortcode_API
	 * @since 1.0.0
	 *
	 * @param array $atts
	 */
	public function launchkey_shortcode( $atts ) {
		$class = isset( $atts['class'] ) ? addslashes( $atts['class'] ) : '';
		$id    = isset( $atts['id'] ) ? addslashes( $atts['id'] ) : '';
		$style = isset( $atts['style'] ) ? addslashes( $atts['style'] ) : '';
		$hide  = isset( $atts['hide'] ) ? $atts['hide'] : '';

		if ( $hide != 'true' && ! $this->wp_facade->is_user_logged_in() ) {
			$this->launchkey_form( $class, $id, $style );
		}
	} //end launchkey_logout

	/**
	 * launchkey_form - login form for wp-login.php
	 *
	 * @since 1.0.0
	 *
	 * @param string $class A space separated list of classes to set on the "class" attribute of a containing DIV for the login button
	 * @param string $id The value to set on the "id" attribute of a containing DIV for the login button
	 * @param string $style A string of HTML style code tto set on the "style" attribute of a containing DIV for the login button
	 */
	public function launchkey_form( $class = '', $id = '', $style = '' ) {
		$options = $this->get_option();


		if ( isset( $_GET['launchkey_error'] ) ) {
			$this->wp_facade->_echo( $this->template->render_template( 'error', array(
				'error'   => 'Error!',
				'message' => 'The LaunchKey request was denied or an issue was detected during authentication. Please try again.'
			) ) );
		} elseif ( isset( $_GET['launchkey_ssl_error'] ) ) {
			$this->wp_facade->_echo( $this->template->render_template( 'error', array(
				'error'   => 'Error!',
				'message' => 'There was an error trying to request the LaunchKey servers. If this persists you may need to disable SSL verification.'
			) ) );
		} elseif ( isset( $_GET['launchkey_security'] ) ) {
			$this->wp_facade->_echo( $this->template->render_template( 'error', array(
				'error'   => 'Error!',
				'message' => 'There was a security issue detected and you have been logged out for your safety. Log back in to ensure a secure session.'
			) ) );
		}

		if ( isset( $_GET['launchkey_pair'] ) ) {
			$this->wp_facade->_echo( $this->template->render_template( 'auth-message', array(
				'alert'   => 'Almost finished!',
				'message' => 'Log in with your WordPress username and password for the last time to finish the user pair process. After this you can login exclusively with LaunchKey!'
			) ) );
		} else {

			$this->wp_facade->_echo( $this->template->render_template( 'launchkey-form', array(
				'class'               => $class,
				'id'                  => $id,
				'style'               => $style,
				'login_url'           => sprintf(
					'%s/authorize?client_id=%s&redirect_uri=%s',
					$this->base_url,
					$options[ LaunchKey_WP_Options::OPTION_ROCKET_KEY ],
					urlencode( $this->wp_facade->admin_url( 'admin-ajax.php?action=launchkey-callback' ) )
				),
				'login_text'          => 'Log in with',
				'login_with_app_name' => $options[ LaunchKey_WP_Options::OPTION_APP_DISPLAY_NAME ],
				'size'                => in_array( $this->wp_facade->get_locale(), array(
					'fr_FR',
					'es_ES'
				) ) ? 'small' : 'medium'
			) ) );
		}
	} //end launchkey_pair

	/**
	 * Method to handle redirects from the LaunchKey OAuth service
	 *
	 * '@since 1.0.0
	 */
	public function launchkey_callback() {
		/**
		 * If the service redirected with an error,
		 * or without an OAuth response code,
		 * or with an invalid OAuth response code,
		 * then redirect to the login page with an error
		 */
		if ( isset( $_GET['error'] ) || ! isset( $_GET['code'] ) || ! $this->is_valid_oauth_code( $_GET['code'] ) ) {
			return $this->wp_facade->wp_redirect( $this->wp_facade->wp_login_url() . "?launchkey_error=1" );
		}

		// Get an access/refresh token for the OAUth code
		$token_response = $this->get_token_for_code( $_GET['code'] );

		// If the response is an error, redirect to the login page with an "SSL" error
		if ( $this->wp_facade->is_wp_error( $token_response ) ) {
			return $this->wp_facade->wp_redirect( $this->wp_facade->wp_login_url() . "?launchkey_ssl_error=1" );
		} elseif ( ! $this->is_token_response_valid( $token_response ) ) {
			return $this->wp_facade->wp_redirect( $this->wp_facade->wp_login_url() . "?launchkey_error=1" );
		}


		$user_id = $this->get_user_id_by_launchkey_user_hash( $token_response['user'] );
		//Log the user in or send them to login form to pair their existing account.
		if ( $user_id ) {
			// If the user is already paired
			$this->wp_facade->wp_set_auth_cookie( $user_id, false );
			$this->login_user( $token_response['access_token'], $token_response['expires_in'],
				$token_response['refresh_token'] );
			$this->wp_facade->wp_redirect( $this->wp_facade->admin_url() );
		} else {
			// First Time Pair
			$this->login_user( $token_response['access_token'], $token_response['expires_in'],
				$token_response['refresh_token'] );
			$this->prepare_for_launchkey_pair( $token_response['user'], $token_response['access_token'],
				$token_response['expires_in'], $token_response['refresh_token'] );
		}
	} //end launchkey_callback

	/**
	 * launchkey_admin_callback - performed during admin_init action
	 *
	 */
	public function launchkey_admin_callback() {

		$options = $this->get_option();

		if ( isset( $_GET['launchkey_admin_pair'] ) ) {
			$user = $this->wp_facade->wp_get_current_user();
			$this->launchkey_pair( "", $user->data );
		}

		//check status of oauth access token
		if ( isset( $_COOKIE['launchkey_access_token'] ) ) {
			$args = array(
				'httpversion' => '1.1',
				'headers'     => array(
					'Authorization' => 'Bearer ' . $_COOKIE['launchkey_access_token'],
					'Connection'    => 'close'
				),
				'sslverify'   => $options[ LaunchKey_WP_Options::OPTION_SSL_VERIFY ],
				'timeout'     => $options[ LaunchKey_WP_Options::OPTION_REQUEST_TIMEOUT ]
			);

			$oauth_response  = $this->wp_facade->wp_remote_post( "{$this->base_url}/resource/ping", $args );
			$response_object =
				$oauth_response instanceof WP_Error ? null : json_decode( $oauth_response['body'], true );
			if ( $response_object && isset( $response_object['message'] ) ) {
				if ( $response_object['message'] != 'valid' ) {
					//refresh_token
					if ( isset( $_COOKIE['launchkey_refresh_token'] ) ) {
						//prepare data for access token
						$data = array(
							'httpversion' => '1.1',
							'body'        => array(
								'client_id'     => $options[ LaunchKey_WP_Options::OPTION_ROCKET_KEY ],
								'client_secret' => $options[ LaunchKey_WP_Options::OPTION_SECRET_KEY ],
								'redirect_uri'  => $this->wp_facade->admin_url(),
								'refresh_token' => $_COOKIE['launchkey_refresh_token'],
								'grant_type'    => "refresh_token"
							),
							'sslverify'   => $options[ LaunchKey_WP_Options::OPTION_SSL_VERIFY ],
							'timeout'     => $options[ LaunchKey_WP_Options::OPTION_REQUEST_TIMEOUT ],
							'headers'     => array( 'Connection' => 'close' )
						);

						//make oauth call
						$oauth_get =
							$this->wp_facade->wp_remote_post( "{$this->base_url}/access_token", $data );

						if ( ! $this->wp_facade->is_wp_error( $oauth_get ) ) {
							$oauth_response = json_decode( $oauth_get['body'], true );
						} else {
							$this->wp_facade->wp_logout();
							$this->wp_facade->wp_redirect( $this->wp_facade->wp_login_url() .
							                               "?launchkey_ssl_error=1" );

							return;
						}

						if ( isset( $oauth_response['refresh_token'] ) && isset( $oauth_response['access_token'] ) ) {
							$launchkey_access_token  = $oauth_response['access_token'];
							$launchkey_refresh_token = $oauth_response['refresh_token'];
							$timestamp               = $this->wp_facade->current_time( 'timestamp', true );
							$launchkey_expires       = $timestamp + $oauth_response['expires_in'];
							$cookie_expires          = $timestamp + ( 86400 * 30 );
							$this->wp_facade->setcookie( 'launchkey_access_token', $launchkey_access_token,
								$cookie_expires,
								COOKIEPATH, COOKIE_DOMAIN );
							$this->wp_facade->setcookie( 'launchkey_refresh_token', $launchkey_refresh_token,
								$cookie_expires,
								COOKIEPATH, COOKIE_DOMAIN );
							$this->wp_facade->setcookie( 'launchkey_expires', $launchkey_expires, $cookie_expires,
								COOKIEPATH,
								COOKIE_DOMAIN );
						} else {
							$this->wp_facade->wp_logout();
							$this->wp_facade->wp_redirect( $this->wp_facade->wp_login_url() . "?loggedout=1" );

							return;
						}
					} else {
						$this->wp_facade->wp_logout();
						$this->wp_facade->wp_redirect( $this->wp_facade->wp_login_url() . "?loggedout=1" );

						return;
					}
				}
			} else {
				$this->wp_facade->wp_logout();
				$this->wp_facade->wp_redirect( $this->wp_facade->wp_login_url() . "?launchkey_ssl_error=1" );

				return;
			}
		}
	} //end function launchkey_admin_callback

	/**
	 * launchkey_pair - pair a launchkey user with the WordPress user. performed during wp_login.
	 *
	 * @param mixed $not_used - required
	 * @param mixed $user
	 *
	 * @access public
	 * @return void
	 */
	protected function launchkey_pair( $not_used, $user ) {
		if ( isset( $_COOKIE['launchkey_user'] ) ) {
			if ( is_numeric( $user->ID ) && $user->ID > 0 && ctype_alnum( $_COOKIE['launchkey_user'] ) &&
			     strlen( $_COOKIE['launchkey_user'] ) > 10
			) {
				$this->wp_facade->update_user_meta( $user->ID, "launchkey_user", $_COOKIE['launchkey_user'] );
			}
		}
	}

	/**
	 * Register actions and callbacks with WP Engine for admin
	 */
	private function register_admin_actions() {
		$this->wp_facade->add_action( 'wp_ajax_launchkey-callback', array( $this, 'launchkey_callback' ) );
		$this->wp_facade->add_action( 'wp_ajax_nopriv_launchkey-callback', array( $this, 'launchkey_callback' ) );
		$this->wp_facade->add_action( 'admin_init', array( $this, 'launchkey_admin_callback' ) );
	}

	/**
	 * Is the provided code in the appropriate format for an OAuth response from the LaucnhKey OAuth service
	 *
	 * @param string $code
	 *
	 * @return bool
	 */
	private function is_valid_oauth_code( $code ) {
		return ctype_alnum( $code ) && strlen( $code ) === 64;
	}

	/**
	 * Exchange a valid OAuth response code for a token object
	 *
	 * @param $response_code
	 *
	 * @return array|WP_Error
	 */
	private function get_token_for_code( $response_code ) {
		$options = $this->get_option();

		//prepare request data for access token
		$data                  = array();
		$data['client_id']     = $options[ LaunchKey_WP_Options::OPTION_ROCKET_KEY ];
		$data['client_secret'] = $options[ LaunchKey_WP_Options::OPTION_SECRET_KEY ];
		$data['redirect_uri']  = $this->wp_facade->admin_url();
		$data['code']          = $response_code;
		$data['grant_type']    = "authorization_code";

		//make oauth call
		$params = http_build_query( $data );

		// Attempt to get an access token from the resposne code
		$oauth_get = $this->wp_facade->wp_remote_get( "{$this->base_url}/access_token?" . $params,
			array(
				'httpversion' => '1.1',
				'sslverify'   => $options[ LaunchKey_WP_Options::OPTION_SSL_VERIFY ],
				'timeout'     => $options[ LaunchKey_WP_Options::OPTION_REQUEST_TIMEOUT ],
				'headers'     => array( 'Connection' => 'close' )
			)
		);

		if ( $this->wp_facade->is_wp_error( $oauth_get ) ) {
			// If the response is an error, return the error
			$response = $oauth_get;
		} else {
			// Otherwise, decode the response
			$response = json_decode( $oauth_get['body'], true );
		}

		return $response;
	}

	/**
	 * @param $user_hash
	 *
	 * @return int
	 *
	 */
	private function get_user_id_by_launchkey_user_hash( $user_hash ) {
		//Match existing user to LaunchKey user
		$meta_args = array( 'meta_key' => 'launchkey_user', 'meta_value' => $user_hash );
		$users     = $this->wp_facade->get_users( $meta_args );

		$id = null;
		if ( ! empty( $users ) && is_array( $users ) ) {
			$user = array_shift( $users );
			if ( $user instanceof WP_User && $user->ID ) {
				$id = $user->ID;
			}
		}

		return $id;
	}

	/**
	 * @param $access_token
	 * @param $expires_in
	 * @param $refresh_token
	 */
	private function login_user( $access_token, $expires_in, $refresh_token ) {
		// Set up expiration for the auth and refresh tokens
		$timestamp = $this->wp_facade->current_time( 'timestamp', true );
		// The refresh token expires within 30 daya, allowing for refresh whnever appropriate
		$refresh_expires = $timestamp + ( 86400 * 30 );
		// launchkey_expires token expires when the access token expires
		$launchkey_expires = $timestamp + $expires_in;

		$this->wp_facade->setcookie( 'launchkey_access_token', $access_token, $refresh_expires, COOKIEPATH,
			COOKIE_DOMAIN );
		$this->wp_facade->setcookie( 'launchkey_refresh_token', $refresh_token, $refresh_expires, COOKIEPATH,
			COOKIE_DOMAIN );
		$this->wp_facade->setcookie( 'launchkey_expires', $launchkey_expires, $refresh_expires, COOKIEPATH,
			COOKIE_DOMAIN );
	}

	private function is_token_response_valid( array $token_response ) {
		$invalid = empty( $token_response['user'] ) ||
		           empty( $token_response['access_token'] ) ||
		           empty( $token_response['refresh_token'] ) ||
		           empty( $token_response['expires_in'] );

		return ! $invalid;
	}

	/**
	 * @param $launchkey_user_hash
	 */
	private function prepare_for_launchkey_pair( $launchkey_user_hash ) {
		// Set the pair cookie with the LaunchKey user hash
		$this->wp_facade->setcookie(
			'launchkey_user',
			$launchkey_user_hash,
			$this->wp_facade->current_time( 'timestamp', true ) + 300,
			COOKIEPATH,
			COOKIE_DOMAIN
		);

		// Redirect to finish pairing
		if ( ! $this->wp_facade->current_user_can( 'manage_options' ) ) {
			//not previously logged in
			$this->wp_facade->wp_redirect( $this->wp_facade->wp_login_url() . "?launchkey_pair=1" );
		} else {
			//previously authenticated
			$this->wp_facade->wp_redirect( $this->wp_facade->admin_url( "profile.php?launchkey_admin_pair=1&updated=1" ) );
		}
	}

	/**
	 * @return mixed
	 */
	private function get_option() {
		return $this->is_multi_site ? $this->wp_facade->get_site_option( LaunchKey_WP_Admin::OPTION_KEY ) :
			$this->wp_facade->get_option( LaunchKey_WP_Admin::OPTION_KEY );
	}
}
