<?php

/**
 * @since 1.1.0
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */
class LaunchKey_WP_SSO_Client implements LaunchKey_WP_Client {

	/**
	 * @since 1.1.0
	 */
	const CALLBACK_AJAX_ACTION = 'launchkey-sso-callback';

	/**
	 * @var LaunchKey_WP_Global_Facade
	 */
	private $wp_facade;

	/**
	 * @var LaunchKey_WP_Template
	 */
	private $template;

	/**
	 * @var string
	 */
	private $entity_id;

	/**
	 * @var LaunchKey_WP_SAML2_Response_Service
	 */
	private $saml_response_service;

	/**
	 * @var LaunchKey_WP_SAML2_Request_Service
	 */
	private $saml_request_service;

	/**
	 * @var wpdb wpdb
	 */
	private $wpdb;

	/**
	 * @var string
	 */
	private $login_url;

	/**
	 * @var string
	 */
	private $logout_url;

	/**
	 * @var string
	 */
	private $error_url;

	/**
	 * @var bool
	 */
	private $is_multi_site;

	/**
	 * LaunchKey_WP_SSO_Client constructor.
	 *
	 * @param LaunchKey_WP_Global_Facade $wp_facade
	 * @param LaunchKey_WP_Template $template
	 * @param string $entity_id
	 * @param LaunchKey_WP_SAML2_Response_Service $saml_response_service Service providing SAML functionality
	 * @param LaunchKey_WP_SAML2_Request_Service $saml_request_service Service providing SAML functionality
	 * @param string $login_url URL to send user when logging in in via SSO
	 * @param string $logout_url URL to send user after logout when logged in via SSO
	 * @param string $error_url URL to send user when a login/logout error occurs
	 * @param bool $is_multi_site
	 */
	public function __construct(
		LaunchKey_WP_Global_Facade $wp_facade,
		LaunchKey_WP_Template $template,
		$entity_id,
		LaunchKey_WP_SAML2_Response_Service $saml_response_service,
		LaunchKey_WP_SAML2_Request_Service $saml_request_service,
		wpdb $wpdb,
		$login_url,
		$logout_url,
		$error_url,
		$is_multi_site
	) {
		$this->wp_facade             = $wp_facade;
		$this->template              = $template;
		$this->entity_id             = $entity_id;
		$this->saml_response_service = $saml_response_service;
		$this->saml_request_service  = $saml_request_service;
		$this->wpdb                  = $wpdb;
		$this->login_url             = $login_url;
		$this->logout_url            = $logout_url;
		$this->error_url             = $error_url;
		$this->is_multi_site         = $is_multi_site;
	}


	/**
	 * Register actions and callbacks with WP Engine
	 */
	public function register_actions() {
		$this->wp_facade->add_shortcode( 'launchkey_login', array( $this, 'launchkey_shortcode' ) );
		$this->wp_facade->add_action( 'login_form', array( &$this, 'launchkey_form' ) );

		// Register the authentication controller as the first filter in the chain
		$this->wp_facade->add_filter( 'authenticate', array( $this, 'authenticate' ), 0, 3 );
		// Register logout handler
		$this->wp_facade->add_filter( 'wp_logout', array( $this, 'logout' ) );

		// Place this at the end of the init chain to only worry about users that are otherwise considered
		// authenticated
		$this->wp_facade->add_filter( 'init', array( $this, 'launchkey_still_authenticated_page_load' ), 999, 3 );


		/**
		 * Jack into the WordPress heartbeat process to log the user out based on server side de-orbit events
		 * being processed.  The authentication check is performed on "heartbeat_send" filter so we ensure we verify
		 * before that by using the "heartbeat_received" filter.
		 *
		 * @see wp_ajax_heartbeat
		 */
		$this->wp_facade->add_filter( 'heartbeat_received', array( $this, 'launchkey_still_authenticated_heartbeat' ) );
	}


	/**
	 * Function to render a {@see launchkey_form} via a WordPress short code
	 *
	 * [id="id-value" class="class-value" style="style-value" hide="true" ]
	 *
	 *   A hide value of "true" or the user being logged in will not show the form
	 *
	 * @link https://codex.wordpress.org/Shortcode_API
	 * @since 1.1.0
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
	 * @since 1.1.0
	 *
	 * @param string $class A space separated list of classes to set on the "class" attribute of a containing DIV for the login button
	 * @param string $id The value to set on the "id" attribute of a containing DIV for the login button
	 * @param string $style A string of HTML style code tto set on the "style" attribute of a containing DIV for the login button
	 */
	public function launchkey_form( $class = '', $id = '', $style = '' ) {
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


		$container = SAML2_Utils::getContainer();
		$request   = new SAML2_AuthnRequest();
		$request->setId( $container->generateId() );
		$request->setDestination( $this->login_url );
		$request->setIssuer( $this->entity_id );
		$request->setRelayState( $this->wp_facade->admin_url() );
		$request->setAssertionConsumerServiceURL( $this->wp_facade->site_url('wp-login.php', 'login_post') );
		$request->setProtocolBinding( SAML2_Const::BINDING_HTTP_POST );
		$request->setIsPassive( false );
		$request->setNameIdPolicy( array(
			'Format'      => SAML2_Const::NAMEID_PERSISTENT,
			'AllowCreate' => true
		) );
		// Send it off using the HTTP-Redirect binding
		$binding = new SAML2_HTTPRedirect();
		$binding->setDestination( $this->login_url );
		$options = $this->is_multi_site ? $this->wp_facade->get_site_option( LaunchKey_WP_Admin::OPTION_KEY ) :
			$this->wp_facade->get_option( LaunchKey_WP_Admin::OPTION_KEY );

		$this->wp_facade->_echo( $this->template->render_template( 'launchkey-form', array(
			'class'               => $class,
			'id'                  => $id,
			'style'               => $style,
			'login_url'           => $binding->getRedirectURL( $request ),
			'login_text'          => 'Log in with',
			'login_with_app_name' => $options[ LaunchKey_WP_Options::OPTION_APP_DISPLAY_NAME ],
			'size'                => in_array( $this->wp_facade->get_locale(), array(
				'fr_FR',
				'es_ES'
			) ) ? 'small' : 'medium'
		) ) );
	}

	/**
	 * Front controller for LaunchKey Native/White Label authentication
	 *
	 *
	 * @param WP_User $user Unused parameter always passed first by authenticate filter
	 * @param string $username Username specified by the user in the login screen
	 * @param string $password Password specifiedby the user in the login screen
	 *
	 * @since 1.0.0
	 * @return WP_User
	 */
	public function authenticate( $user, $username, $password ) {
		if ( empty( $user ) && empty( $username ) && empty( $password ) ) {
			if ( ! empty( $_REQUEST['SAMLResponse'] ) ) {
				return $this->handle_saml_response( $_REQUEST['SAMLResponse'], $user );
			} elseif ( ! empty( $_REQUEST['SAMLRequest'] ) ) {
				return $this->handle_saml_request( $_REQUEST['SAMLRequest'] );
			}
		} elseif ( ! $username && ! $password && $user = $this->wp_facade->wp_get_current_user() ) {
			// If no username or password and there is a current user, we are validating user is still logged in
			if ( $user && $user->launchkey_username && 'false' === $user->launchkey_authorized ) {
				$this->wp_facade->wp_logout();
			}
		}
	}

	/**
	 * Method to handle redirects for logout of the LaunchKey SSO service
	 *
	 * '@since 1.1.0
	 */
	public function logout() {
		if ( $user = $this->wp_facade->wp_get_current_user() ) {
			$this->wp_facade->update_user_meta( $user->ID, 'launchkey_authorized', 'false' );
			// And that user has logged in with LaunchKey SSO
			if ( ! empty ( $user->launchkey_sso_session ) ) {
				// Reset the SSO session
				$this->wp_facade->update_user_meta( $user->ID, 'launchkey_sso_session', null );
				// Redirect to SSO logout
				$this->wp_facade->wp_redirect( $this->logout_url );
				$this->wp_facade->_exit();
			}
		}
	}

	/**
	 * Init filter to see if a LaunchKey authenticated user has been de-orbited and log them out if that is the case
	 *
	 * @since 1.2.0
	 */
	public function launchkey_still_authenticated_page_load() {
		/**
		 * If the current session
		 */
		if ( $this->wp_facade->is_user_logged_in() ) {
			// Get the current user
			$user = $this->wp_facade->wp_get_current_user();

			// If they have been de-authorized
			if ( false === $this->get_user_authorized( $user->ID ) ) {

				// Log out the user
				$this->wp_facade->wp_logout();

				// Reset the LaunchKey auth properties
				$this->reset_auth( $user->ID );

				$this->wp_facade->wp_redirect( $this->wp_facade->wp_login_url() );
				$this->wp_facade->_exit();
			}
		}
	}


	/**
	 * Hearbeat filter to see if a LaunchKey authenticated user has been de-orbited and log them out if that is the case
	 *
	 * @since 1.2.0
	 */
	public function launchkey_still_authenticated_heartbeat() {
		/**
		 * If the current session
		 */
		if ( $this->wp_facade->is_user_logged_in() ) {
			// Get the current user
			$user = $this->wp_facade->wp_get_current_user();

			// If they have been de-authorized
			if ( false === $this->get_user_authorized( $user->ID ) ) {

				// Log out the user
				$this->wp_facade->wp_logout();

				// Reset the LaunchKey auth properties
				$this->reset_auth( $user->ID );
			}
		}
	}

	private function translate_role( $role ) {
		static $role_synonyms = array( "admin" => "administrator" );

		return isset( $role_synonyms[ $role ] ) ? $role_synonyms[ $role ] : $role;
	}

	/**
	 * @param string saml_response
	 * @param WP_User $user
	 *
	 * @return WP_User
	 */
	private function handle_saml_response( $saml_response, $user ) {
		try {
			$this->saml_response_service->load_saml_response( $saml_response );
			if ( ! $this->saml_response_service->is_entity_in_audience( $this->entity_id ) ) {
				throw new Exception( sprintf( "Entity \"%s\" is not in allowed audience", $this->entity_id ) );
			} elseif ( ! $this->saml_response_service->is_timestamp_within_restrictions( $this->wp_facade->time() ) ) {
				throw new Exception( "Response has expired" );
			} elseif ( ! $this->saml_response_service->is_valid_destination( $this->get_login_post_url() ) ) {
				throw new Exception( "Invalid response destination" );
			} elseif ( $this->saml_response_service->is_session_index_registered() ) {
				throw new Exception( sprintf(
					"Session index %s already registered.  Possible replay attack.",
					$this->saml_response_service->get_session_index()
				) );
			}

			// Find the user by login
			$user = $this->wp_facade->get_user_by( 'login', $this->saml_response_service->get_name() );

			// If we don't have a user, create one
			if ( ! ( $user instanceof WP_User ) ) {
				$role      = $this->get_sso_attribute( 'role' );
				$role      = $role ? $this->translate_role( $role ) : false;
				$user_data = array(
					'user_login' => $this->saml_response_service->get_name(),
					'user_pass'  => '',
					'role'       => $role,
					'user_email' => $this->get_sso_attribute( 'user_email' ),
					'first_name' => $this->get_sso_attribute( 'first_name' ),
					'last_name'  => $this->get_sso_attribute( 'last_name' ),
				);
				$user_id   = $this->wp_facade->wp_insert_user( $user_data );
				// Unset the password - wp_insert_user always generates a hash - it's misleading
				$this->wp_facade->wp_update_user( array( 'ID' => $user_id, 'user_pass' => '' ) );
				$user = new WP_User( $user_id );
			}

			// Set the SSO session so we know we are logged in via SSO
			$this->wp_facade->update_user_meta( $user->ID, 'launchkey_sso_session',
				$this->saml_response_service->get_session_index() );
			$this->wp_facade->update_user_meta( $user->ID, 'launchkey_authorized',
				'true' );

			$this->saml_response_service->register_session_index();
		} catch ( Exception $e ) {
			$this->wp_facade->wp_redirect( $this->error_url );
			$this->wp_facade->_exit();
		};

		return $user;
	}

	/**
	 * @param string $saml_request
	 *
	 * @return null
	 *
	 * @since 1.1.0
	 */
	private function handle_saml_request( $saml_request ) {
		$this->saml_request_service->load_saml_request( $saml_request );
		if ( ! $this->saml_request_service->is_timestamp_within_restrictions( $this->wp_facade->time() ) ) {
			$this->wp_facade->wp_die( 'Invalid Request', 400 );
		} elseif ( ! $this->saml_request_service->is_valid_destination( $this->get_login_post_url() ) ) {
			$this->wp_facade->wp_die( 'Invalid Request', 400 );
		} elseif ( ! $user = $this->wp_facade->get_user_by( 'login', $this->saml_request_service->get_name() ) ) {
			$this->wp_facade->wp_die( 'Invalid Request', 400 );
		} elseif ( $this->saml_request_service->get_session_index() != $user->get( "launchkey_sso_session" ) ) {
			$this->wp_facade->wp_die( 'Invalid Request', 400 );
		} else {
			$this->wp_facade->update_user_meta( $user->ID, 'launchkey_authorized', 'false' );
		}
	}

	/**
	 * @param $user_id
	 */
	private function reset_auth( $user_id ) {
		$this->wp_facade->update_user_meta( $user_id, 'launchkey_sso_session', null );
		$this->wp_facade->update_user_meta( $user_id, 'launchkey_authorized', null );
	}

	/**
	 * @param $user_id
	 *
	 * @return boolean
	 */
	private function get_user_authorized( $user_id ) {
		$value =
			$this->wpdb->get_var( $this->wpdb->prepare( "SELECT meta_value FROM {$this->wpdb->usermeta} WHERE user_id = %s AND meta_key = 'launchkey_authorized' LIMIT 1",
				$user_id ) );
		if ( 'true' === $value ) {
			$authorized = true;
		} elseif ( 'false' === $value ) {
			$authorized = false;
		} else {
			$authorized = null;
		}

		return $authorized;
	}

	private function get_sso_attribute( $key ) {
		$values = $this->saml_response_service->get_attribute( $key );

		return $values ? $values[0] : null;
	}

	/**
	 * @return string
	 */
	private function get_login_post_url() {
		return $this->wp_facade->site_url('wp-login.php', 'login_post');
	}
}