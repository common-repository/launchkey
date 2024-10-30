<?php
use RingCentral\Psr7\Request;
use RingCentral\Psr7\Response;

/**
 * @package launchkey
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 *
 * LaunchKey Native Client
 *
 * WordPress LaucnhKey client for handling native LaunchKey API interactions (non-OAuth).
 *
 * @since 1.0.0
 */
class LaunchKey_WP_Native_Client implements LaunchKey_WP_Client {

	/**
	 * @since 1.0.0
	 */
	const CALLBACK_AJAX_ACTION = 'launchkey-native-callback';

	/**
	 * @since 1.0.0
	 */
	const WHITE_LABEL_PAIR_ACTION = 'launchkey-whitelabel-pair';

	/**
	 * @var LaunchKey_WP_Global_Facade
	 */
	private $wp_facade;

	/**
	 * @var \LaunchKey\SDK\Client
	 */
	private $launchkey_client;

	/**
	 * @var LaunchKey_WP_Template
	 */
	private $template;

	/**
	 * @var string
	 */
	private $language_domain;

	/**
	 * @var WP_Error
	 */
	private $pair_error;

	/**
	 * @var boolean
	 */
	private $is_multi_site;
	/**
	 * @var
	 */
	private $multi_site;

	/**
	 * LaunchKey_WP_Native_Client constructor.
	 *
	 * @param \LaunchKey\SDK\Client $launchkey_client
	 * @param LaunchKey_WP_Global_Facade $wp_facade
	 * @param LaunchKey_WP_Template $template
	 * @param string $language_domain
	 * @param bool $is_multi_site
	 */
	public function __construct(
		LaunchKey\SDK\Client $launchkey_client,
		LaunchKey_WP_Global_Facade $wp_facade,
		LaunchKey_WP_Template $template,
		$language_domain,
		$is_multi_site
	) {
		$this->wp_facade        = $wp_facade;
		$this->launchkey_client = $launchkey_client;
		$this->template         = $template;
		$this->language_domain  = $language_domain;
		$this->is_multi_site    = $is_multi_site;
	}

	/**
	 * Register actions and callbacks with WP Engine
	 *
	 * @since 1.0.0
	 */
	public function register_actions() {
		$options = $this->get_option( LaunchKey_WP_Admin::OPTION_KEY );

		$this->wp_facade->add_action( 'login_form', array( $this, 'show_native_login_hint' ) );

		if ( LaunchKey_WP_Implementation_Type::WHITE_LABEL ===
		     $options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ]
		) {
			$this->wp_facade->add_action( 'login_form', array( $this, 'show_powered_by' ) );
		}

		// Add the progress bar to the login form so the user is aware that the login is processing while
		$this->wp_facade->add_action( 'login_form', array( $this, 'progress_bar' ) );

		// Register the authentication controller as the first filter in the chain
		$this->wp_facade->add_filter( 'authenticate', array( $this, 'authentication_controller' ), 0, 3 );

		// Place this at the end of the auth chain to only worry about users that are otherwise considered
		// authenticated
		$this->wp_facade->add_filter( 'init', array( $this, 'launchkey_still_authenticated_page_load' ), 999, 3 );

		// Register LaunchKey error codes as shake error codes to alert the user when authentication fails or errors
		$this->wp_facade->add_filter( 'shake_error_codes', array( $this, 'register_shake_error_codes' ) );

		$this->wp_facade->add_filter( 'wp_logout', array( $this, 'logout' ) );

		/**
		 * Jack into the WordPress heartbeat process to log the user out based on server side de-orbit events
		 * being processed.  The authentication check is performed on "heartbeat_send" filter so we ensure we verify
		 * before that by using the "heartbeat_received" filter.
		 *
		 * @see wp_ajax_heartbeat
		 */
		$this->wp_facade->add_filter( 'heartbeat_received', array( $this, 'launchkey_still_authenticated_heartbeat' ) );

		if ( $this->wp_facade->is_admin() ) {
			$this->register_admin_actions();
		}
	} //end register_actions

	/**
	 * @return mixed
	 */
	private function get_option( $key ) {
		return $this->is_multi_site ? $this->wp_facade->get_site_option( $key ) :
			$this->wp_facade->get_option( $key );
	}

	/**
	 * Register actions and callbacks with WP Engine for admin
	 */
	private function register_admin_actions() {
		$this->wp_facade->add_action(
			'wp_ajax_' . static::CALLBACK_AJAX_ACTION,
			array( $this, 'launchkey_callback' )
		);
		$this->wp_facade->add_action(
			'wp_ajax_nopriv_' . static::CALLBACK_AJAX_ACTION,
			array( $this, 'launchkey_callback' )
		);
		$this->wp_facade->add_action(
			'personal_options_update',
			array( $this, 'pair_callback' )
		);
		$this->wp_facade->add_action(
			'user_profile_update_errors',
			array( $this, 'pair_errors_callback' )
		);
		$this->wp_facade->add_action(
			'wp_ajax_' . static::WHITE_LABEL_PAIR_ACTION,
			array( $this, 'white_label_pair_callback' )
		);
		$this->wp_facade->add_action(
			'wp_ajax_nopriv_' . static::WHITE_LABEL_PAIR_ACTION,
			array( $this, 'white_label_pair_callback' )
		);
	}

	/**
	 * Login hint to be shown when non-OAuth is used
	 *
	 * @since 1.0.0
	 */
	public function show_native_login_hint() {
		$options = $this->get_option( LaunchKey_WP_Admin::OPTION_KEY );
		$this->wp_facade->_echo( $this->template->render_template( 'native-login-hint', array(
			'app_display_name' => $options[ LaunchKey_WP_Options::OPTION_APP_DISPLAY_NAME ]
		) ) );
	}

	/**
	 * Powered by LaunchKey HTML to be shown when white label app is used
	 *
	 * @since 1.0.0
	 */
	public function show_powered_by() {
		$this->wp_facade->_echo( $this->template->render_template( 'powered-by-launchkey' ) );
	}

	/**
	 * Display the "Processing Login" animation
	 *
	 * @since 1.0.0
	 */
	public function progress_bar() {
		$this->wp_facade->_echo( $this->template->render_template( 'progress-bar',
			array( 'processing' => 'Processing login' ) ) );
	}

	/**
	 * Add the LaunchKey error codes to the shake codes for the logon screen
	 *
	 * @param $shake_error_codes
	 *
	 * @return array
	 *
	 * @since 1.0.0
	 */
	public function register_shake_error_codes( $shake_error_codes ) {
		return array_merge( (array) $shake_error_codes, array(
			'launchkey_authentication_timeout',
			'launchkey_authentication_denied',
			'launchkey_authentication_error',
		) );
	}

	/**
	 * Authenticate us user via LaunchKey
	 *
	 * @param WP_User $user Unused user
	 * @param string $username
	 *
	 * @return null|WP_Error|WP_User
	 *
	 * @since 1.0.0
	 */
	public function launchkey_user_authentication( $user, $username ) {
		$response = null;

		// Get the user by their login name
		$user = $this->wp_facade->get_user_by( 'login', $username );


		if ( ! $user ) { // If not user, authentication fails
			$response = new WP_Error(
				'launchkey_authentication_denied',
				$this->wp_facade->__( 'Authentication denied!', $this->language_domain )
			);
		} elseif ( $user instanceof WP_User ) {
			// Authenticate user with the LaunchKey username determined via pair
			$authenticated = $this->authenticate_user( $user->ID, $user->launchkey_username );

			if ( $this->wp_facade->is_wp_error( $authenticated ) ) {
				// If an error is returned, use that for the response.  Rejecting the auth request is an error
				$response = $authenticated;
			} else {
				// Otherwise, the user accepted the request. Use the user as the response.
				$response = $user;
			}
		}

		// Return the response
		return $response;
	}

	/**
	 * @param $user_id
	 * @param $launchkey_username
	 *
	 * @return null|WP_Error
	 */
	private function authenticate_user( $user_id, $launchkey_username ) {
		// reset user authentication
		$this->reset_auth( $user_id );

		// Get the auth client from the SDK
		$auth = $this->launchkey_client->auth();
		try {
			// Authenticate and get the request ID
			$auth_request = $auth->authenticate( $launchkey_username )->getAuthRequestId();

			// Set the auth request ID in the user metadata to be available to the server side event
			$this->wp_facade->update_user_meta( $user_id, 'launchkey_auth', $auth_request );

			// Loop until a response has been recorded by the SSE callback
			do {
				// Sleep before checking for the response to not kill the server
				sleep( 1 );

				// See if the user has authorized
				$auth = $this->get_user_authorized( $user_id );
			} while ( null === $auth ); // If the response is null, continue the loop

			if ( $auth ) {
				// If the user accepted, return true
				$response = true;
			} else {
				// Otherwise, return an error
				$response = new WP_Error(
					'launchkey_authentication_denied',
					$this->wp_facade->__( 'Authentication denied!', $this->language_domain )
				);;
			}
		} catch ( Exception $e ) {
			// Process exceptions appropriately
			$response = new WP_Error();
			if ( $e instanceof \LaunchKey\SDK\Service\Exception\NoPairedDevicesError ) {
				$response->add(
					'launchkey_authentication_denied',
					$this->wp_facade->__( 'No Paired Devices!', $this->language_domain )
				);
			} elseif ( $e instanceof \LaunchKey\SDK\Service\Exception\NoSuchUserError ) {
				$response->add(
					'launchkey_authentication_denied',
					$this->wp_facade->__( 'Authentication denied!', $this->language_domain )
				);
			} elseif ( $e instanceof \LaunchKey\SDK\Service\Exception\RateLimitExceededError ) {
				$response->add(
					'launchkey_authentication_denied',
					$this->wp_facade->__( 'Authentication denied!', $this->language_domain )
				);
			} elseif ( $e instanceof \LaunchKey\SDK\Service\Exception\ExpiredAuthRequestError ) {
				$response->add(
					'launchkey_authentication_timeout',
					$this->wp_facade->__( 'Authentication denied!', $this->language_domain )
				);
			} else {
				if ( $this->wp_facade->is_debug_log() ) {
					$this->wp_facade->error_log( 'Error authenticating user with Launchkey: ' . $e->getMessage() );
				}
				$response->add(
					'launchkey_authentication_error',
					$this->wp_facade->__( 'Authentication error! Please try again later', $this->language_domain )
				);
			}
		}

		return $response;
	}

	/**
	 * @param $user_id
	 */
	private function reset_auth( $user_id ) {
		$this->wp_facade->update_user_meta( $user_id, 'launchkey_auth', null );
		$this->wp_facade->update_user_meta( $user_id, 'launchkey_authorized', null );
	}

	/**
	 * @param $user_id
	 *
	 * @return boolean
	 */
	private function get_user_authorized( $user_id ) {
		$db    = $this->wp_facade->get_wpdb();
		$value =
			$db->get_var( $db->prepare( "SELECT meta_value FROM $db->usermeta WHERE user_id = %s AND meta_key = 'launchkey_authorized' LIMIT 1",
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

	/**
	 * Front controller for LaunchKey Native/White Label authentication
	 *
	 *
	 * @param WP_User $user Unused parameter always passed first by authenticate filter
	 * @param string $username Username specified by the user in the login screen
	 * @param string $password Password specifiedby the user in the login screen
	 * @return null|WP_Error|WP_User Return WP_User if auth is successful, WP_Error if an error occurred, or null
	 * if no processing occurs.
	 *
	 * @since 1.0.0
	 */
	public function authentication_controller( $user, $username, $password ) {
		if ( $username && empty( $password ) ) {
			// If username and no password, user is attempting passwordless login

			// Find the user by login
			$user = $this->wp_facade->get_user_by( 'login', $username );

			// If we have a user and thatg user is paired
			if ( $user instanceof WP_User && $user->launchkey_username ) {
				return $this->launchkey_user_authentication( $user, $username );
			}
		} elseif ( ! $username && ! $password && $user = $this->wp_facade->wp_get_current_user() ) {
			// If no username or password and there is a current user, we are validating user is still logged in
			if ( $user && $user->launchkey_username && 'false' === $user->launchkey_authorized ) {
				$this->wp_facade->wp_logout();
			}
		}
	}

	/**
	 * handler for LaunchKey authentication
	 * @since 1.0.0
	 */
	public function launchkey_callback() {

		try {
			$headers = array();
			array_walk( $_SERVER, function ( $value, $key ) use ( &$headers ) {
				if ( preg_match( '/^HTTP\_(.+)$/', $key, $matches ) ) {
					$headers[ str_replace( '_', '-', $matches[1] ) ] = $value;
				}
			} );

			preg_match( '/^[^\/]+\/(.*)$/', $_SERVER['SERVER_PROTOCOL'], $matches );
			$protocol_version = $matches ? $matches[1] : null;

			$request = new Request(
				$_SERVER['REQUEST_METHOD'],
				$_SERVER['REQUEST_URI'],
				$headers,
				$this->wp_facade->fopen( 'php://input', 'rb' ),
				$protocol_version
			);

			$http_response = new Response();

			// Have the SDK client handle the callback
			$response = $this->launchkey_client->serverSentEvent()->handleEvent( $request, $http_response );

			if ( $response instanceof \LaunchKey\SDK\Domain\AuthResponse ) { // If this is an auth response

				// Find the user by the auth_request provided in the response
				$users = $this->wp_facade->get_users( array(
					'meta_key'   => 'launchkey_auth',
					'meta_value' => $response->getAuthRequestId()
				) );
				if ( count( $users ) > 1 ) {
					throw new \LaunchKey\SDK\Service\Exception\InvalidRequestError( 'Too many users found for user hash ' .
					                                                                $response->getUserHash() );
				} elseif ( count( $users ) < 1 ) {
					throw new \LaunchKey\SDK\Service\Exception\InvalidRequestError( 'No user found for user hash ' .
					                                                                $response->getUserHash() );
				}
				$user = array_pop( $users );

				// Update the auth value and the user hash in the user metadata based on response data
				$this->wp_facade->update_user_meta( $user->ID, "launchkey_authorized",
					$response->isAuthorized() ? 'true' : 'false' );
				$this->wp_facade->update_user_meta( $user->ID, "launchkey_user", $response->getUserHash() );

				// If this is a native implementation and we have a valid User Push ID in the response,
				// replace the username with that to prevent exposure of the username
				$options      = $this->get_option( LaunchKey_WP_Admin::OPTION_KEY );
				$user_push_id = $response->getUserPushId();
				if ( $user_push_id && LaunchKey_WP_Implementation_Type::NATIVE ===
				                      $options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ]
				) {
					$this->wp_facade->update_user_meta( $user->ID, "launchkey_username", $user_push_id );
				}
			} elseif ( $response instanceof \LaunchKey\SDK\Domain\DeOrbitCallback ) { // If it's a de-orbit request

				// Find the user by the provided user hash
				$users = $this->wp_facade->get_users( array(
					'meta_key'   => 'launchkey_user',
					'meta_value' => $response->getUserHash()
				) );
				if ( count( $users ) !== 1 ) {
					throw new \LaunchKey\SDK\Service\Exception\InvalidRequestError( 'Too many users found for user hash ' .
					                                                                $response->getUserHash() );
				}
				$user = array_pop( $users );

				// Set authorized to false in the user metadata
				$this->wp_facade->update_user_meta( $user->ID, "launchkey_authorized", 'false' );
				$this->launchkey_client->auth()->deOrbit( $user->launchkey_auth );

			}
		} catch ( \Exception $e ) {
			if ( $this->wp_facade->is_debug_log() ) {
				$this->wp_facade->error_log( 'Callback Exception: ' . $e->getMessage() );
			}
			if ( // If the request is invalid, return 400
				$e instanceof \LaunchKey\SDK\Service\Exception\InvalidRequestError ||
				$e instanceof \LaunchKey\SDK\Service\Exception\UnknownCallbackActionError
			) {
				$this->wp_facade->wp_die( 'Invalid Request', 400 );
			} else { // Otherwise, return 500
				$this->wp_facade->wp_die( 'Server Error', 500 );
			}
		}
	}

	/**
	 * Logout the user and perform a de-orbit if there is a known LaunchKey auth_request
	 *
	 * @since 1.0.0
	 */
	public function logout() {
		// If there is a current user
		if ( $user = $this->wp_facade->wp_get_current_user() ) {
			// And that user has logged in with LaunchKey
			if ( ! empty ( $user->launchkey_auth ) ) {
				try {
					// De-orbit the auth
					$this->launchkey_client->auth()->deOrbit( $user->launchkey_auth );
				} catch ( Exception $e ) {
					if ( $this->wp_facade->is_debug_log() ) {
						$this->wp_facade->error_log( 'LaunchKey Error on native client log out: ' . $e->getMessage() );
					}
				}
			}
			// Remove the aith data for the user
			$this->reset_auth( $user->ID );
		}
	}

	/**
	 * Complete the pairing process based on the authentication attempt
	 * Errors will displayed to the user by the pair_errors_callback
	 * @since 1.0.0
	 */
	public function pair_callback() {
		// launchkey_username in the post means it's a pairing attempt
		if ( array_key_exists( 'launchkey_username', $_POST ) ) {
			$user = $this->wp_facade->wp_get_current_user();

			// If there is no valid nonce, set the pair error
			if ( ! $this->wp_facade->wp_verify_nonce( $_POST['launchkey_nonce'],
				LaunchKey_WP_User_Profile::NONCE_KEY )
			) {
				$this->pair_error = new WP_Error( 'launchkey_pair_error',
					$this->wp_facade->__( 'Invalid nonce.  Please try again.', $this->language_domain ) );
			} elseif ( ! $user ) { // If there is no user, set the pair error
				$this->pair_error = new WP_Error( 'launchkey_pair_error',
					$this->wp_facade->__( 'You must me logged in to pair', $this->language_domain ) );
			} elseif ( ! $_POST['launchkey_username'] ) { // If the launchkey_username is blank, set the pair error
				$this->pair_error = new WP_Error( 'launchkey_pair_error',
					$this->wp_facade->__( 'Username is required to pair', $this->language_domain ) );
			} else { // Otherwise, attempt to pair the LaunchKey userusing the supplied launchkey_username
				$response = $this->authenticate_user( $user->ID, $_POST['launchkey_username'] );
				// If there was an error during the authentication process, set the pair error
				if ( $this->wp_facade->is_wp_error( $response ) ) {
					$this->pair_error = $response;
				}
			}
		}
	}

	/**
	 * Callback for use by the user_profile_update_errors action/filter.  It will add the error set by the pairing
	 * process to be displayed to the user.
	 *
	 * @since 1.0.0
	 *
	 * @param WP_Error $errors
	 */
	public function pair_errors_callback( WP_Error $errors ) {
		if ( $this->pair_error ) {
			$errors->add(
				$this->pair_error->get_error_code(),
				$this->pair_error->get_error_message(),
				$this->pair_error->get_error_data()
			);
		}
	}

	/**
	 * Callback handler to process white label pairing via AJAX
	 *
	 * @since 1.0.0
	 */
	public function white_label_pair_callback() {
		if ( isset( $_POST['nonce'] ) ) { // If there is no nonce, ignore the request
			if ( $this->wp_facade->wp_verify_nonce( $_POST['nonce'],
				LaunchKey_WP_User_Profile::NONCE_KEY )
			) { // If there is a valid nonce
				if ( $user = $this->wp_facade->wp_get_current_user() ) { // and a current logged in user
					try {
						// Create a LaunchKey White Label user with the WordPress username as the unique identifer
						$pair_response = $this->launchkey_client->whiteLabel()->createUser( $user->user_login );

						// Set the WordPress username as the LaunchKey username for subsequent login attempts
						$this->wp_facade->update_user_meta( $user->ID, 'launchkey_username', $user->user_login );

						// Set up the response with the QR Code URL and manual pairing codes
						$response = array(
							'qrcode' => $pair_response->getQrCodeUrl(),
							'code'   => $pair_response->getCode()
						);
					} catch ( \LaunchKey\SDK\Service\Exception\CommunicationError $e ) { // Communication error response
						$response =
							array( 'error' => 'There was a communication error encountered during the pairing process.  Please try again later' );
					} catch ( \LaunchKey\SDK\Service\Exception\InvalidCredentialsError $e ) { // Invalid credentials response
						$response =
							array( 'error' => 'There was an error encountered during the pairing process caused by a misconfiguration.  Please contact the administrator.' );
					} catch ( \Exception $e ) { // General error response
						$response =
							array( 'error' => 'There was an error encountered during the pairing process.  Please contact the administrator.' );
					}

					// Add a new nonce to the response to allow another request
					$response['nonce'] = $this->wp_facade->wp_create_nonce( LaunchKey_WP_User_Profile::NONCE_KEY );

					// Set the headers for the AJAX response
					$this->wp_facade->wp_send_json( $response );
				}
			}
		}
	}

	/**
	 * Init filter to see if a LaunchKey authenticated user has been de-orbited and log them out if that is the case
	 *
	 * @since 1.0.0
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
	 * @since 1.0.0
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

	/**
	 * Used only as a workaround in authentication_controller
	 * @see authentication_controller
	 * @codeCoverageIgnore
	 */
	public function null_method() {
		// Intentionally left blank
	}

	/**
	 * @return mixed
	 */
	private function update_option( $key ) {
		return $this->is_multi_site ? $this->wp_facade->update_site_option( $key ) :
			$this->wp_facade->update_option( $key );
	}
}