<?php
use RingCentral\Psr7\Request;
use RingCentral\Psr7\Response;

/**
 * Plugin Configuration Wizard
 *
 * Wizard to walk a WordPress administrator through configuring and verifying the LaunchKey
 * WordPress plugin.
 *
 * @package launchkey
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 * @since 1.0.0
 */
class LaunchKey_WP_Configuration_Wizard {
	/**
	 * Action name for AJAX callback used to verify native implementation configurations
	 *
	 * @since 1.0.0
	 */
	const VERIFY_CONFIG_AJAX_ACTION = 'launchkey-config-wizard-verify';

	/**
	 * Action name for AJAX callback used to submit config data for wizard
	 *
	 * @since 1.0.0
	 */
	const DATA_SUBMIT_AJAX_ACTION = 'launchkey-config-wizard-data-submit';

	/**
	 * Nonce key for the verifier
	 *
	 * @since 1.0.0
	 */
	const VERIFIER_NONCE_KEY = 'launchkey-config-verifier-nonce';

	/**
	 * Nonce key for the wizard
	 *
	 * @since 1.0.0
	 */
	const WIZARD_NONCE_KEY = 'launchkey-config-wizard-nonce';

	/**
	 * Action name for the action that generates QR code
	 *
	 * @since 1.4.0
	 */
	const QR_CODE_ACTION = 'launchkey-config-wizard-qr-code';

	/**
	 * Option name for "Easy Config" options
	 *
	 * @see https://codex.wordpress.org/Options_API
	 * @since 1.4.0
	 */
	const EASY_SETUP_OPTION = 'launchkey-easy-setup';

	/**
	 * @var LaunchKey_WP_Admin
	 */
	public $admin;

	/**
	 * @var LaunchKey_WP_Global_Facade
	 */
	private $wp_facade;

	/**
	 * @var \LaunchKey\SDK\Client
	 */
	private $launchkey_client;

	/**
	 * @var bool Is the site a network installation
	 */
	private $is_multi_site;

	/**
	 * LaunchKey_WP_Configuration_Wizard constructor.
	 *
	 * @param LaunchKey_WP_Global_Facade $wp_facade
	 * @param LaunchKey_WP_Admin $admin
	 * @param \LaunchKey\SDK\Service\CryptService $crypt_service
	 * @param bool $is_multi_site
	 * @param \LaunchKey\SDK\Client $launchkey_client
	 */
	public function __construct(
		LaunchKey_WP_Global_Facade $wp_facade,
		LaunchKey_WP_Admin $admin,
		\LaunchKey\SDK\Service\CryptService $crypt_service,
		$is_multi_site,
		\LaunchKey\SDK\Client $launchkey_client = null
	) {
		$this->wp_facade        = $wp_facade;
		$this->admin            = $admin;
		$this->launchkey_client = $launchkey_client;
		$this->crypt_service    = $crypt_service;
		$this->is_multi_site    = $is_multi_site;
	}

	/**
	 * Register actions for the wizard with WordPress
	 *
	 * @since 1.0.0
	 */
	public function register_actions() {
		$this->wp_facade->add_action(
			'wp_ajax_' . static::VERIFY_CONFIG_AJAX_ACTION,
			array( $this, 'verify_configuration_callback' )
		);
		$this->wp_facade->add_action(
			'wp_ajax_' . static::DATA_SUBMIT_AJAX_ACTION,
			array( $this, 'wizard_submit_ajax' )
		);
		$this->wp_facade->add_action(
			'wp_ajax_' . static::QR_CODE_ACTION,
			array( $this, 'wizard_easy_setup_qr_code' )
		);
		$this->wp_facade->add_action(
			'wp_ajax_nopriv_' . LaunchKey_WP_Native_Client::CALLBACK_AJAX_ACTION,
			array( $this, 'wizard_easy_setup_callback' )
		);
		$this->wp_facade->add_filter( 'init', array( $this, 'enqueue_verify_configuration_script' ) );
		$this->wp_facade->add_filter( 'init', array( $this, 'enqueue_scripts' ) );
	}

	/**
	 * @since 1.0.0
	 */
	public function verify_configuration_callback() {
		if ( isset( $_REQUEST['nonce'] ) &&
		     $this->wp_facade->wp_verify_nonce( $_REQUEST['nonce'], static::VERIFIER_NONCE_KEY ) &&
		     $this->wp_facade->current_user_can( 'manage_options' )
		) {
			$user     = $this->wp_facade->wp_get_current_user();
			$response = array( 'nonce' => $this->wp_facade->wp_create_nonce( static::VERIFIER_NONCE_KEY ) );
			if ( stripos( $_SERVER['REQUEST_METHOD'], 'POST' ) !== false && isset( $_POST['verify_action'] ) &&
			     'pair' === $_POST['verify_action']
			) {
				try {
					$white_label_user        = $this->launchkey_client->whiteLabel()->createUser( $user->user_login );
					$response['qrcode_url']  = $white_label_user->getQrCodeUrl();
					$response['manual_code'] = $white_label_user->getCode();
				} catch ( Exception $e ) {
					$response['error'] = $e->getCode();
				}
			} elseif ( stripos( $_SERVER['REQUEST_METHOD'], 'POST' ) !== false ) {
				$response['completed'] = false;
				try {
					$username     = empty ( $_POST['username'] ) ? $user->user_login : $_POST['username'];
					$auth_request = $this->launchkey_client->auth()->authorize( $username );
					$this->wp_facade->update_user_meta( $user->ID, 'launchkey_username', $username );
					$this->wp_facade->update_user_meta( $user->ID, 'launchkey_auth',
						$auth_request->getAuthRequestId() );
					$this->wp_facade->update_user_meta( $user->ID, 'launchkey_authorized', null );
				} catch ( Exception $e ) {
					$response['error'] = $e->getCode();
				}
			} else {
				$db                    = $this->wp_facade->get_wpdb();
				$value                 =
					$db->get_var( $db->prepare( "SELECT meta_value FROM $db->usermeta WHERE user_id = %s AND meta_key = 'launchkey_authorized' LIMIT 1",
						$user->ID ) );
				$response['completed'] = ! empty( $value );
			}
			$this->wp_facade->wp_send_json( $response );
		}
	}

	/**
	 * @since 1.0.0
	 */
	public function enqueue_verify_configuration_script() {
		if ( $this->wp_facade->current_user_can( 'manage_options' ) ) {
			$options = $this->get_option( LaunchKey_WP_Admin::OPTION_KEY );
			$this->wp_facade->wp_enqueue_script(
				'launchkey-config-verifier-native-script',
				$this->wp_facade->plugins_url( '/public/launchkey-config-verifier.js', dirname( __FILE__ ) ),
				array( 'jquery' ),
				'1.0.0',
				true
			);

			$this->wp_facade->wp_localize_script(
				'launchkey-config-verifier-native-script',
				'launchkey_verifier_config',
				array(
					'url'                 => $this->wp_facade->admin_url( 'admin-ajax.php?action=' .
					                                                      static::VERIFY_CONFIG_AJAX_ACTION ),
					'nonce'               => $this->wp_facade->wp_create_nonce( static::VERIFIER_NONCE_KEY ),
					'implementation_type' => $options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ],
					'is_configured'       => $this->is_plugin_configured( $options ),
				)
			);
		}
	}

	private function get_option( $key ) {
		return $this->is_multi_site ? $this->wp_facade->get_site_option( $key ) : $this->wp_facade->get_option( $key );
	}

	/**
	 * @param $options
	 *
	 * @return bool
	 */
	private function is_plugin_configured( $options ) {
		$is_configured =
			( $options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ] === LaunchKey_WP_Implementation_Type::SSO
			  && ! empty( $options[ LaunchKey_WP_Options::OPTION_SSO_ENTITY_ID ] ) )
			|| ( $options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ] !== LaunchKey_WP_Implementation_Type::SSO
			     && ! empty( $options[ LaunchKey_WP_Options::OPTION_SECRET_KEY ] ) );

		return $is_configured;
	}

	/**
	 * @since 1.0.0
	 */
	public function enqueue_scripts() {
		if ( $this->wp_facade->current_user_can( 'manage_options' ) ) {

			$this->wp_facade->wp_enqueue_script(
				'launchkey-qr-code-script',
				$this->wp_facade->plugins_url( '/public/qrcode.js', dirname( __FILE__ ) ),
				array(),
				'1.0.0',
				true
			);

			$this->wp_facade->wp_enqueue_script(
				'launchkey-wizard-script',
				$this->wp_facade->plugins_url( '/public/launchkey-wizard.js', dirname( __FILE__ ) ),
				array( 'jquery', 'launchkey-qr-code-script' ),
				'1.1.0',
				true
			);

			$options = $this->get_option( LaunchKey_WP_Admin::OPTION_KEY );
			$this->wp_facade->wp_localize_script(
				'launchkey-wizard-script',
				'launchkey_wizard_config',
				array(
					'nonce'               => $this->wp_facade->wp_create_nonce( static::WIZARD_NONCE_KEY ),
					'is_configured'       => $this->is_plugin_configured( $options ),
					'implementation_type' => $options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ],
					'url'                 => $this->wp_facade->admin_url( 'admin-ajax.php?action=' .
					                                                      static::DATA_SUBMIT_AJAX_ACTION ),
					'qr_code_url'         => $this->wp_facade->admin_url( 'admin-ajax.php?action=' .
					                                                      static::QR_CODE_ACTION ),
				)
			);
		}
	}

	/**
	 * @since 1.0.0
	 */
	public function wizard_submit_ajax() {
		if ( isset( $_POST['nonce'] ) ) {
			if ( $this->wp_facade->wp_verify_nonce( $_POST['nonce'], static::WIZARD_NONCE_KEY ) &&
			     $this->wp_facade->current_user_can( 'manage_options' )
			) {
				list( $options, $errors ) = $this->admin->check_option( $_POST );
				if ( $errors ) {
					$response["errors"] = $errors;
				} elseif ( $this->is_multi_site ) {
					$this->wp_facade->update_site_option( LaunchKey_WP_Admin::OPTION_KEY, $options );
				} else {
					$this->wp_facade->update_option( LaunchKey_WP_Admin::OPTION_KEY, $options );
				}
				$response['nonce'] = $this->wp_facade->wp_create_nonce( static::WIZARD_NONCE_KEY );
			} else {
				$response['errors'] =
					$this->wp_facade->__( "An error occurred submitting the page.  Please refresh the page and submit again." );
			}
			$this->wp_facade->wp_send_json( $response );
		}
	}

	/**
	 * Compile the data that will be used by the front end to generate a QR Code for WordPress auto-config.
	 * @since 1.4.0
	 */
	public function wizard_easy_setup_qr_code() {
		if ( isset( $_POST['nonce'] ) ) {
			if ( $this->wp_facade->wp_verify_nonce( $_POST['nonce'], static::WIZARD_NONCE_KEY ) &&
			     $this->wp_facade->current_user_can( 'manage_options' )
			) {
				$lk_nonce = $this->launchkey_client->auth()->nonce();
				$this->update_option( static::EASY_SETUP_OPTION, array(
					'nonce'    => $lk_nonce,
					'username' => $this->wp_facade->wp_get_current_user()->user_login
				) );

				$payload = json_encode( array(
					'nonce'   => $lk_nonce->getNonce(),
					'payload' => array(
						'callback_url' => $this->admin->get_callback_url(),
						'rocket_name'  => $this->wp_facade->get_bloginfo( 'name' )
					)
				) );

				$qr_data = base64_encode( $payload );

				$response['nonce']   = $this->wp_facade->wp_create_nonce( static::WIZARD_NONCE_KEY );
				$response['qr_code'] = $qr_data;
			} else {
				$response['errors'] =
					$this->wp_facade->__( "An error occurred submitting the page.  Please refresh the page and submit again." );
			}
			$this->wp_facade->wp_send_json( $response );
		}
	}

	private function update_option( $key, $value ) {
		if ( $this->is_multi_site ) {
			$this->wp_facade->update_site_option( $key, $value );
		} else {
			$this->wp_facade->update_option( $key, $value );
		}
	}

	public function wizard_easy_setup_callback() {
		$headers = array();
		array_walk( $_SERVER, function ( $value, $key ) use ( &$headers ) {
			if ( preg_match( '/^HTTP\_(.+)$/', $key, $matches ) ) {
				$headers[ str_replace( '_', '-', $matches[1] ) ] = $value;
			}
		} );

		preg_match( '/^[^\/]+\/(.*)$/', $_SERVER['SERVER_PROTOCOL'], $matches );
		$protocol_version = $matches ? $matches[1] : null;

		$request       = new Request(
			$_SERVER['REQUEST_METHOD'],
			$_SERVER['REQUEST_URI'],
			$headers,
			$this->wp_facade->fopen( 'php://input', 'rb' ),
			$protocol_version
		);
		$http_response = new Response();

		if ( $request->hasHeader( 'signature' ) ) {

			try {
				// Have the SDK client handle the callback
				$response = $this->launchkey_client->serverSentEvent()->handleEvent( $request, $http_response );

				if ( $response instanceof \LaunchKey\SDK\Domain\RocketCreated ) {

					$config = $this->get_option( LaunchKey_WP_Configuration_Wizard::EASY_SETUP_OPTION );
					if ( empty( $config['nonce'] ) || ! ( $config['nonce'] instanceof \LaunchKey\SDK\Domain\NonceResponse ) ) {
						throw new \LaunchKey\SDK\Service\Exception\InvalidRequestError( sprintf(
							'Easy config request with no valid "nonce" in option "%s"',
							LaunchKey_WP_Configuration_Wizard::EASY_SETUP_OPTION
						) );
					}

					// Delete the option, valid or not.
					$this->wp_facade->delete_option( LaunchKey_WP_Configuration_Wizard::EASY_SETUP_OPTION );

					// Check for expiration of the nonce
					$expires = $config['nonce']->getExpiration();
					if ( $expires <= new DateTime( "now", new DateTimeZone( "UTC" ) ) ) {
						throw new \LaunchKey\SDK\Service\Exception\InvalidRequestError( 'Easy config "nonce" has expired' );
					}

					$rocketConfig = $response->getRocketConfig( $this->crypt_service, $config['nonce']->getNonce() );

					$expected_callback_url = $this->wp_facade->admin_url(
						'admin-ajax.php?action=' . LaunchKey_WP_Native_Client::CALLBACK_AJAX_ACTION
					);


					// Verify the callback URL before attempting to decrypt the data
					$actual_callback_url = $rocketConfig->getCallbackURL();
					if ( $actual_callback_url !== $expected_callback_url ) {
						throw new \LaunchKey\SDK\Service\Exception\InvalidRequestError( sprintf(
							'Easy config is not for this site based on callback. Expected: %s, Actual: %s.',
							$expected_callback_url,
							$actual_callback_url
						) );
					}

					$options = $this->get_option( LaunchKey_WP_Admin::OPTION_KEY );

					$rocket_type = $rocketConfig->isWhiteLabel()
						? LaunchKey_WP_Implementation_Type::WHITE_LABEL
						: LaunchKey_WP_Implementation_Type::NATIVE;

					// Update options from server sent event service response
					$options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ] = $rocket_type;
					$options[ LaunchKey_WP_Options::OPTION_ROCKET_KEY ]          = $rocketConfig->getKey();
					$options[ LaunchKey_WP_Options::OPTION_SECRET_KEY ]          = $rocketConfig->getSecret();
					$options[ LaunchKey_WP_Options::OPTION_PRIVATE_KEY ]         = $rocketConfig->getPrivateKey();

					$this->update_option( LaunchKey_WP_Admin::OPTION_KEY, $options );

					$response_string = "";

					$body = $http_response->getBody();
					$body->rewind();
					while ( $segment = $body->read( 256 ) ) {
						$response_string .= $segment;
					}

					$this->wp_facade->header( "Content-Type: text/plain", true, $http_response->getStatusCode() );

					$this->wp_facade->wp_die( $response_string );
				}
			} catch ( \Exception $e ) {
				if ( $this->wp_facade->is_debug_log() ) {
					$this->wp_facade->error_log( 'Callback Exception: ' . $e->getMessage() );
				}
				if ( $e instanceof \LaunchKey\SDK\Service\Exception\InvalidRequestError ) {
					$this->wp_facade->http_response_code( 400 );
					$this->wp_facade->wp_die( 'Invalid Request' );
				} else {
					$this->wp_facade->http_response_code( 500 );
					$this->wp_facade->wp_die( 'Server Error' );
				}
			}
		}
	}
}
