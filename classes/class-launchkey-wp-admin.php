<?php

/**
 * Plugin administration
 *
 * Class to encapsulate all administration of the plugin
 *
 * @package launchkey
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 * @since 1.0.0
 */
class LaunchKey_WP_Admin {

	/**
	 * Option key to get and set the option array for this plugin.@global
	 * @since 1.0.0
	 */
	const OPTION_KEY = 'launchkey';

	/**
	 * @var LaunchKey_WP_Global_Facade
	 */
	private $wp_facade;

	/**
	 * @var LaunchKey_WP_Template
	 */
	private $template;

	/**
	 * @var string Language domain for translation
	 */
	private $language_domain;

	/**
	 * @var bool Is this
	 */
	private $is_multi_site;

	/**
	 * LaunchKey_WP_Admin constructor.
	 *
	 * @since 1.0.0
	 *
	 * @param LaunchKey_WP_Global_Facade $wp_facade Global wp_facade for testing
	 * @param LaunchKey_WP_Template $template
	 * @param string $language_domain Language domain for translation
	 * @param bool $is_multi_site Is this a multi-site setup?
	 */
	public function __construct(
		LaunchKey_WP_Global_Facade $wp_facade,
		LaunchKey_WP_Template $template,
		$language_domain,
		$is_multi_site
	) {
		$this->wp_facade       = $wp_facade;
		$this->template        = $template;
		$this->language_domain = $language_domain;
		$this->is_multi_site   = $is_multi_site;
	}

	/**
	 * Register actions and callbacks with WP Engine
	 *
	 * @since 1.0.0
	 */
	public function register_actions() {
		if ( $this->is_multi_site ) {
			$this->wp_facade->add_action( 'network_admin_menu', array( $this, 'add_launchkey_network_admin_menus' ) );
		} else {
			$this->wp_facade->add_action( 'admin_menu', array( $this, 'add_launchkey_admin_menus' ) );
		}
		$notices_action = $this->is_multi_site ? 'network_admin_notices' : 'admin_notices';
		$this->wp_facade->add_action( $notices_action, array( $this, 'oauth_warning' ) );
		$this->wp_facade->add_action( $notices_action, array( $this, 'activate_notice' ) );
		$this->wp_facade->add_action( $notices_action, array( $this, 'deprecation_notice' ) );
		$this->wp_facade->add_filter(
			sprintf(
				'%splugin_action_links_%s',
				$this->is_multi_site ? 'network_admin_' : '',
				$this->wp_facade->plugin_basename( $this->wp_facade->plugin_dir_path( __DIR__ ) . 'launchkey.php' )
			),
			array( $this, 'add_action_links' )
		);
	}

	/**
	 * Add the launchkey menu items
	 *
	 * @since 1.0.0
	 */
	public function add_launchkey_admin_menus() {
		// This page will be under "Settings"
		$this->wp_facade->add_options_page( 'LaunchKey', 'LaunchKey', 'manage_options', 'launchkey-settings',
			array( $this, 'create_launchkey_settings_page' ) );
	}

	/**
	 * Add the launchkey menu items
	 *
	 * @since 1.0.0
	 */
	public function add_launchkey_network_admin_menus() {
		// This page will be under "Settings"
		$this->wp_facade->add_submenu_page(
			'settings.php',
			'LaunchKey',
			'LaunchKey',
			'manage_options',
			'launchkey-settings',
			array( $this, 'create_launchkey_settings_page' ) );
	}

	/**
	 * Create the settings page
	 *
	 * Renders the settings page to the screen as defined by {@see setup_launchkey_settings_page}
	 *
	 * @since 1.0.0
	 */
	public function create_launchkey_settings_page() {
		$options          = $this->get_launchkey_options();
		$hasMcrypt        = $this->wp_facade->extension_loaded( 'mcrypt' );
		$hasOpenSSL       = $this->wp_facade->extension_loaded( 'openssl' );
		$hasCurl          = $this->wp_facade->extension_loaded( 'curl' );
		$hasDOM           = $this->wp_facade->extension_loaded( 'dom' );
		$hasPrerequisites = ( $hasCurl && $hasDOM && $hasMcrypt && $hasOpenSSL );

		$this->render_template( 'admin/settings', array(
			'callback_url'        => $this->get_callback_url(),
			'sso_post_url'        => $this->wp_facade->site_url('wp-login.php', 'login_post'),
			'domain'              => $this->wp_facade->parse_url( $this->wp_facade->admin_url(), PHP_URL_HOST ),
			'rocket_key'          => $options[ LaunchKey_WP_Options::OPTION_ROCKET_KEY ],
			'app_display_name'    => $options[ LaunchKey_WP_Options::OPTION_APP_DISPLAY_NAME ],
			'ssl_verify_checked'  => $options[ LaunchKey_WP_Options::OPTION_SSL_VERIFY ] ? 'checked="checked"' : '',
			'mcrypt_pass_fail'    => $hasMcrypt ? 'pass' : 'fail',
			'openssl_pass_fail'   => $hasOpenSSL ? 'pass' : 'fail',
			'curl_pass_fail'      => $hasCurl ? 'pass' : 'fail',
			'dom_pass_fail'       => $hasDOM ? 'pass' : 'fail',
			'show_sso_next'       => $hasPrerequisites ? 'show' : 'hide',
			'show_sso_back'       => $hasPrerequisites ? 'hide' : 'show',
			'wp_username'         => $this->wp_facade->wp_get_current_user()->user_login,
			'sso_entity_id'       => $options[ LaunchKey_WP_Options::OPTION_SSO_ENTITY_ID ],
			'sso_public_key'      => $options[ LaunchKey_WP_Options::OPTION_SSO_CERTIFICATE ],
			'sso_login_url'       => $options[ LaunchKey_WP_Options::OPTION_SSO_LOGIN_URL ],
			'sso_logout_url'      => $options[ LaunchKey_WP_Options::OPTION_SSO_LOGOUT_URL ],
			'sso_error_url'       => $options[ LaunchKey_WP_Options::OPTION_SSO_ERROR_URL ],
		) );
	}

	/**
	 * @return array
	 */
	private function get_launchkey_options() {
		$options = $this->is_multi_site ? $this->wp_facade->get_site_option( static::OPTION_KEY ) :
			$this->wp_facade->get_option( static::OPTION_KEY );

		return $options;
	}

	private function render_template( $template, $context = array() ) {
		$this->wp_facade->_echo( $this->template->render_template( $template, $context ) );
	}

	/**
	 * @return string
	 */
	public function get_callback_url() {
		$callback_url = $this->wp_facade->admin_url(
			'admin-ajax.php?action=' . LaunchKey_WP_Native_Client::CALLBACK_AJAX_ACTION
		);

		return $callback_url;
	}

	public function check_option( $input ) {
		$options = $original_options = $this->get_launchkey_options();
		$errors  = array();

		$implementation_type = $this->process_implementation_type( $input, $errors, $options );

		if ( LaunchKey_WP_Implementation_Type::SSO === $implementation_type ) {
			$this->process_sso_options( $input, $errors, $options );
		} elseif (
			LaunchKey_WP_Implementation_Type::NATIVE == $implementation_type ||
			LaunchKey_WP_Implementation_Type::WHITE_LABEL == $implementation_type ||
			LaunchKey_WP_Implementation_Type::OAUTH == $implementation_type
		) {
			$this->process_standard_options( $input, $errors, $options );
		}

		$options[ LaunchKey_WP_Options::OPTION_SSL_VERIFY ] =
			isset( $input[ LaunchKey_WP_Options::OPTION_SSL_VERIFY ] ) &&
			'on' === $input[ LaunchKey_WP_Options::OPTION_SSL_VERIFY ];

		return array( $options, $errors );
	}

	/**
	 * @param array $input
	 * @param array $errors
	 * @param array $options
	 *
	 * @return string
	 */
	private function process_implementation_type( $input, &$errors, &$options ) {
		$implementation_type = isset( $input[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ] ) ?
			trim( $input[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ] ) : null;
		if ( empty( $implementation_type ) ) {
			$errors[] = $this->wp_facade->__( 'You must select an implementation type', $this->language_domain );
		} elseif ( ! LaunchKey_WP_Implementation_Type::is_valid( $implementation_type ) ) {
			$errors[] =
				$this->wp_facade->__( 'An invalid implelementation type was submitted', $this->language_domain );
		} else {
			if (
				isset( $options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ] ) &&
				LaunchKey_WP_Implementation_Type::WHITE_LABEL ===
				$options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ] &&
				LaunchKey_WP_Implementation_Type::WHITE_LABEL !== $implementation_type &&
				isset( $options[ LaunchKey_WP_Options::OPTION_APP_DISPLAY_NAME ] ) &&
				'LaunchKey' !== $options[ LaunchKey_WP_Options::OPTION_APP_DISPLAY_NAME ] &&
				( empty( $input[ LaunchKey_WP_Options::OPTION_APP_DISPLAY_NAME ] ) ||
				  'LaunchKey' !== $input[ LaunchKey_WP_Options::OPTION_APP_DISPLAY_NAME ] )
			) {
				$input[ LaunchKey_WP_Options::OPTION_APP_DISPLAY_NAME ] = 'LaunchKey';
				$errors[]                                               = $this->wp_facade->__(
					'App Display Name was reset as the Implementation Type is no longer White Label',
					$this->language_domain
				);
			}
			$options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ] = $implementation_type ?: null;
		}

		return $implementation_type;
	}

	/**
	 * @param array $errors
	 * @param array $options
	 *
	 * @internal param array $input
	 */
	private function process_sso_options( $input, &$errors, &$options ) {
		if ( empty( $input[ LaunchKey_WP_Options::OPTION_SSO_ENTITY_ID ] ) ) {
			$errors[] = $this->wp_facade->__(
				'SSO Profile Entity ID is required',
				$this->language_domain
			);
		} else {
			$options[ LaunchKey_WP_Options::OPTION_SSO_ENTITY_ID ] =
				$input[ LaunchKey_WP_Options::OPTION_SSO_ENTITY_ID ];
		}
		if (
			empty( $_FILES['sso_idp']['tmp_name'] ) &&
			empty( $options[ LaunchKey_WP_Options::OPTION_SSO_CERTIFICATE ] )
		) {
			$errors[] = $this->wp_facade->__(
				'SSO Profile File is required',
				$this->language_domain
			);
		} else if ( ! empty( $_FILES['sso_idp']['tmp_name'] ) ) {
			try {
				$idp_doc                                                 =
					SAML2_DOMDocumentFactory::fromString( file_get_contents( $_FILES['sso_idp']['tmp_name'] ) );
				$helper                                                  =
					LaunchKey_WP_SSO_Config_Helper::from_DOM_document( $idp_doc );
				$options[ LaunchKey_WP_Options::OPTION_SSO_CERTIFICATE ] = $helper->get_X509_certificate();
				$options[ LaunchKey_WP_Options::OPTION_SSO_LOGIN_URL ]   = $helper->get_SSO_redirect();
				$options[ LaunchKey_WP_Options::OPTION_SSO_LOGOUT_URL ]  = $helper->get_SLO_redirect();
				$options[ LaunchKey_WP_Options::OPTION_SSO_ERROR_URL ]   = $helper->get_error_redirect();
			} catch ( Exception $e ) {
				$errors[] = $this->wp_facade->__(
						'The SSO Profile file provided had an error being parsed',
						$this->language_domain
					) . ": " . $e->getMessage();
			}
		}
	}

	/**
	 * @param array $input
	 * @param array $errors
	 * @param array $options
	 */
	private function process_standard_options( &$input, &$errors, &$options ) {
		if ( empty( $input[ LaunchKey_WP_Options::OPTION_ROCKET_KEY ] ) ) {
			$errors[] = $this->wp_facade->__( 'Rocket Key is a required field', $this->language_domain );
		} else {

			$rocket_key = trim( $input[ LaunchKey_WP_Options::OPTION_ROCKET_KEY ] );
			if ( ! is_numeric( $rocket_key ) ) {
				$errors[] = $this->wp_facade->__( 'Rocket Key must be numeric', $this->language_domain );
			} elseif ( strlen( $rocket_key ) !== 10 ) {
				$errors[] = $this->wp_facade->__( 'Rocket Key must be 10 digits', $this->language_domain );
			} else {
				$options[ LaunchKey_WP_Options::OPTION_ROCKET_KEY ] = $rocket_key;
			}
		}

		if ( empty( $input[ LaunchKey_WP_Options::OPTION_SECRET_KEY ] ) &&
		     empty( $options[ LaunchKey_WP_Options::OPTION_SECRET_KEY ] )
		) {
			$errors[] = $this->wp_facade->__( 'Secret Key is a required field', $this->language_domain );
		} else if ( ! empty( $input[ LaunchKey_WP_Options::OPTION_SECRET_KEY ] ) ) {
			$secret_key = trim( $input[ LaunchKey_WP_Options::OPTION_SECRET_KEY ] );
			if ( ! ctype_alnum( $secret_key ) ) {
				$errors[] = $this->wp_facade->__( 'Secret Key must be alphanumeric', $this->language_domain );
			} elseif ( strlen( $secret_key ) !== 32 ) {
				$errors[] = $this->wp_facade->__( 'Secret Key must be 32 characters', $this->language_domain );
			} else {
				$options[ LaunchKey_WP_Options::OPTION_SECRET_KEY ] = $secret_key;
			}
		}

		$app_display_name = isset( $input[ LaunchKey_WP_Options::OPTION_APP_DISPLAY_NAME ] ) ?
			trim( $input[ LaunchKey_WP_Options::OPTION_APP_DISPLAY_NAME ] ) : null;
		if (
			'LaunchKey' !== $app_display_name &&
			LaunchKey_WP_Implementation_Type::WHITE_LABEL !==
			$options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ]
		) {
			$errors[]                                                 = $this->wp_facade->__(
				'App Display Name can only be modified for White Label implementations',
				$this->language_domain
			);
			$options[ LaunchKey_WP_Options::OPTION_APP_DISPLAY_NAME ] = 'LaunchKey';
		} else {
			$options[ LaunchKey_WP_Options::OPTION_APP_DISPLAY_NAME ] = $app_display_name ?: null;
		}

		if (
			empty( $_FILES['private_key']['tmp_name'] ) &&
			empty( $options[ LaunchKey_WP_Options::OPTION_PRIVATE_KEY ] ) &&
			isset( $options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ] ) &&
			LaunchKey_WP_Implementation_Type::requires_private_key( $options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ] )
		) {
			$errors[] = $this->wp_facade->__(
				'Private Key is required',
				$this->language_domain
			);
		} else if ( ! empty( $_FILES['private_key']['tmp_name'] ) ) {
			$private_key = @file_get_contents( $_FILES['private_key']['tmp_name'] );
			$rsa         = new \phpseclib\Crypt\RSA();
			if ( @$rsa->loadKey( $private_key ) ) {
				if ( $rsa->getPrivateKey( $rsa->privateKeyFormat ) ) {
					$options[ LaunchKey_WP_Options::OPTION_PRIVATE_KEY ] = $private_key;
				} else {
					$errors[] = $this->wp_facade->__(
						'The Key file provided was a valid RSA key file but did not contain a private key.  Did you mistakenly supply the public key file?',
						$this->language_domain
					);
				}
			} else {
				$errors[] = $this->wp_facade->__(
					'The Private Key provided was invalid',
					$this->language_domain
				);
			}
		}
	}

	/**
	 * Display a deprecation notice if the current implementation type in OAuth
	 *
	 * @since 1.0.0
	 */
	public function oauth_warning() {
		$options = $this->get_launchkey_options();
		if ( LaunchKey_WP_Implementation_Type::OAUTH ===
		     $options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ]
		) {
			$this->render_template( 'admin/oauth-deprecation-warning' );
		}
	}

	/**
	 * Display a deprecation notice if the current implementation type in OAuth
	 *
	 * @since 1.0.0
	 */
	public function activate_notice() {
		$options     = $this->get_launchkey_options();
		$hook_suffix = $this->wp_facade->get_hook_suffix();

		// If we are on a relevant page to the plugin and it's not configured, show the activate banner
		if ( in_array( $hook_suffix, array( 'plugins.php', 'users.php', 'profile.php' ) ) &&
		     (
			     ( LaunchKey_WP_Implementation_Type::SSO ===
			       $options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ]
			       && empty( $options[ LaunchKey_WP_Options::OPTION_SSO_ENTITY_ID ] ) )
			     || ( LaunchKey_WP_Implementation_Type::SSO !==
			          $options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ]
			          && empty( $options[ LaunchKey_WP_Options::OPTION_SECRET_KEY ] )
			     )
		     )
		) {
			$this->render_template( 'admin/activate-plugin', array(
				'settings_url' => $this->get_settings_page(),
				'icon_url'     => $this->wp_facade->plugins_url( '/public/launchkey-logo-white.png',
					dirname( __FILE__ ) )
			) );
		}
	}

	/**
	 * Display a deprecation notice in WP admin
	 *
	 * @since 1.4.6
	 */
	public function deprecation_notice() {
		$hook_suffix = $this->wp_facade->get_hook_suffix();

		// If we are on a relevant page to the plugin and it's not configured, show the activate banner
		if ( in_array( $hook_suffix, array( 'plugins.php', 'users.php', 'profile.php' ) ) ) {
			$this->render_template( 'admin/deprecation-notice', array() );
		}
	}

	/**
	 * @return string
	 */
	private function get_settings_page( $wizard = false ) {
		$page = $this->is_multi_site ? 'network/settings.php' : 'options-general.php';
		$page .= '?page=launchkey-settings';
		$page .= $wizard ? '#wizard-home' : '';

		return $this->wp_facade->admin_url( $page );
	}

	/**
	 * Add links to additional actions to the actions links in the plugins list
	 *
	 * @param $links
	 *
	 * @return array
	 *
	 * @since 1.0.0
	 */
	public function add_action_links( $links ) {
		static $template = '<a href="%s">%s</a>';
		$links[] = sprintf(
			$template,
			$this->get_settings_page( true ),
			$this->wp_facade->__( 'Setup Wizard', $this->language_domain )
		);

		$links[] = sprintf(
			$template,
			$this->get_settings_page(),
			$this->wp_facade->__( 'Settings', $this->language_domain )
		);

		return $links;
	}
}
