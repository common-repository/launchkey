<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2016 LaunchKey, Inc. See project license for usage.
 */

/**
 * Make site the plugin functions are available
 */
require_once ABSPATH . 'wp-admin/includes/plugin.php';

/**
 * Class LaunchKey_WP_Bootstrap
 */
class LaunchKey_WP_Bootstrap {

	/**
	 * @var \wpdb
	 */
	private $wpdb;

	/**
	 * @var LaunchKey_WP_Global_Facade
	 */
	private $facade;

	/**
	 * @var \phpseclib\Crypt\AES
	 */
	private $crypt_aes;

	/**
	 * @var string
	 */
	private $api_base_url;

	/**
	 * @var bool
	 */
	private $validate_certs;

	/**
	 * LaunchKey_WP_Bootstrap constructor.
	 *
	 * @param wpdb $wpdb
	 * @param LaunchKey_WP_Global_Facade $facade
	 * @param \phpseclib\Crypt\AES $crypt_aes
	 * @param string $api_base_url
	 * @param bool $validate_certificates
	 * @param string $plugin_file
	 */
	public function __construct(
		wpdb $wpdb,
		LaunchKey_WP_Global_Facade $facade,
		\phpseclib\Crypt\AES $crypt_aes,
		$api_base_url = "https://api.launchkey.com",
		$validate_certificates = true,
		$plugin_file
	) {
		$this->wpdb           = $wpdb;
		$this->facade         = $facade;
		$this->crypt_aes      = $crypt_aes;
		$this->api_base_url   = $api_base_url;
		$this->validate_certs = $validate_certificates;
		$this->plugin_file    = $plugin_file;
	}

	public function launchkey_cron() {
		$table_name = $this->wpdb->prefix . 'launchkey_sso_sessions';
		$dt         = new DateTime( "- 1 hour" );
		$dt->setTimezone( new DateTimeZone( "UTC" ) );

		$this->wpdb->query(
			$this->wpdb->prepare( "DELETE FROM {$table_name} WHERE seen < %s", $dt->format( "Y-m-d H:i:s" ) )
		);
	}

	public function launchkey_cron_remove() {
		$timestamp = wp_next_scheduled( 'launchkey_cron_hook' );
		wp_unschedule_event( $timestamp, 'launchkey_cron_hook' );
	}

	/**
	 * Initialize LaunchKey WordPress Plugin
	 *
	 * This function will perform the entire initialization for the plugin.  The initialization is encapsulated into
	 * a funciton to protect against global variable collision.
	 *
	 * @since 1.0.0
	 * Enclose plug-in initialization to protect against global variable corruption
	 */
	function run() {

		$facade      = $this->facade;
		$plugin_file = $this->plugin_file;

		/**
		 * Register activation hooks for the plugin
		 * @since 1.1.0
		 */
		$facade->register_activation_hook( $plugin_file, array( $this, 'launchkey_create_tables' ) );

		/**
		 * Remove the scheduled cron
		 * @since 1.1.0
		 */
		$facade->register_deactivation_hook( $plugin_file, array( $this, 'launchkey_cron_remove' ) );

		/**
		 * @since 1.1.0
		 * Add the cron hook and schedule if not scheduled
		 */
		$facade->add_action( 'launchkey_cron_hook', array( $this, 'launchkey_cron' ) );
		if ( ! $facade->wp_next_scheduled( 'launchkey_cron_hook' ) ) {
			$facade->wp_schedule_event( $facade->time(), 'hourly', 'launchkey_cron_hook' );
		}

		/**
		 * Language domain for the plugin
		 */
		$language_domain = 'launchkey';

		/**
		 * Register plugin text domain with language files
		 *
		 * @see load_plugin_textdomain
		 * @link https://developer.wordpress.org/reference/hooks/plugins_loaded/
		 */
		$facade->add_action( 'plugins_loaded', function () use ( $language_domain, $facade, $plugin_file ) {
			$facade->load_plugin_textdomain( $language_domain, false,
				$facade->plugin_basename( $plugin_file ) . '/languages/' );
		} );

		// Create an options handler that will encrypt and decrypt the plugin options as necessary
		$options_handler = new LaunchKey_WP_Options( $this->crypt_aes );

		/**
		 * The pre_update_option_launchkey filter will process the "launchkey" option directly
		 * before updating the data in the database.
		 *
		 * @since 1.0.0
		 * @link https://developer.wordpress.org/reference/hooks/pre_update_option_option/
		 * @see LaunchKey_WP_Options::pre_update_option_filter
		 */
		$facade->add_filter( 'pre_update_option_launchkey', array( $options_handler, 'pre_update_option_filter' ) );
		$facade->add_filter( 'pre_update_site_option_launchkey',
			array( $options_handler, 'pre_update_option_filter' ) );

		/**
		 * The pre_update_option_filter filter will process the "launchkey" option directly
		 * before adding the data in the database.
		 *
		 * @since 1.0.0
		 * @link https://developer.wordpress.org/reference/hooks/pre_update_option_option/
		 * @see LaunchKey_WP_Options::pre_update_option_filter
		 */
		$facade->add_filter( 'pre_add_option_launchkey', array( $options_handler, 'pre_update_option_filter' ) );
		$facade->add_filter( 'pre_add_site_option_launchkey', array( $options_handler, 'pre_update_option_filter' ) );

		/**
		 * The option_launchkey filter will process the "launchkey" option directly
		 * after retrieving the data from the database.
		 *
		 * @since 1.0.0
		 * @link https://developer.wordpress.org/reference/hooks/option_option/
		 * @see LaunchKey_WP_Options::post_get_option_filter
		 */
		$facade->add_filter( 'option_launchkey', array( $options_handler, 'post_get_option_filter' ) );
		$facade->add_filter( 'site_option_launchkey', array( $options_handler, 'post_get_option_filter' ) );

		$is_multi_site =
			$facade->is_multisite() &&
			$facade->is_plugin_active_for_network( $facade->plugin_basename( $plugin_file ) );
		$options       = $is_multi_site ? $facade->get_site_option( LaunchKey_WP_Admin::OPTION_KEY ) :
			$facade->get_option( LaunchKey_WP_Admin::OPTION_KEY );

		/**
		 * Handle upgrades if in the admin and not the latest version
		 */
		if ( $facade->is_admin() && $this->launchkey_is_activated() && $options &&
		     $options[ LaunchKey_WP_Options::OPTION_VERSION ] < 1.1
		) {
			$this->launchkey_create_tables();
		}

		/**
		 * If the pre-1.0.0 option style was already used, create a 1.0.0 option and remove the old options.  They are
		 * removed as the secret_key was stored plain text in the database.
		 *
		 * @since 1.0.0
		 */
		if ( $facade->get_option( 'launchkey_app_key' ) || $facade->get_option( 'launchkey_secret_key' ) ) {
			$launchkey_options[ LaunchKey_WP_Options::OPTION_ROCKET_KEY ]          =
				$facade->get_option( 'launchkey_app_key' );
			$launchkey_options[ LaunchKey_WP_Options::OPTION_SECRET_KEY ]          =
				$facade->get_option( 'launchkey_secret_key' );
			$launchkey_options[ LaunchKey_WP_Options::OPTION_SSL_VERIFY ]          =
				( defined( 'LAUNCHKEY_SSLVERIFY' ) && LAUNCHKEY_SSLVERIFY ) || true;
			$launchkey_options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ] =
				LaunchKey_WP_Implementation_Type::OAUTH;
			$launchkey_options[ LaunchKey_WP_Options::OPTION_LEGACY_OAUTH ]        = true;

			$updated =
				$is_multi_site ? $facade->update_network_option( LaunchKey_WP_Admin::OPTION_KEY, $launchkey_options ) :
					$facade->update_option( LaunchKey_WP_Admin::OPTION_KEY, $launchkey_options );
			if ( $updated ) {
				$facade->delete_option( 'launchkey_app_key' );
				$facade->delete_option( 'launchkey_secret_key' );
			} else {
				throw new RuntimeException( 'Unable to upgrade LaunchKey meta-data.  Failed to save setting ' .
				                            LaunchKey_WP_Admin::OPTION_KEY );
			}
		} elseif ( ! $options ) {
			$is_multi_site ? $facade->add_site_option( LaunchKey_WP_Admin::OPTION_KEY, array() ) :
				$facade->add_option( LaunchKey_WP_Admin::OPTION_KEY, array() );
			$options = $is_multi_site ? $facade->get_site_option( LaunchKey_WP_Admin::OPTION_KEY ) :
				$facade->get_option( LaunchKey_WP_Admin::OPTION_KEY );
		}

		/**
		 * Create a templating object and point it at the correct directory for template files.
		 *
		 * @see LaunchKey_WP_Template
		 */
		$template =
			new LaunchKey_WP_Template( $facade->dirname( $plugin_file ) . '/templates', $facade, $language_domain );

		// Prevent XXE Processing Vulnerability
		$facade->libxml_disable_entity_loader( true );

		// Get the plugin options to determine which authentication implementation should be utilized
		$logger           = new LaunchKey_WP_Logger( $facade );
		$launchkey_client = null;
		$client           = null;

		// Only register the pieces that need to interact with LaunchKey if it's been configured
		if ( LaunchKey_WP_Implementation_Type::SSO === $options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ] &&
		     ! empty( $options[ LaunchKey_WP_Options::OPTION_SSO_ENTITY_ID ] )
		) {

			$container = new LaunchKey_WP_SAML2_Container( $logger );
			SAML2_Compat_ContainerSingleton::setContainer( $container );
			$securityKey = new XMLSecurityKey( XMLSecurityKey::RSA_SHA1, array( 'type' => 'public' ) );
			$securityKey->loadKey( $options[ LaunchKey_WP_Options::OPTION_SSO_CERTIFICATE ], false, true );
			$saml_response_service = new LaunchKey_WP_SAML2_Response_Service( $securityKey, $facade );
			$saml_request_service  = new LaunchKey_WP_SAML2_Request_Service( $securityKey );

			$client = new LaunchKey_WP_SSO_Client(
				$this->facade,
				$template,
				$options[ LaunchKey_WP_Options::OPTION_SSO_ENTITY_ID ],
				$saml_response_service,
				$saml_request_service,
				$this->wpdb,
				$options[ LaunchKey_WP_Options::OPTION_SSO_LOGIN_URL ],
				$options[ LaunchKey_WP_Options::OPTION_SSO_LOGOUT_URL ],
				$options[ LaunchKey_WP_Options::OPTION_SSO_ERROR_URL ],
				$is_multi_site
			);
		} elseif ( LaunchKey_WP_Implementation_Type::OAUTH ===
		           $options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ] &&
		           ! empty( $options[ LaunchKey_WP_Options::OPTION_SECRET_KEY ] )
		) {
			/**
			 * If the implementation type is OAuth, use the OAuth client
			 * @see LaunchKey_WP_OAuth_Client
			 */
			$client = new LaunchKey_WP_OAuth_Client( $facade, $template, $is_multi_site );
		} elseif ( ! empty( $options[ LaunchKey_WP_Options::OPTION_SECRET_KEY ] ) ) {

			$config = new \LaunchKey\SDK\Config();
			$config->setApiBaseUrl( $this->api_base_url );
			$launchkey_client = \LaunchKey\SDK\Client::wpFactory(
				$options[ LaunchKey_WP_Options::OPTION_ROCKET_KEY ],
				$options[ LaunchKey_WP_Options::OPTION_SECRET_KEY ],
				$options[ LaunchKey_WP_Options::OPTION_PRIVATE_KEY ],
				$this->validate_certs,
				$config
			);

			$client = new LaunchKey_WP_Native_Client( $launchkey_client, $facade, $template, $language_domain,
				$is_multi_site );

			$facade->add_filter( 'init', function () use ( $facade, $plugin_file ) {
				$facade->wp_enqueue_script(
					'launchkey-script',
					plugins_url( '/public/launchkey-login.js', $plugin_file ),
					array( 'jquery' ),
					'1.1.1',
					true
				);
			} );
		} else {
			$config = new \LaunchKey\SDK\Config();
			$config->setApiBaseUrl( $this->api_base_url );
			$launchkey_client = \LaunchKey\SDK\Client::wpFactory( $config );
		}

		if ( $client ) {

			/**
			 * Register the non-admin actions for authentication client.  These actions will handle all of the
			 * authentication work for the plugin.
			 *
			 * @see LaunchKey_WP_Client::register_actions
			 * @see LaunchKey_WP_OAuth_Client::register_actions
			 * @see LaunchKey_WP_Native_Client::register_actions
			 */
			$client->register_actions();

			/**
			 * Create the a user profile object and register its actions.  These actions will handle all functionality
			 * related to a user customizing their authentication related options.
			 *
			 * @see LaunchKey_WP_User_Profile
			 */
			$profile = new LaunchKey_WP_User_Profile( $facade, $template, $language_domain, $is_multi_site );
			$profile->register_actions();

			/**
			 * Hideous workaround for the wp-login.php page not printing styles in the header like it should.
			 *
			 * @since 1.0.0
			 */
			if ( ! $facade->has_action( 'login_enqueue_scripts', 'wp_print_styles' ) ) {
				$facade->add_action( 'login_enqueue_scripts', 'wp_print_styles', 11 );
			}
		}

		if ( $facade->is_admin() || ( $is_multi_site && $facade->is_network_admin() ) ) {
			/**
			 * If we are in the admin, create an admin object and register its actions.  These actions
			 * will manage setting of options and user management for the plugin.
			 *
			 * @see is_admin
			 * @see LaunchKey_WP_Admin
			 */
			$launchkey_admin = new LaunchKey_WP_Admin( $facade, $template, $language_domain, $is_multi_site );
			$launchkey_admin->register_actions();

			$config_wizard = new LaunchKey_WP_Configuration_Wizard(
				$facade, $launchkey_admin, new \LaunchKey\SDK\Service\PhpSecLibCryptService(null), $is_multi_site, $launchkey_client
			);
			$config_wizard->register_actions();
		}

		/**
		 * Add a filter to enqueue styles for the plugin
		 *
		 * @since 1.0.0
		 *
		 * @see add_filter
		 * @see wp_enqueue_style
		 * @link https://developer.wordpress.org/reference/functions/add_filter/
		 * @link https://developer.wordpress.org/reference/functions/wp_enqueue_style/
		 */
		$facade->add_filter( 'init', function () use ( $facade, $plugin_file ) {
			$facade->wp_enqueue_style(
				'launchkey-style',
				$facade->plugins_url( '/public/launchkey.css', $plugin_file ),
				array(),
				'1.0.1',
				false
			);
		} );

		/**
		 * Handle activation when a "must use" plugin
		 */
		if ( $this->launchkey_is_mu_plugin() ) {
			$mu_activated_option = "launchkey_activated";
			if ( ! $facade->get_option( $mu_activated_option ) ) {
				$facade->do_action( "activate_" . $facade->plugin_basename( $plugin_file ) );
				$facade->add_option( $mu_activated_option, true );
			}
		}
	}

	/**
	 * Create/update tables utilized by the plugin
	 * @since 1.1.0
	 */
	public function launchkey_create_tables() {
		$table_name = $this->wpdb->prefix . 'launchkey_sso_sessions';

		$sql = "CREATE TABLE {$table_name} (
			id VARCHAR(255) NOT NULL,
			seen DATETIME NOT NULL,
			UNIQUE KEY {$table_name}_id (id)
		);";

		require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
		$this->facade->dbDelta( $sql );
	}

	private function launchkey_is_mu_plugin() {
		return strpos( __FILE__, WPMU_PLUGIN_DIR ) === 0;
	}

	private function launchkey_is_activated() {
		return $this->facade->is_plugin_active( $this->plugin_file ) || $this->launchkey_is_mu_plugin();
	}

}
