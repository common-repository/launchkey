<?php

/**
 * @package launchkey
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */
class LaunchKey_WP_User_Profile {
	const NONCE_KEY = 'launchkey-user-profile-nonce';

	/**
	 * @var LaunchKey_WP_Template
	 */
	private $template;

	/**
	 * @var string
	 */
	private $language_domain;

	/**
	 * @var bool
	 */
	private $is_multi_site;

	/**
	 * LaunchKey_WP_User_Profile constructor.
	 *
	 * @param LaunchKey_WP_Global_Facade $wp_facade
	 * @param LaunchKey_WP_Template $template
	 * @param string $language_domain
	 * @param $is_multi_site
	 */
	public function __construct(
			LaunchKey_WP_Global_Facade $wp_facade,
			LaunchKey_WP_Template $template,
			$language_domain,
			$is_multi_site ) {
		$this->wp_facade = $wp_facade;
		$this->template  = $template;
		$this->language_domain = $language_domain;
		$this->is_multi_site = $is_multi_site;
	}

	/**
	 * Register actions and callbacks with WP Engine
	 *
	 * @since 1.0.0
	 */
	public function register_actions() {
		$this->wp_facade->add_action( 'profile_personal_options', array( $this, 'launchkey_personal_options' ) );
		$this->wp_facade->add_action( 'admin_init', array( $this, 'remove_password_handler' ) );
		$this->wp_facade->add_action( 'admin_init', array( $this, 'unpair_handler' ) );

		$options = $this->get_option();
		$implementation_type = $options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ];
		if ( LaunchKey_WP_Implementation_Type::SSO !== $implementation_type ) {
			$this->wp_facade->add_filter(
					$this->is_multi_site ? 'wpmu_users_columns' : 'manage_users_columns',
					array( $this, 'add_users_columns' )
			);
			$this->wp_facade->add_filter(
					'manage_users_custom_column',
					array( $this, 'apply_custom_column_filter' ), 10, 3
			);
		}
	} //end register_actions

	/**
	 * Handler to show the LaunchKey options in the user profile screen
	 *
	 * @param $user
	 *
	 * @since 1.0.0
	 */
	public function launchkey_personal_options( $user ) {
		$user_meta           = $this->wp_facade->get_user_meta( $user->ID );
		$options             = $this->get_option();
		$implementation_type = $options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ];

		if ( // OAuth and Native paired display unpair and remove password
			( LaunchKey_WP_Implementation_Type::OAUTH === $implementation_type &&
			  ! empty( $user_meta['launchkey_user'] ) )
			|| ( LaunchKey_WP_Implementation_Type::NATIVE === $implementation_type &&
			     ! empty( $user_meta['launchkey_username'] ) )
		) {
			//check if password is set before allowing unpair
			if ( !empty( $user->user_pass ) ) {
				$nonce = $this->wp_facade->wp_create_nonce( static::NONCE_KEY );
				$display = $this->template->render_template( 'personal-options/paired-with-password', array(
					'app_display_name' => $options[LaunchKey_WP_Options::OPTION_APP_DISPLAY_NAME],
					'unpair_uri' => $this->wp_facade->admin_url( '/profile.php?launchkey_unpair=1&launchkey_nonce=' . $nonce ),
					'password_remove_uri' => $this->wp_facade->admin_url( '/profile.php?launchkey_remove_password=1&launchkey_nonce=' . $nonce )
				) );
			} else {
				$display = $this->template->render_template( 'personal-options/paired-without-password', array(
					'app_display_name' => $options[LaunchKey_WP_Options::OPTION_APP_DISPLAY_NAME]
				) );
			}
		} elseif ( LaunchKey_WP_Implementation_Type::SSO === $implementation_type ) {
			if ( !empty( $user->user_pass ) ) {
				$nonce = $this->wp_facade->wp_create_nonce( static::NONCE_KEY );
				$display = $this->template->render_template( 'personal-options/sso-with-password', array(
					'app_display_name' => $options[LaunchKey_WP_Options::OPTION_APP_DISPLAY_NAME],
					'password_remove_uri' => $this->wp_facade->admin_url( '/profile.php?launchkey_remove_password=1&launchkey_nonce=' .  $nonce )
				) );
			} else {
				$display = $this->template->render_template( 'personal-options/sso-without-password', array(
					'app_display_name' => $options[LaunchKey_WP_Options::OPTION_APP_DISPLAY_NAME]
				) );
			}
		} else {

			$display = $this->handle_pair(
				$user,
				$options[ LaunchKey_WP_Options::OPTION_IMPLEMENTATION_TYPE ],
				$options[ LaunchKey_WP_Options::OPTION_ROCKET_KEY ],
				$options[ LaunchKey_WP_Options::OPTION_APP_DISPLAY_NAME ]
			);
		}
		$this->wp_facade->_echo( $display );
	} //end launchkey_personal_options

	/**
	 * Handler to unpair a user
	 *
	 * @since 1.0.0
	 */
	public function unpair_handler() {
		if ( isset( $_GET['launchkey_unpair'] ) && isset( $_GET['launchkey_nonce'] ) ) {
			if ( $this->wp_facade->wp_verify_nonce( $_GET['launchkey_nonce'], LaunchKey_WP_User_Profile::NONCE_KEY ) ) {
				$user = $this->wp_facade->wp_get_current_user();
				$this->launchkey_unpair( $user );
			}
		}
	}

	/**
	 * Handler for removing passwords from wordpress users
	 *
	 * @since 1.0.0
	 */
	public function remove_password_handler() {
		if ( isset( $_GET['launchkey_nonce'] ) && isset( $_GET['launchkey_remove_password'] ) ) {
			if ( $this->wp_facade->wp_verify_nonce( $_GET['launchkey_nonce'], LaunchKey_WP_User_Profile::NONCE_KEY ) ) {
				$user = $this->wp_facade->wp_get_current_user();
				if ( $user->ID > 0 ) {
					$wpdb = $this->wp_facade->get_wpdb();
					$wpdb->update( $wpdb->users, array( 'user_pass' => '' ), array( 'ID' => $user->ID ) );

					// Redirect the user to the base page to affect the login if it's needed
					preg_match('/^[^\?]+/', $_SERVER['REQUEST_URI'], $matches);
					$this->wp_facade->wp_redirect($matches[0]);
				}
			}
		}
	}

	/**
	 * Add LaunchKey columns to users list
	 *
	 * @param $columns
	 *
	 * @return mixed
	 *
	 * @since 1.0.0
	 */
	public function add_users_columns( $columns ) {
		$columns['launchkey_paired'] = $this->wp_facade->__( 'Paired', $this->language_domain );

		return $columns;
	}

	/**
	 * Return list value for LaunchKey columns added to users list
	 *
	 * @param $output
	 * @param $column_name
	 * @param $user_id
	 *
	 * @return mixed
	 *
	 * @since 1.0.0
	 */
	public function apply_custom_column_filter( $output, $column_name, $user_id ) {
		if ( 'launchkey_paired' === $column_name ) {
			$response = $this->wp_facade->get_user_meta( $user_id, 'launchkey_user' ) ? 'Yes' : 'No';
			$output   = $this->wp_facade->__( $response );
		}

		return $output;
	}

	/**
	 * launchkey_unpair - unpair a launchkey user with the WordPress user.
	 *
	 * @param mixed $user
	 *
	 * @access public
	 * @return void
	 */
	protected function launchkey_unpair( $user ) {
		if ( is_numeric( $user->ID ) && $user->ID > 0 && strlen( $user->user_pass ) > 0 ) {
			$this->wp_facade->delete_user_meta( $user->ID, 'launchkey_user' );
			$this->wp_facade->delete_user_meta( $user->ID, 'launchkey_username' );
			$this->wp_facade->delete_user_meta( $user->ID, 'launchkey_auth' );
			$this->wp_facade->delete_user_meta( $user->ID, 'launchkey_authorized' );
		}
	}

	/**
	 * @param WP_User $user
	 * @param string $implementation_type
	 * @param int $rocket_key
	 * @param string $app_display_name
	 *
	 * @return string
	 */
	private function handle_pair( WP_User $user, $implementation_type, $rocket_key, $app_display_name ) {
		if ( LaunchKey_WP_Implementation_Type::OAUTH === $implementation_type ) {
			$display = $this->template->render_template( 'personal-options/unpaired-oauth', array(
				'app_display_name' => $app_display_name,
				'pair_uri'         => sprintf(
					'https://oauth.launchkey.com/authorize?client_id=%s&redirect_uri=%s',
					$rocket_key,
					$this->wp_facade->admin_url( '/admin-ajax.php?action=launchkey-callback&launchkey_admin_pair=1' )
				),
			) );
		} elseif ( LaunchKey_WP_Implementation_Type::NATIVE === $implementation_type ) {
			$display = $this->template->render_template( 'personal-options/unpaired-native', array(
				'app_display_name' => $app_display_name,
				'nonce'            => $this->wp_facade->wp_create_nonce( static::NONCE_KEY )
			) );
		} elseif ( LaunchKey_WP_Implementation_Type::WHITE_LABEL == $implementation_type ) {
			$nonce   = $this->wp_facade->wp_create_nonce( static::NONCE_KEY );
			$display = $this->template->render_template( 'personal-options/white-label', array(
				'app_display_name'    => $app_display_name,
				'nonce'               => $nonce,
				'pair_uri'            => $this->wp_facade->admin_url( '/admin-ajax.php?action=' .
				                                                      LaunchKey_WP_Native_Client::WHITE_LABEL_PAIR_ACTION ),
				'paired'              => isset( $user->launchkey_username ) ? 'true' : 'false',
				'has_password'        => empty( $user->user_pass ) ? 'false' : 'true',
				'password_remove_uri' => $this->wp_facade->admin_url( '/profile.php?launchkey_remove_password=1&launchkey_nonce=' .
				                                                      $nonce )
			) );
		}

		return $display;
	}

	/**
	 * @return mixed
	 */
	private function get_option() {
		return $this->is_multi_site ? $this->wp_facade->get_site_option( LaunchKey_WP_Admin::OPTION_KEY ) : $this->wp_facade->get_option( LaunchKey_WP_Admin::OPTION_KEY );
	}
}
