<?php

/**
 * @since 1.0.0
 * @package launchkey
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */
class LaunchKey_WP_Options {

	/**
	 * Option of the version itself.  This is not representative of the plugin version.
	 * @since 1.0.0
	 * @var string
	 */
	const VERSION = '1.1.0';

	const OPTION_IMPLEMENTATION_TYPE = 'implementation_type';
	const OPTION_ROCKET_KEY = 'rocket_key';
	const OPTION_SECRET_KEY = 'secret_key';
	const OPTION_PRIVATE_KEY = 'private_key';
	const OPTION_APP_DISPLAY_NAME = 'app_display_name';
	const OPTION_SSL_VERIFY = 'ssl_verify';
	const OPTION_REQUEST_TIMEOUT = 'request_timeout';
	const OPTION_LEGACY_OAUTH = 'legacy_oauth';
	const OPTION_SSO_ENTITY_ID = 'sso_entity_id';
	const OPTION_SSO_CERTIFICATE = 'sso_certificate';
	const OPTION_SSO_LOGIN_URL = 'sso_login_url';
	const OPTION_SSO_LOGOUT_URL = 'sso_logout_url';
	const OPTION_SSO_ERROR_URL = 'sso_error_url';

	/**
	 * @since 1.1.0
	 */
	const OPTION_VERSION = 'version';

	const STATIC_IV = '6CC8B88C26AA10B8F95B107837393BA35C62509605369FADDD545BF8FC76AD38';

	/**
	 * @var array
	 */
	private $cache;

	/**
	 * @var \phpseclib\Crypt\AES
	 */
	private $crypt_aes;

	/**
	 * LaunchKey_WP_Options constructor.
	 *
	 * @param \phpseclib\Crypt\AES $crypt_aes
	 */
	public function __construct( \phpseclib\Crypt\AES $crypt_aes ) {
		$this->crypt_aes = $crypt_aes;
		$this->cache = array();
	}

	/**
	 * Process the launchkey option to prepare for storage in the database.  The method will encrypt the data and set
	 * the current version so that the option may be programmatically updated in place in the future.
	 *
	 * @since 1.0.0
	 *
	 * @param array $input
	 *
	 * @return array
	 */
	public function pre_update_option_filter( array $input ) {
		$output = $input;

		$output['version'] = static::VERSION;

		if ( !empty( $input[LaunchKey_WP_Options::OPTION_SECRET_KEY] ) ) {

			$key = md5( $input[LaunchKey_WP_Options::OPTION_SECRET_KEY] );

			if ( empty( $this->cache[$key] ) ) {
				/**
				 * Use the rocket key as the IV. If null, use the static value.
				 * @link https://docs.launchkey.com/glossary.html#term-iv
				 */
				$iv = empty( $input[LaunchKey_WP_Options::OPTION_ROCKET_KEY] ) ? static::STATIC_IV : $input[LaunchKey_WP_Options::OPTION_ROCKET_KEY];
				$this->crypt_aes->setIV( $iv );

				/**
				 * Encrypt and Base64 encode the encrypted value and set it as the output value
				 * @link https://docs.launchkey.com/glossary.html#term-base64
				 */
				$this->cache[$key] = base64_encode( $this->crypt_aes->encrypt( $input[LaunchKey_WP_Options::OPTION_SECRET_KEY] ) );
			}

			$output[LaunchKey_WP_Options::OPTION_SECRET_KEY] = $this->cache[$key];
		} else {
			$output[LaunchKey_WP_Options::OPTION_SECRET_KEY] = null;
		}

		if ( !empty( $input[LaunchKey_WP_Options::OPTION_PRIVATE_KEY] ) ) {

			$key = md5( $input[LaunchKey_WP_Options::OPTION_PRIVATE_KEY] );

			if ( empty( $this->cache[$key] ) ) {
				/**
				 * Use the decrypted secret key as the IV. If null, use the static value.
				 * @link https://docs.launchkey.com/glossary.html#term-iv
				 */
				$iv = empty( $input[LaunchKey_WP_Options::OPTION_SECRET_KEY] ) ? static::STATIC_IV : $input[LaunchKey_WP_Options::OPTION_SECRET_KEY];
				$this->crypt_aes->setIV( $iv );

				/**
				 * Encrypt and Base64 encode the encrypted value and set it as the output value
				 * @link https://docs.launchkey.com/glossary.html#term-base64
				 */
				$this->cache[$key] = base64_encode( $this->crypt_aes->encrypt( $input[LaunchKey_WP_Options::OPTION_PRIVATE_KEY] ) );
			}
			$output[LaunchKey_WP_Options::OPTION_PRIVATE_KEY] = $this->cache[$key];
		} else {
			$output[LaunchKey_WP_Options::OPTION_PRIVATE_KEY] = null;
		}

		return $output;
	}

	/**
	 * Process the launchkey option to prepare for usage within the plugin.  The option will have encrypted attributes
	 * decrypted as well as set default values for any missing or unset attributes.
	 *
	 * @since 1.0.0
	 *
	 * @param $input
	 *
	 * @return array
	 */
	public function post_get_option_filter( $input ) {
		// Define the defaults for attributes
		$defaults = static::get_defaults();

		// If the input is empty (null) set it to an empty array
		$input ?: array();

		// Merge the input array over the defaults array to set any know data to the response
		$output = array_merge( $defaults, $input );

		// If the secret key attribute is not empty, decrypt it
		if ( !empty( $input[LaunchKey_WP_Options::OPTION_SECRET_KEY] ) ) {

			$key = md5( $input[LaunchKey_WP_Options::OPTION_SECRET_KEY] );

			if ( empty( $this->cache[$key] ) ) {
				/**
				 * Use the rocket key as the IV. If null, use the static value.
				 * @link https://docs.launchkey.com/glossary.html#term-iv
				 */
				$iv = empty( $output[LaunchKey_WP_Options::OPTION_ROCKET_KEY] ) ? static::STATIC_IV : $output[LaunchKey_WP_Options::OPTION_ROCKET_KEY];
				$this->crypt_aes->setIV( $iv );

				/**
				 * Decrypt the Base64 decoded string and set it as the output value
				 * @link https://docs.launchkey.com/glossary.html#term-base64
				 */
				$this->cache[$key] = $this->crypt_aes->decrypt( base64_decode( $input[LaunchKey_WP_Options::OPTION_SECRET_KEY] ) );
			}

			$output[LaunchKey_WP_Options::OPTION_SECRET_KEY] = $this->cache[$key];
		}

		// If the private key attribute is not empty, decrypt it
		if ( !empty( $input[LaunchKey_WP_Options::OPTION_PRIVATE_KEY] ) ) {

			$key = md5( $input[LaunchKey_WP_Options::OPTION_PRIVATE_KEY] );

			if ( empty( $this->cache[$key] ) ) {
				/**
				 * Use the decrypted secret key as the IV. If null, use the static value.
				 * @link https://docs.launchkey.com/glossary.html#term-iv
				 */
				$iv = empty( $output[LaunchKey_WP_Options::OPTION_SECRET_KEY] ) ? static::STATIC_IV : $output[LaunchKey_WP_Options::OPTION_SECRET_KEY];
				$this->crypt_aes->setIV( $iv );

				/**
				 * Decrypt the Base64 decoded string and set it as the output value
				 * @link https://docs.launchkey.com/glossary.html#term-base64
				 *
				 * We are suppressing errors as
				 */
				$this->cache[$key] = @$this->crypt_aes->decrypt( base64_decode( $input[LaunchKey_WP_Options::OPTION_PRIVATE_KEY] ) );
			}
			$output[LaunchKey_WP_Options::OPTION_PRIVATE_KEY] = $this->cache[$key];
		}

		return $output;
	}

	/**
	 * Get the option defaults
	 *
	 * Get an array of LaunchKey Options pre-populated with the default values.
	 *
	 * @return array
	 *
	 * @since 1.0.0
	 */
	public static function get_defaults() {
		$defaults = array(
			static::OPTION_ROCKET_KEY => null,
			static::OPTION_SECRET_KEY => null,
			static::OPTION_PRIVATE_KEY => null,
			static::OPTION_APP_DISPLAY_NAME => 'LaunchKey',
			static::OPTION_SSL_VERIFY => true,
			static::OPTION_IMPLEMENTATION_TYPE => null,
			static::OPTION_REQUEST_TIMEOUT => 60,
			static::OPTION_LEGACY_OAUTH => false,
			// Since 1.1.0
			static::OPTION_SSO_ENTITY_ID => null,
			static::OPTION_SSO_CERTIFICATE => null,
			static::OPTION_SSO_LOGIN_URL => null,
			static::OPTION_SSO_LOGOUT_URL => null,
			static::OPTION_SSO_ERROR_URL => null,
			static::OPTION_VERSION => 0.0
		);

		return $defaults;
	}
}
