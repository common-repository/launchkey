<?php

/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */
class LaunchKey_WP_SAML2_Response_Service {

	/**
	 * @var array|SAML2_Assertion[]
	 */
	private $assertions = array();

	/**
	 * @var XMLSecurityKey
	 */
	private $security_key;

	/**
	 * @var string
	 */
	private $destination;

	/**
	 * @var LaunchKey_WP_Global_Facade
	 */
	private $facade;

	/**
	 * LaunchKey_WP_SAML2_Response_Service constructor.
	 *
	 * @param XMLSecurityKey $security_key
	 * @param LaunchKey_WP_Global_Facade $facade
	 */
	public function __construct( XMLSecurityKey $security_key, LaunchKey_WP_Global_Facade $facade ) {
		$this->security_key = $security_key;
		$this->facade       = $facade;
	}

	/**
	 * @param string $saml_response Base64 Encoded SAML
	 *
	 * @throws Exception When no assertions are found or signature in invalid
	 */
	public function load_saml_response( $saml_response ) {
		$response_element = SAML2_DOMDocumentFactory::fromString( base64_decode( $saml_response ) )->documentElement;
		$signature_info   = SAML2_Utils::validateElement( $response_element );
		SAML2_Utils::validateSignature( $signature_info, $this->security_key );
		$response          = SAML2_StatusResponse::fromXML( $response_element );
		$this->destination = $response->getDestination();
		$assertions        = $response->getAssertions();
		$this->assertions  = $assertions;
	}

	/**
	 * @return string
	 * @throws Exception
	 */
	public function get_name() {
		foreach ( $this->assertions as $assertion ) {
			$assertion->decryptNameId( $this->security_key );
			$name_id = $assertion->getNameId();
			if ( $name_id ) {
				$name = $name_id['Value'];
				break;
			}
		}

		return $name;
	}

	/**
	 * @return string
	 */
	public function get_session_index() {
		foreach ( $this->assertions as $assertion ) {
			$index = $assertion->getSessionIndex();
			if ( $index ) {
				break;
			}
		}

		return $index;
	}

	/**
	 * @param string $name Attribute name
	 *
	 * @return array
	 */
	public function get_attribute( $name ) {
		$value = null;
		foreach ( $this->assertions as $assertion ) {
			$attributes = $assertion->getAttributes();
			if ( array_key_exists( $name, $attributes ) ) {
				$value = $attributes[ $name ];
				break;
			}
		}

		return $value;
	}

	/**
	 * Is the entity ID provided within the audience restrictions of the response.
	 *
	 * @param string $entity_id Entity ID to validate
	 *
	 * @return bool
	 */
	public function is_entity_in_audience( $entity_id ) {
		$valid = true;
		foreach ( $this->assertions as $assertion ) {
			if ( $assertion->getValidAudiences() && ! in_array( $entity_id, $assertion->getValidAudiences() ) ) {
				$valid = false;
				break;
			}
		}

		return $valid;
	}

	/**
	 * Is the provided timestamp within the conditional time window of the response
	 *
	 * @param int $timestamp Timestamp to validate
	 *
	 * @return bool
	 */
	public function is_timestamp_within_restrictions( $timestamp ) {
		$valid = true;
		foreach ( $this->assertions as $assertion ) {
			if ( ( $assertion->getNotBefore() && $timestamp < $assertion->getNotBefore() ) ||
			     ( $assertion->getNotOnOrAfter() && $timestamp >= $assertion->getNotOnOrAfter() )
			) {
				$valid = false;
				break;
			}
		}

		return $valid;
	}

	/**
	 * Is the provided destination URL the destination URL for the response.
	 *
	 * @param string $destination Destination URL to validate
	 *
	 * @return bool
	 */
	public function is_valid_destination( $destination ) {
		return $destination === $this->destination;
	}

	/**
	 * Register the current session index to prevent replay
	 * @throw Exception DB errors throw exceptions
	 */
	public function register_session_index() {
		$db    = $this->facade->get_wpdb();
		$date  = date( "Y-m-d H:i:s" );
		$query = $db->prepare(
			"INSERT INTO {$db->prefix}launchkey_sso_sessions VALUES (%s, %s) ON DUPLICATE KEY UPDATE seen = %s",
			$this->get_session_index(),
			$date,
			$date
		);
		$db->query( $query );
		if ( $db->last_error ) {
			throw new Exception( sprintf( "Database Error: %s", $db->last_error ) );
		}
	}

	/**
	 * Is the current session index registered. If so, this is a replay
	 * @return bool Registered
	 * @throws Exception DB errors throw exceptions
	 */
	public function is_session_index_registered() {
		$db    = $this->facade->get_wpdb();
		$query = $db->prepare(
			"SELECT COUNT(*) FROM {$db->prefix}launchkey_sso_sessions WHERE id = %s",
			$this->get_session_index()
		);
		$count = $db->get_var( $query );
		if ( $db->last_error ) {
			throw new Exception( sprintf( "Database Error: %s", $db->last_error ) );
		}

		return $count > 0;
	}
}
