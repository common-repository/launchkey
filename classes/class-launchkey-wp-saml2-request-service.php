<?php

/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */
class LaunchKey_WP_SAML2_Request_Service {

	/**
	 * @var XMLSecurityKey
	 */
	private $security_key;

	/**
	 * @var string
	 */
	private $session_index;

	/**
	 * @var string
	 */
	private $name;

	/**
	 * @var string
	 */
	private $destination;

	/**
	 * @var int timestamp
	 */
	private $notOnOrAfter;

	/**
	 * LaunchKey_WP_SAML2_Response_Service constructor.
	 *
	 * @param XMLSecurityKey $security_key
	 */
	public function __construct( XMLSecurityKey $security_key ) {
		$this->security_key = $security_key;
	}

	/**
	 * @param string $saml_request Base64 Encoded SAML
	 *
	 * @throws Exception When signature in invalid
	 */
	public function load_saml_request( $saml_request ) {
		$request_element = SAML2_DOMDocumentFactory::fromString( base64_decode( $saml_request ) )->documentElement;
		$signature_info  = SAML2_Utils::validateElement( $request_element );
		SAML2_Utils::validateSignature( $signature_info, $this->security_key );
		/** @var SAML2_LogoutRequest $request */
		$request = SAML2_LogoutRequest::fromXML( $request_element );
		$request->decryptNameId( $this->security_key );
		$name_id = $request->getNameId();

		$this->notOnOrAfter  = $request->getNotOnOrAfter();
		$this->name          = $name_id ? $name_id['Value'] : null;
		$this->session_index = $request->getSessionIndex();
		$this->destination   = $request->getDestination();
	}

	/**
	 * @return string
	 * @throws Exception
	 */
	public function get_name() {
		return $this->name;
	}

	/**
	 * @return string
	 */
	public function get_session_index() {
		return $this->session_index;
	}

	/**
	 * Is the provided timestamp within the conditional time window of the response
	 *
	 * @param int $timestamp Timestamp to validate
	 *
	 * @return bool
	 */
	public function is_timestamp_within_restrictions( $timestamp ) {
		return $timestamp < $this->notOnOrAfter;
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
}
