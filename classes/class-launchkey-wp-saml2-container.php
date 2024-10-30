<?php

/**
 * @since 1.1.0
 * @package launchkey
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */
class LaunchKey_WP_SAML2_Container extends SAML2_Compat_AbstractContainer {
	/**
	 * @var \Psr\Log\LoggerInterface
	 */
	private $logger;

	/**
	 * LaunchKey_WP_SAML2_Container constructor.
	 *
	 * @param \Psr\Log\LoggerInterface $logger
	 */
	public function __construct( \Psr\Log\LoggerInterface $logger ) {
		$this->logger = $logger;
	}

	/**
	 * Get a PSR-3 compatible logger.
	 * @return Psr\Log\LoggerInterface
	 */
	public function getLogger() {
		return $this->logger;
	}

	/**
	 * Generate a random identifier for identifying SAML2 documents.
	 */
	public function generateId() {
		$data = '_';
        for($i = 0; $i < 21; $i++) {
            $data .= sprintf('%02x', ord(chr(mt_rand(0, 255))));
        }

        return $data;
	}

	/**
	 * Log an incoming message to the debug log.
	 *
	 * Type can be either:
	 * - **in** XML received from third party
	 * - **out** XML that will be sent to third party
	 * - **encrypt** XML that is about to be encrypted
	 * - **decrypt** XML that was just decrypted
	 *
	 * @param string $message
	 * @param string $type
	 *
	 * @return void
	 */
	public function debugMessage( $message, $type ) {
		$this->getLogger()->debug("Incoming message", array("type" => $type, "XML message" => $message));
	}

	/**
	 * Trigger the user to perform a GET to the given URL with the given data.
	 *
	 * @param string $url
	 * @param array $data
	 *
	 * @return void
	 */
	public function redirect( $url, $data = array() ) {
		$this->redirect_url = sprintf('%s?%s', $url, http_build_query($data));
	}

	/**
	 * Trigger the user to perform a POST to the given URL with the given data.
	 *
	 * @param string $url
	 * @param array $data
	 *
	 * @return void
	 */
	public function postRedirect( $url, $data = array() ) {
		$this->redirect($url, $data);
	}

	/**
	 * @return string
	 */
	public function getRedirectUrl() {
		return $this->redirect_url;
	}
}
