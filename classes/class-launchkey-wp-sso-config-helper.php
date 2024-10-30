<?php

/**
 * @since 1.1.0
 * @package launchkey
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */
class LaunchKey_WP_SSO_Config_Helper {

	/**
	 * @var SAML2_XML_md_EntityDescriptor
	 */
	private $entityDescriptor;

	/**
	 * LaunchKey_WP_SSO_Config_Helper constructor.
	 *
	 * @param SAML2_XML_md_EntityDescriptor $entityDescriptor
	 */
	public function __construct( SAML2_XML_md_EntityDescriptor $entityDescriptor ) {
		$this->entityDescriptor = $entityDescriptor;
	}

	/**
	 * @param $file_name
	 *
	 * @return static
	 */
	public static function from_xml_file( $file_name ) {
		$doc = SAML2_DOMDocumentFactory::fromFile( $file_name );

		return static::from_DOM_document( $doc );
	}

	/**
	 * @param $xml_string
	 *
	 * @return static
	 */
	public static function from_xml_string( $xml_string ) {
		$doc = SAML2_DOMDocumentFactory::fromString( $xml_string );

		return static::from_DOM_document( $doc );
	}

	/**
	 * @param DOMDocument $doc
	 *
	 * @return static
	 */
	public static function from_DOM_document( DOMDocument $doc ) {
		return new static( new SAML2_XML_md_EntityDescriptor( $doc->documentElement ) );
	}

	/**
	 * @return null|string
	 */
	public function get_SSO_redirect() {
		$url = null;
		foreach ( $this->get_IDP_SSO_descriptor()->SingleSignOnService as $endpoint ) {
			if ( SAML2_Const::BINDING_HTTP_REDIRECT == $endpoint->Binding ) {
				$url = $endpoint->Location;
				break;
			}
		}
		return $url;
	}

	/**
	 * @return null|string
	 */
	public function get_SLO_redirect() {
		$url = null;
		foreach ( $this->get_IDP_SSO_descriptor()->SingleLogoutService as $endpoint ) {
			if ( SAML2_Const::BINDING_HTTP_REDIRECT == $endpoint->Binding ) {
				$url = $endpoint->Location;
				break;
			}
		}
		return $url;
	}

	/**
	 * @return null|string
	 */
	public function get_error_redirect() {
		return $this->get_IDP_SSO_descriptor()->errorURL;
	}

	/**
	 * @return string
	 */
	public function get_name_ID_format() {
		return $this->get_IDP_SSO_descriptor()->NameIDFormat[0];
	}

	public function get_X509_certificate() {
		$cert = null;
		foreach ($this->get_IDP_SSO_descriptor()->KeyDescriptor as $key_descriptor) {
			foreach ($key_descriptor->KeyInfo->info as $key_info) {
				if ($key_info instanceof SAML2_XML_ds_X509Data) {
					foreach ($key_info->data as $data) {
						if ($data instanceof SAML2_XML_ds_X509Certificate) {
							$cert = SAML2_Certificate_X509::createFromCertificateData($data->certificate)->getCertificate();
						}
					}
				}
			}
		}
		return $cert;
	}

	/**
	 * @return SAML2_XML_md_IDPSSODescriptor
	 */
	private function get_IDP_SSO_descriptor() {
		$descriptor = null;
		foreach ( $this->entityDescriptor->RoleDescriptor as $role_descriptor ) {
			if ( $role_descriptor instanceof SAML2_XML_md_IDPSSODescriptor ) {
				$descriptor = $role_descriptor;
			}
		}
		return $descriptor;
	}
}
