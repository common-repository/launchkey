<?php

/**
 * @package launchkey
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 *
 * Templating support
 *
 * Templating support for the plugin
 *
 * @since 1.0.0
 */
class LaunchKey_WP_Template {

	/**
	 * @var array
	 */
	private $templates = array();

	/**
	 * @var string
	 */
	private $templates_directory;

	/**
	 * @var LaunchKey_WP_Global_Facade
	 */
	private $wp_facade;

	/**
	 * @var string
	 */
	private $language_domain;

	/**
	 * LaunchKey_WP_Template constructor.
	 *
	 * @param string $templates_directory
	 * @param LaunchKey_WP_Global_Facade $wp_facade
	 * @param string $language_domain
	 */
	public function __construct( $templates_directory, LaunchKey_WP_Global_Facade $wp_facade, $language_domain ) {
		$this->templates_directory = $templates_directory;
		$this->wp_facade           = $wp_facade;
		$this->language_domain     = $language_domain;
	}

	/**
	 * Render a template from templates directory with the provided context.  The context values
	 * will be translated using the language domain specified in the construct
	 *
	 * @since 1.0.0
	 *
	 * @param $string
	 * @param array $context
	 *
	 * @return string
	 */
	public function render_template( $string, array $context = array() ) {
		$wp_facade = $this->wp_facade;
		$language_domain = $this->language_domain;
		if ( ! isset( $this->templates[ $string ] ) ) {
			$file                       = sprintf( '%s/%s.html', $this->templates_directory, $string );
			$this->templates[ $string ] = file_get_contents( $file );
		}
		$search = $replace = array();
		array_walk( $context, function ( $value, $key ) use ( &$search, &$replace, $language_domain, $wp_facade ) {
			array_push( $search, "%%%{$key}%%%" );
			array_push( $replace, $wp_facade->__( $value, $language_domain ) );
		} );
		$complete = str_replace( $search, $replace, $this->templates[ $string ] );

		return $complete;
	}
}
