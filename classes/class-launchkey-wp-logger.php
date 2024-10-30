<?php

/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 * @since 1.1.0
 */
class LaunchKey_WP_Logger implements Psr\Log\LoggerInterface {

	/**
	 * @var LaunchKey_WP_Global_Facade
	 */
	private $wp_facade;

	/**
	 * LaunchKey_WP_Logger constructor.
	 *
	 * @param LaunchKey_WP_Global_Facade $wp_facade
	 */
	public function __construct( LaunchKey_WP_Global_Facade $wp_facade ) {
		$this->wp_facade = $wp_facade;
	}

	/**
	 * System is unusable.
	 *
	 * @param string $message
	 * @param array $context
	 *
	 * @return null
	 */
	public function emergency( $message, array $context = array() ) {
		$this->log( "EMERGENCY", $message, $context );
	}

	/**
	 * Action must be taken immediately.
	 *
	 * Example: Entire website down, database unavailable, etc. This should
	 * trigger the SMS alerts and wake you up.
	 *
	 * @param string $message
	 * @param array $context
	 *
	 * @return null
	 */
	public function alert( $message, array $context = array() ) {
		$this->log( "ALERT", $message, $context );
	}

	/**
	 * Critical conditions.
	 *
	 * Example: Application component unavailable, unexpected exception.
	 *
	 * @param string $message
	 * @param array $context
	 *
	 * @return null
	 */
	public function critical( $message, array $context = array() ) {
		$this->log( "CRITICAL", $message, $context );
	}

	/**
	 * Runtime errors that do not require immediate action but should typically
	 * be logged and monitored.
	 *
	 * @param string $message
	 * @param array $context
	 *
	 * @return null
	 */
	public function error( $message, array $context = array() ) {
		$this->log( "ERROR", $message, $context );
	}

	/**
	 * Exceptional occurrences that are not errors.
	 *
	 * Example: Use of deprecated APIs, poor use of an API, undesirable things
	 * that are not necessarily wrong.
	 *
	 * @param string $message
	 * @param array $context
	 *
	 * @return null
	 */
	public function warning( $message, array $context = array() ) {
		$this->debug_log( "WARNING", $message, $context );
	}

	/**
	 * Normal but significant events.
	 *
	 * @param string $message
	 * @param array $context
	 *
	 * @return null
	 */
	public function notice( $message, array $context = array() ) {
		$this->debug_log( "NOTICE", $message, $context );
	}

	/**
	 * Interesting events.
	 *
	 * Example: User logs in, SQL logs.
	 *
	 * @param string $message
	 * @param array $context
	 *
	 * @return null
	 */
	public function info( $message, array $context = array() ) {
		$this->debug_log( "INFO", $message, $context );
	}

	/**
	 * Detailed debug information.
	 *
	 * @param string $message
	 * @param array $context
	 *
	 * @return null
	 */
	public function debug( $message, array $context = array() ) {
		$this->debug_log( "DEBUG", $message, $context );
	}

	/**
	 * Logs with an arbitrary level.
	 *
	 * @param mixed $level
	 * @param string $message
	 * @param array $context
	 *
	 * @return null
	 */
	public function log( $level, $message, array $context = array() ) {
		$context_string = "";
		foreach ( $context as $key => $value ) {
			$context_string .= ( "\n\t" . $key . ": " . (string) $value );
		}
		$this->wp_facade->error_log( sprintf( "[%s] %s%s", $level, $message, $context_string ) );
	}

	private function debug_log( $level, $message, array $context = array() ) {
		if ( $this->wp_facade->is_debug_log() ) {
			$this->log( $level, $message, $context );
		}
	}
}
