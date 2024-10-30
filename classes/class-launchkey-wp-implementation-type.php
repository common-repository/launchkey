<?php
/**
 * @package launchkey
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

class LaunchKey_WP_Implementation_Type
{
	const OAUTH = 'oauth';

	const NATIVE = 'native';

	const WHITE_LABEL = 'white-label';

	const SSO = 'sso';

	/**
	 * Is the provided implementation type valid?
	 *
	 * @param string $implementation_type
	 *
	 * @return bool
	 */
	public static function is_valid( $implementation_type ) {
		return in_array( $implementation_type, array( static::OAUTH, static::NATIVE, static::WHITE_LABEL, static::SSO ) );
	}

	/**
	 * Does the provided implmentation type require an RSA private key?
	 *
	 * @param string $implementation_type
	 *
	 * @return bool
	 */
	public static function requires_private_key( $implementation_type ) {
		return static::OAUTH !== $implementation_type;
	}
}
