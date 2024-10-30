<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Service\Exception;

/**
 * Exception throw when an auth request is made but the user has no paired devices
 *
 * @package LaunchKey\SDK\Service\Exception
 */
class NoPairedDevicesError extends \Exception
{
    // Intentionally left blank
}
