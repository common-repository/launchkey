<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Service\Exception;

/**
 * Exception for instances where a callback request is made to the handleCallback method of an API service which
 * does not know how to handle the data provided.
 *
 * @package LaunchKey\SDK\Service\Exception
 */
class UnknownCallbackActionError extends \Exception
{
    // Intentionally left blank
}
