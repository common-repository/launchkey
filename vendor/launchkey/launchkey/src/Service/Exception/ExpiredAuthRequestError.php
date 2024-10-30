<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Service\Exception;

/**
 * Exception for errors that occur due to the identified auth request having expired when communicating with the
 * LaunchKey Engine API
 *
 * @package LaunchKey\SDK\Service\Exception
 */
class ExpiredAuthRequestError extends \Exception
{
    // Intentionally left blank
}
