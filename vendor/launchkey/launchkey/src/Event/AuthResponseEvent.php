<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Event;

use LaunchKey\SDK\Domain\AuthResponse;

/**
 * Event dispatched after the SDK receives a LaunchKey authorization response from either a poll request or a
 * LaunchKey engine callback
 *
 * @package LaunchKey\SDK\Event
 */
class AuthResponseEvent extends AbstractEvent
{
    const NAME = "launchkey.auth.response";

    /**
     * @var AuthResponse
     */
    private $authResponse;

    public function __construct(AuthResponse $authResponse)
    {
        $this->authResponse = $authResponse;
    }

    /**
     * @return AuthResponse
     */
    public function getAuthResponse()
    {
        return $this->authResponse;
    }
}
