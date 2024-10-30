<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Event;


use LaunchKey\SDK\Domain\AuthRequest;

/**
 * Event dispatched after the SDK initiates a LaunchKey authorization request
 *
 * @package LaunchKey\SDK\Event
 */
class AuthRequestEvent extends AbstractEvent
{
    const NAME = "launchkey.auth.request";

    /**
     * @var AuthRequest
     */
    private $authRequest;

    public function __construct(AuthRequest $authRequest)
    {
        $this->authRequest = $authRequest;
    }

    /**
     * @return AuthRequest
     */
    public function getAuthRequest()
    {
        return $this->authRequest;
    }
}
