<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Event;

use LaunchKey\SDK\Domain\PingResponse;

/**
 * Event triggered after a ping response is received
 *
 * @package LaunchKey\SDK\Event
 */
class PingResponseEvent extends AbstractEvent
{
    const NAME = "launchkey.ping.response";

    /**
     * @var PingResponse
     */
    private $pingResponse;

    /**
     * @param PingResponse $pingResponse
     */
    public function __construct(PingResponse $pingResponse)
    {
        $this->pingResponse = $pingResponse;
    }

    /**
     * @return PingResponse
     */
    public function getPingResponse()
    {
        return $this->pingResponse;
    }
}
