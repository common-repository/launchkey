<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Event;


use LaunchKey\SDK\Domain\DeOrbitRequest;

/**
 * Event dispatched after the SDK initiates a LaunchKey de-orbit response
 *
 * @package LaunchKey\SDK\Event
 */
class DeOrbitRequestEvent extends AbstractEvent
{
    const NAME = "launchkey.de-orbit.request";

    /**
     * @var DeOrbitRequest
     */
    private $deOrbitRequest;

    public function __construct(DeOrbitRequest $deOrbitRequest)
    {
        $this->deOrbitRequest = $deOrbitRequest;
    }

    /**
     * @return DeOrbitRequest
     */
    public function getDeOrbitRequest()
    {
        return $this->deOrbitRequest;
    }
}
