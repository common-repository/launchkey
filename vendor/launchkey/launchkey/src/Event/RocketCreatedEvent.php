<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2016 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Event;


use LaunchKey\SDK\Domain\RocketCreated;

/**
 * Event dispatched after the SDK receives a LaunchKey config request
 *
 * @package LaunchKey\SDK\Event
 */
class RocketCreatedEvent extends AbstractEvent
{
    const NAME = "launchkey.callback.rocket-created";

    /**
     * @var RocketCreated
     */
    private $rocketCreated;

    /**
     * RocketCreatedEvent constructor.
     *
     * @param RocketCreated $rocketCreated Rocket data from rocket creation callback request
     */
    public function __construct(RocketCreated $rocketCreated)
    {
        $this->rocketCreated = $rocketCreated;
    }

    /**
     * Get the config data from callback request
     *
     * @return RocketCreated Rocket created callback data
     */
    public function getRocketCreated()
    {
        return $this->rocketCreated;
    }
}
