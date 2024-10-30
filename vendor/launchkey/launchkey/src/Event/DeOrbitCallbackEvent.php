<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Event;


use LaunchKey\SDK\Domain\DeOrbitCallback;

/**
 * Event dispatched after the SDK receives a LaunchKey deorbit response
 *
 * @package LaunchKey\SDK\Event
 */
class DeOrbitCallbackEvent extends AbstractEvent
{
    const NAME = "launchkey.callback.de-orbit";

    /**
     * @var DeOrbitCallback
     */
    private $deOrbitCallback;

    function __construct(DeOrbitCallback $deOrbitCallback)
    {
        $this->deOrbitCallback = $deOrbitCallback;
    }

    /**
     * @return DeOrbitCallback
     */
    public function getDeOrbitCallback()
    {
        return $this->deOrbitCallback;
    }
}
