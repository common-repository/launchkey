<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Event;

/**
 * Abstract event to provide propagation handling for LaunchKey SDK events
 *
 * @package LaunchKey\SDK\Event
 */
abstract class AbstractEvent implements Event
{
    protected $propagationStopped = false;

    public function stopPropagation()
    {
        $this->propagationStopped = true;
    }


    public function isPropagationStopped()
    {
        return $this->propagationStopped;
    }
}
