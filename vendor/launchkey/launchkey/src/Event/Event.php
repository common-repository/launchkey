<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Event;

/**
 * Interface for LaunchKey SDK events
 *
 * @package LaunchKey\SDK\Event
 */
interface Event
{
    public function stopPropagation();

    public function isPropagationStopped();
}
