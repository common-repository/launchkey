<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\EventDispatcher;


use LaunchKey\SDK\Event\Event;

/**
 * Interface for performing event dispatching
 *
 * @package LaunchKey\SDK\Service
 */
interface EventDispatcher
{
    /**
     * Dispatch the event to all subscribers that have subscribed to the provided event name.
     *
     * @param string $eventName Name of the event.
     * @param Event $event
     */
    public function dispatchEvent($eventName, Event $event);

    /**
     * @param string $eventName Name of the event
     * @param string|array|callable $callable Callable to be executed when the event is dispatched.  For more information
     * on callables as related to your PHP version, @see http://php.net/manual/en/language.types.callable.php
     * @param integer $priority Priority of the callable for the event name.  Higher priority will executed before lower priority.
     * Callables with the same priority cannot be guaranteed to execute in the order in which they are added.
     */
    public function subscribe($eventName, $callable, $priority = 0);
}
