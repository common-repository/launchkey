<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\EventDispatcher;


use LaunchKey\SDK\Event\Event;

/**
 * Implementation of EventDispatcher that will process events locally and synchronously
 *
 * @package LaunchKey\SDK\EventDispatcher
 */
class SynchronousLocalEventDispatcher implements EventDispatcher
{
    private $subscriptions = array();

    /**
     * Dispatch the event to all subscribers that have subscribed to the provided event name.
     *
     * @param string $eventName Name of the event.
     * @param Event $event
     */
    public function dispatchEvent($eventName, Event $event)
    {
        $subscriptionPriorities = isset($this->subscriptions[$eventName]) ? $this->subscriptions[$eventName] : null;
        if ($subscriptionPriorities) {
            krsort($subscriptionPriorities);
            array_walk($subscriptionPriorities, function (array $subscriptions)use ($event, $eventName)  {
                array_walk($subscriptions, function ($callable) use ($event, $eventName) {
                    if (!$event->isPropagationStopped()) {
                        call_user_func($callable, $eventName, $event);
                    }
                });
            });
        }
    }

    /**
     * @param string $eventName Name of the event
     * @param string|array|callable $callable Callable to be executed when the event is dispatched.  For more information
     * on callables as related to your PHP version, @see http://php.net/manual/en/language.types.callable.php
     * @param integer $priority Priority of the callable for the event name.  Higher priority will executed before lower priority.
     * Callables with the same priority cannot be guaranteed to execute in the order in which they are added.
     */
    public function subscribe($eventName, $callable, $priority = 0)
    {
        $this->subscriptions[$eventName][$priority][] = $callable;
    }
}
