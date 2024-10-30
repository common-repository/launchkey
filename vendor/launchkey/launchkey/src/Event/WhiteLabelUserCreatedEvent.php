<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Event;


use LaunchKey\SDK\Domain\WhiteLabelUser;

/**
 * Event for successful creation of a white label user
 *
 * @package LaunchKey\SDK\Event
 */
class WhiteLabelUserCreatedEvent extends AbstractEvent
{
    const NAME = "launchkey.whitelabel.user.created";

    /**
     * @var WhiteLabelUser
     */
    private $whiteLabelUser;

    public function __construct(WhiteLabelUser $whiteLabelUser)
    {
        $this->whiteLabelUser = $whiteLabelUser;
    }

    /**
     * @return WhiteLabelUser
     */
    public function getWhiteLabelUser()
    {
        return $this->whiteLabelUser;
    }
}
