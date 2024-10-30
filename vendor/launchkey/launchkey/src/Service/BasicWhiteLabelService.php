<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Service;

use LaunchKey\SDK\Domain\WhiteLabelUser;
use LaunchKey\SDK\Event\WhiteLabelUserCreatedEvent;
use LaunchKey\SDK\EventDispatcher\EventDispatcher;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;

/**
 * Basic implementation of the WhiteLabelService providing event dispatching abd logging
 * @package LaunchKey\SDK\Service
 */
class BasicWhiteLabelService implements WhiteLabelService
{
    /**
     * @var ApiService
     */
    private $apiService;

    /**
     * @var EventDispatcher
     */
    private $eventDispatcher;

    /**
     * @var LoggerAwareInterface
     */
    private $logger;

    /**
     * @param ApiService $apiService
     * @param EventDispatcher $eventDispatcher
     * @param LoggerInterface $logger
     */
    public function __construct(
        ApiService $apiService,
        EventDispatcher $eventDispatcher,
        LoggerInterface $logger = null
    )
    {
        $this->apiService = $apiService;
        $this->eventDispatcher = $eventDispatcher;
        $this->logger = $logger;
    }

    /**
     * @inheritdoc
     */
    public function createUser($identifier) {
        $this->debugLog("Initiating white label user create request", array("identifier" => $identifier));
        $user = $this->apiService->createWhiteLabelUser($identifier);
        $this->debugLog("White label user created", array("user" => $user));
        $this->eventDispatcher->dispatchEvent(WhiteLabelUserCreatedEvent::NAME, new WhiteLabelUserCreatedEvent($user));
        return $user;
    }

    /**
     * @param $message
     * @param $context
     */
    private function debugLog($message, $context)
    {
        if ($this->logger) $this->logger->debug($message, $context);
    }
}
