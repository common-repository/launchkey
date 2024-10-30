<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Service;


use LaunchKey\SDK\Domain\AuthRequest;
use LaunchKey\SDK\Domain\AuthResponse;
use LaunchKey\SDK\Domain\DeOrbitCallback;
use LaunchKey\SDK\Domain\DeOrbitRequest;
use LaunchKey\SDK\Domain\RocketCreated;
use LaunchKey\SDK\Event\AuthRequestEvent;
use LaunchKey\SDK\Event\AuthResponseEvent;
use LaunchKey\SDK\Event\DeOrbitCallbackEvent;
use LaunchKey\SDK\Event\DeOrbitRequestEvent;
use LaunchKey\SDK\Event\RocketCreatedEvent;
use LaunchKey\SDK\EventDispatcher\EventDispatcher;
use LaunchKey\SDK\Service\Exception\CommunicationError;
use LaunchKey\SDK\Service\Exception\InvalidRequestError;
use Psr\Log\LoggerInterface;

/**
 * Basic implementation of the AuthService interface providing event dispatching abd logging
 *
 * @package LaunchKey\SDK\Service
 */
class BasicAuthService implements AuthService
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
     * @var LoggerInterface
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
    ) {
        $this->apiService      = $apiService;
        $this->eventDispatcher = $eventDispatcher;
        $this->logger          = $logger;
    }

    /**
     * @inheritdoc
     */
    public function authorize($username)
    {
        return $this->auth($username, false);
    }

    /**
     * @inheritdoc
     */
    public function authenticate($username)
    {
        return $this->auth($username, true);
    }

    /**
     * @inheritdoc
     */
    public function getStatus($authRequestId)
    {
        $this->debugLog("Sending poll request", array("authRequestId" => $authRequestId));
        $authResponse = $this->apiService->poll($authRequestId);
        $this->debugLog("poll response received", array("response" => $authResponse));
        try {
            $this->processAuthResponse($authResponse);
        } catch (\Exception $e) {
            if ($this->logger) {
                $this->logger->error("Error logging Authentication true", array("Exception" => $e));
            }
        }

        return $authResponse;
    }

    /**
     * @inheritdoc
     */
    public function deOrbit($authRequestId)
    {
        $this->debugLog("Logging Revoke true", array("authRequestId" => $authRequestId));
        $this->apiService->log($authRequestId, "Revoke", true);
        $this->eventDispatcher->dispatchEvent(
            DeOrbitRequestEvent::NAME,
            new DeOrbitRequestEvent(new DeOrbitRequest($authRequestId))
        );
    }

    /**
     * @inheritdoc
     */
    public function handleCallback(array $queryParameters)
    {
        $this->debugLog("Handling callback", array("data" => $queryParameters));
        $response = $this->apiService->handleCallback($queryParameters);
        if ($response instanceof DeOrbitCallback) {
            $this->debugLog("De-orbit callback determined", array("data" => $response));
            $this->eventDispatcher->dispatchEvent(DeOrbitCallbackEvent::NAME, new DeOrbitCallbackEvent($response));
        } elseif ($response instanceof AuthResponse) {
            $this->debugLog("Auth callback determined", array("data" => $response));
            $this->processAuthResponse($response);
        } elseif ($response instanceof RocketCreated) {
            $this->debugLog("Rocket creation callback determined", array("data" => $response));
            $this->eventDispatcher->dispatchEvent(
                RocketCreatedEvent::NAME,
                new RocketCreatedEvent($response)
            );
        }

        return $response;
    }

    /**
     * @inheritDoc
     */
    public function nonce()
    {
        $this->debugLog("Sending nonce request");
        $response = $this->apiService->nonce();
        $this->debugLog("API nonce response received", array("nonce" => $response));

        return $response;
    }


    /**
     * @param $username
     *
     * @return AuthRequest
     */
    private function auth($username, $session)
    {
        $this->debugLog("Sending auth request", array("username" => $username, "session" => $session));
        $authRequest = $this->apiService->auth($username, $session);
        $this->eventDispatcher->dispatchEvent(AuthRequestEvent::NAME, new AuthRequestEvent($authRequest));
        $this->debugLog("auth response received", array("response" => $authRequest));

        return $authRequest;
    }

    /**
     * @param AuthResponse $authResponse
     */
    private function processAuthResponse(AuthResponse $authResponse)
    {
        $this->eventDispatcher->dispatchEvent(AuthResponseEvent::NAME, new AuthResponseEvent($authResponse));
        if ($authResponse->isAuthorized()) {
            if ($this->logger) {
                $this->logger->debug("Logging Authenticate true");
            }
            $this->apiService->log($authResponse->getAuthRequestId(), "Authenticate", true);
        }
    }

    private function debugLog($message, $context = array())
    {
        if ($this->logger) {
            $this->logger->debug($message, $context);
        }
    }
}
