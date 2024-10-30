<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Service;


use LaunchKey\SDK\Domain\AuthRequest;
use LaunchKey\SDK\Domain\AuthResponse;
use LaunchKey\SDK\Domain\DeOrbitCallback;
use LaunchKey\SDK\Domain\NonceResponse;
use LaunchKey\SDK\Domain\PingResponse;
use LaunchKey\SDK\Domain\WhiteLabelUser;
use LaunchKey\SDK\Service\Exception\CommunicationError;
use LaunchKey\SDK\Service\Exception\ExpiredAuthRequestError;
use LaunchKey\SDK\Service\Exception\InvalidCredentialsError;
use LaunchKey\SDK\Service\Exception\InvalidRequestError;
use LaunchKey\SDK\Service\Exception\InvalidResponseError;
use LaunchKey\SDK\Service\Exception\LaunchKeyEngineError;
use LaunchKey\SDK\Service\Exception\NoPairedDevicesError;
use LaunchKey\SDK\Service\Exception\NoSuchUserError;
use LaunchKey\SDK\Service\Exception\RateLimitExceededError;
use LaunchKey\SDK\Service\Exception\UnknownCallbackActionError;

/**
 * Interface for interacting with the LaunchKey API
 *
 * @package LaunchKey\SDK\Service
 */
interface ApiService
{
    /**
     * Perform a ping request
     * @return PingResponse
     * @throws CommunicationError If there was an error communicating with the endpoint
     * @throws InvalidRequestError If the endpoint proclaims the request invalid
     */
    public function ping();

    /**
     * Perform an "auth" request
     *
     * @param string $username Username to authorize
     * @param bool $session Is the request for a user session and not a transaction
     * @throws CommunicationError If there was an error communicating with the endpoint
     * @throws InvalidCredentialsError If the credentials supplied to the endpoint were invalid
     * @throws NoPairedDevicesError If the account for the provided username has no paired devices with which to respond
     * @throws NoSuchUserError If the username provided does not exist
     * @throws RateLimitExceededError If the same username is requested to often and exceeds the rate limit
     * @throws InvalidRequestError If the endpoint proclaims the request invalid
     * @return AuthRequest
     */
    public function auth($username, $session);

    /**
     * Poll to see if the auth request is completed and approved/denied
     *
     * @param string $authRequest auth_request returned from an auth call
     * @return AuthResponse
     * @throws CommunicationError If there was an error communicating with the endpoint
     * @throws InvalidCredentialsError If the credentials supplied to the endpoint were invalid
     * @throws InvalidRequestError If the endpoint proclaims the request invalid
     * @throws InvalidResponseError If the response returned is not properly formed
     * @throws ExpiredAuthRequestError If the auth request has expired
     */
    public function poll($authRequest);

    /**
     * Update the LaunchKey Engine with the current status of the auth request or user session
     *
     * @param string $authRequest auth_request returned from an auth call
     * @param string $action Action to log.  i.e. Authenticate, Revoke, etc.
     * @param bool $status
     * @return null
     * @throws CommunicationError If there was an error communicating with the endpoint
     * @throws InvalidCredentialsError If the credentials supplied to the endpoint were invalid
     * @throws InvalidRequestError If the endpoint proclaims the request invalid
     * @throws ExpiredAuthRequestError If the auth request has expired
     * @throws LaunchKeyEngineError If the LaunchKey cannot apply the request auth request, action, status
     */
    public function log($authRequest, $action, $status);

    /**
     * Create a white label user with the following identifier
     *
     * @param string $identifier Unique and permanent identifier for the user in the white label application.  This identifier
     * will be used in all future communications regarding this user.  As such, it cannot ever change.
     *
     * @return WhiteLabelUser
     * @throws CommunicationError If there was an error communicating with the endpoint
     * @throws InvalidCredentialsError If the credentials supplied to the endpoint were invalid
     * @throws InvalidRequestError If the endpoint proclaims the request invalid
     */
    public function createWhiteLabelUser($identifier);

    /**
     * Handle a LaunchKey engine callback with the query parameters from the callback POST call
     *
     * @param array $queryParameters Query parameters from the callback POST call
     * @param callable $rocketCreationResponder (Optional) This is a callable for replying to a Rocket Creation server
     * sent event. The response is expected to be of the type "text/plain" with a 200 status code and the body composed
     * of the RSA public key passed in as the first parameter. The following is an example of processing via raw PHP:
     *
     *      $rocketConfigResponder = function($publicKey) {
     *          header("Content-Type: text/plain", true, 200);
     *          echo $publicKey;
     *      }
     *
     *      $apiService->handleCallback($_GET, $rocketCreationResponder);
     *
     * @return AuthResponse|DeOrbitCallback Object generated by processing the provided $postData
     */
    public function handleCallback(array $queryParameters, $rocketCreationResponder = null);

    /**
     * Get a nonce and its expiration to be utilized in other API requests
     *
     * @return NonceResponse
     * @throws CommunicationError If there was an error communicating with the endpoint
     * @throws InvalidRequestError If the endpoint proclaims the request invalid
     * @throws InvalidResponseError If the response data is not valid JSON
     */
    public function nonce();
}
