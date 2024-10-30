<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2016 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Service;


use LaunchKey\SDK\Domain\AuthResponse;
use LaunchKey\SDK\Domain\DeOrbitCallback;
use LaunchKey\SDK\Domain\RocketCreated;
use LaunchKey\SDK\Service\Exception\InvalidRequestError;
use LaunchKey\SDK\Service\Exception\UnknownCallbackActionError;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

interface ServerSentEventService
{
    /**
     * Handle a Server Sent Event (SSE) request utilizing a middleware approach. This approach will do the following:
     *      1. Process it's logic until complete
     *      2. Call the $next callable if supplied with same method signature of this method.
     *      3. Trigger the appropriate event for the callback type
     *      4. Return the appropriate response for the callback type.
     *
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @param callable $next Callable object to
     *
     * @throws UnknownCallbackActionError When the provided $request does not contain the correct information
     * to process any know Server Sent Event
     * @throws InvalidRequestError When the request contains the correct data elements for a particular
     * server sent event but the data values are not valid.
     *
     * @return AuthResponse|DeOrbitCallback|RocketCreated
     */
    public function handleEvent(RequestInterface $request, ResponseInterface $response, $next = null);
}
