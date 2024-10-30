<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */
namespace LaunchKey\SDK\Service;

use LaunchKey\SDK\Domain\WhiteLabelUser;

/**
 * Interface for providing white label based services
 *
 * @package LaunchKey\SDK\Service
 */
interface WhiteLabelService
{
    /**
     * @param string $identifier Permanent and unique identifier of this user within your application.
     * This identifier will be used authenticate the user as well as pair devices additional devices to
     * the user's account within your white label group.
     * @return WhiteLabelUser
     * @throws CommunicationError If there was an error communicating with the endpoint
     * @throws InvalidCredentialsError If the credentials supplied to the endpoint were invalid
     * @throws InvalidRequestError If the endpoint proclaims the request invalid
     * @throws InvalidResponseError If the encrypted data is not valid JSON
     */
    public function createUser($identifier);
}