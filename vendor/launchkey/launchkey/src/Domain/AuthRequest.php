<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Domain;

/**
 * Value object representing an authentication/authorization request
 *
 * @package LaunchKey\SDK\Domain
 */
class AuthRequest
{
    /**
     * @var string User name or internal identifier for the authorization request.  Internal identifiers are used for
     * white label applications.
     */
    private $username;

    /**
     * @var bool Is the authorization request for a user session as opposed to a transaction.  Defaults to FALSE.
     */
    private $userSession;

    /**
     * @var string auth_request value from LaunchKey API "auths" post
     */
    private $authRequestId;

    /**
     * @param string $username LaunchKey user name for the authorization request.  Internal identifiers are used for
     * white label applications.
     * @param bool $userSession Is the authorization request for a user session as opposed to a transaction.
     * @param string $authRequestId auth_request value from LaunchKey API "auths" post
     */
    function __construct($username, $userSession, $authRequestId)
    {
        $this->username = $username;
        $this->userSession = $userSession;
        $this->authRequestId = $authRequestId;
    }

    /**
     * @return string User name or internal identifier for the authorization request.  Internal identifiers are used for
     * white label applications.
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * @return boolean Is the authorization request for a user session as opposed to a transaction.
     */
    public function isUserSession()
    {
        return $this->userSession;
    }

    /**
     * Get the auth_request value from LaunchKey API "auths" post
     *
     * @return string
     */
    public function getAuthRequestId()
    {
        return $this->authRequestId;
    }
}
