<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Domain;

/**
 * Value object representing a de-orbit callback request from a server side event
 *
 * @package LaunchKey\SDK\Domain
 */
class DeOrbitCallback
{
    /**
     * @var \DateTime When the de-orbit occurred
     */
    private $deOrbitTime;

    /**
     * @var string The user hash for the user that requested the de-orbit.
     */
    private $userHash;

    /**
     * @param \DateTime|null $deOrbitTime When the de-orbit occurred.  Defaults to the current date/time.
     * @param string|null $userHash The user hash the requested the de-orbit.
     */
    public function __construct(\DateTime $deOrbitTime = null, $userHash = null)
    {
        $this->deOrbitTime = $deOrbitTime ?: new \DateTime();
        $this->userHash = $userHash;
    }

    /**
     *  Get when the de-orbit occurred
     *
     * @return \DateTime
     */
    public function getDeOrbitTime()
    {
        return $this->deOrbitTime;
    }

    /**
     * Get the user hash for the user that requested the de-orbit.
     *
     * @return string
     */
    public function getUserHash()
    {
        return $this->userHash;
    }
}
