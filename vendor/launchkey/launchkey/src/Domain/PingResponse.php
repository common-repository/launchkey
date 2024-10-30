<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Domain;

/**
 * Value object representing the response from a ping request
 *
 * @package LaunchKey\SDK\Domain
 */
class PingResponse
{
    /**
     * @var \DateTime
     */
    private $launchKeyTime;

    /**
     * @var \DateTime
     */
    private $keyTimeStamp;

    /**
     * @var String
     */
    private $publicKey;

    /**
     * @param \DateTime $launchKeyTime The date/time in the default time zone based omn the launchkey_time returned by ping
     * response.
     * @param string $publicKey The public key returned by the ping response
     * @param \DateTime $keyTimeStamp The date/time the current RSA public key was created
     */
    function __construct(\DateTime $launchKeyTime, $publicKey, \DateTime $keyTimeStamp)
    {
        $this->launchKeyTime = $launchKeyTime;
        $this->publicKey = $publicKey;
        $this->keyTimeStamp = $keyTimeStamp;
    }

    /**
     * Get the date/time of LaunchKey Engine when the ping response was created.
     *
     * @return \DateTime
     */
    public function getLaunchKeyTime()
    {
        return $this->launchKeyTime;
    }

    /**
     * Get the LaunchKey Engine's RSA public key of the current RSA public/private key pair.
     *
     * @return String
     */
    public function getPublicKey()
    {
        return $this->publicKey;
    }

    /**
     * Get the date/time the current RSA public key was created
     *
     * @return \DateTime
     */
    public function getKeyTimeStamp()
    {
        return $this->keyTimeStamp;
    }

    public function toJson()
    {
        return json_encode(array(
            "launchKeyTime" => $this->launchKeyTime->getTimestamp() * 1000,
            "publicKey" => $this->publicKey,
            "keyTimeStamp" => $this->keyTimeStamp->getTimestamp() * 1000
        ));
    }

    public static function fromJson($json)
    {
        $value = json_decode($json, true);
        if (json_last_error()) {
            throw new \InvalidArgumentException("Invalid JSON");
        }
        if (!isset($value["launchKeyTime"]) || !isset($value["publicKey"]) || !isset($value["keyTimeStamp"])) {
            throw new \InvalidArgumentException("launchKeyTime, publicKey, and keyTimeStamp are required attributes");
        }
        if (!is_integer($value["launchKeyTime"]) || !is_integer($value["keyTimeStamp"])) {
            throw new \InvalidArgumentException("launchKeyTime and keyTimeStamp are required to be integers expressing the number of milliseconds since the epoc");
        }

        $launchKeyDate = new \DateTime();
        $launchKeyDate->setTimestamp(floor($value['launchKeyTime']/1000));
        $keyTimeStamp = new \DateTime();
        $keyTimeStamp->setTimestamp(floor($value['keyTimeStamp']/1000));
        return new PingResponse($launchKeyDate, $value['publicKey'], $keyTimeStamp);
    }
}
