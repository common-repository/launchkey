<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2016 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Domain;


/**
 * Value item representing the Rocket configuration data obtained and generated via a rocket creation callback
 * @package LaunchKey\SDK\Domain
 */
class RocketConfig
{
    /**
     * @var string Rocket key
     */
    private $key;

    /**
     * @var string Secret Key
     */
    private $secret;

    /**
     * @var string Rocket name
     */
    private $name;

    /**
     * @var string Callback URL for Server Sent Events (SSE)
     */
    private $callbackURL;

    /**
     * @var string PEM formatted X.509 RSA private key for associated Rocket Key
     */
    private $privateKey;

    /**
     * @var bool Is this a white label rocket
     */
    private $whiteLabel;

    /**
     * RocketConfig constructor.
     *
     * @param string $rocketKey Rocket Key
     * @param string $secretKey Secret Key for associated Rocket Key
     * @param string $rocketName Rocket name
     * @param bool $whiteLabel Is this a white label rocket
     * @param string $callbackURL Callback URL for Server Sent Events (SSE)
     * @param string $privateKey PEM formatted X.509 RSA private key for associated Rocket Key
     */
    public function __construct($rocketKey, $secretKey, $rocketName, $whiteLabel, $callbackURL, $privateKey)
    {
        $this->key         = $rocketKey;
        $this->secret      = $secretKey;
        $this->name        = $rocketName;
        $this->whiteLabel  = $whiteLabel;
        $this->callbackURL = $callbackURL;
        $this->privateKey  = $privateKey;
    }

    /**
     * Get the rocket key
     *
     * @return string Rocket Key
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * Get the Secret Key
     *
     * @return string Secret Key
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * Get the Rocket name
     *
     * @return string Rocket name
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * Is this a white label Rocket
     *
     * @return boolean Is this a white label Rocket
     */
    public function isWhiteLabel()
    {
        return $this->whiteLabel;
    }

    /**
     * Get the callback URL for Server Sent Events (SSE)
     *
     * @return string Callback URL
     */
    public function getCallbackURL()
    {
        return $this->callbackURL;
    }

    /**
     * Get the RSA private key
     *
     * @return string PEM formatted X.509 RSA private key
     */
    public function getPrivateKey()
    {
        return $this->privateKey;
    }
}
