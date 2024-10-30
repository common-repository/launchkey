<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2016 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Domain;

/**
 * Class RSAKeyPair
 * @package LaunchKey\SDK\Domain
 */
class RSAKeyPair
{
    /**
     * @var string
     */
    private $privateKey;

    /**
     * @var string
     */
    private $publicKey;

    /**
     * RSAKeyPair constructor.
     *
     * @param string $privateKey
     * @param string $publicKey
     */
    public function __construct($privateKey, $publicKey)
    {
        $this->privateKey = $privateKey;
        $this->publicKey  = $publicKey;
    }

    /**
     * @return string
     */
    public function getPrivateKey()
    {
        return $this->privateKey;
    }

    /**
     * @return string
     */
    public function getPublicKey()
    {
        return $this->publicKey;
    }
}
