<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2016 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Domain;

/**
 * Value object representing response from LaunchKey API Nonce endpoint
 *
 * @package LaunchKey\SDK\Domain
 */
class NonceResponse
{

    /**
     * @var string
     */
    private $nonce;

    /**
     * @var \DateTime
     */
    private $expiration;

    /**
     * NonceResponse constructor.
     *
     * @param string $nonce
     * @param \DateTime $expiration
     */
    public function __construct($nonce, \DateTime $expiration)
    {
        $this->nonce      = $nonce;
        $this->expiration = $expiration;
    }

    /**
     * @return string
     */
    public function getNonce()
    {
        return $this->nonce;
    }

    /**
     * @return \DateTime
     */
    public function getExpiration()
    {
        return $this->expiration;
    }
}
