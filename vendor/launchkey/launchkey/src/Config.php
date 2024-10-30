<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK;

use Psr\Log\LoggerInterface;

/**
 * Registry for configuring the LaunchKey SDK client
 *
 * @package LaunchKey\SDK
 */
class Config
{
    /**
     * Seconds to cache public keys requests.
     *
     * @var int
     */
    private $publicKeyTTL = 60;

    /**
     * Secret key for the organization or application.
     *
     * @var string
     */
    private $secretKey;

    /**
     * Private key of the RSA private/public key pair for the organization or application.
     *
     * @var string
     */
    private $privateKey;

    /**
     * @var string
     */
    private $privateKeyPassword;

    /**
     * App key for an application
     * @var string
     */
    private $appKey;

    /**
     * @var Cache\Cache
     */
    private $cache;

    /**
     * @var EventDispatcher\EventDispatcher
     */
    private $eventDispatcher;

    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @var string
     */
    private $apiBaseUrl = "https://api.launchkey.com";

    /**
     * @var int
     */
    private $apiRequestTimeout = 0;

    /**
     * @var int
     */
    private $apiConnectTimeout = 0;

    /**
     * Get the number of seconds a public key will be cached.
     *
     * @return int
     */
    public function getPublicKeyTTL()
    {
        return $this->publicKeyTTL;
    }

    /**
     * Set the number of seconds a public key will be cached.
     *
     * @param mixed $publicKeyTTL
     * @return $this
     */
    public function setPublicKeyTTL($publicKeyTTL)
    {
        $this->publicKeyTTL = $publicKeyTTL;
        return $this;
    }

    /**
     * Get the secret key for the organization or application.
     *
     * @return string
     */
    public function getSecretKey()
    {
        return $this->secretKey;
    }

    /**
     * Set the secret key for the organization or application.
     *
     * @param string $secretKey
     * @return $this
     */
    public function setSecretKey($secretKey)
    {
        $this->secretKey = $secretKey;
        return $this;
    }

    /**
     * Get the private key of the RSA private/public key pair for the organization or application.
     *
     * @return string
     */
    public function getPrivateKey()
    {
        return $this->privateKey;
    }

    /**
     * Set the private key of the RSA private/public key pair for the organization or application.
     *
     * @param string $privateKey
     * @return $this
     */
    public function setPrivateKey($privateKey)
    {
        $this->privateKey = $privateKey;
        return $this;
    }

    /**
     * @return string
     */
    public function getPrivateKeyPassword()
    {
        return $this->privateKeyPassword;
    }

    /**
     * @param string $privateKeyPassword
     * @return $this
     */
    public function setPrivateKeyPassword($privateKeyPassword)
    {
        $this->privateKeyPassword = $privateKeyPassword;
        return $this;
    }

    /**
     * Set the location of the file that contains the private key of the RSA private/public key pair for the
     * organization or application.
     *
     * @param string $location File location.  This may be a location of the local file system or a remote location
     * with a valid parseable URL by your PHP installation.
     * @return $this
     */
    public function setPrivateKeyLocation($location)
    {
        $resolvedLocation = preg_match("/.+:\/\/.+/", $location) ? $location : stream_resolve_include_path($location);
        if (!$resolvedLocation) {
            throw new \InvalidArgumentException("Unable to resolve location: " . $location);
        }

        $old = error_reporting(E_ERROR);
        $data = file_get_contents($location, FILE_USE_INCLUDE_PATH);
        error_reporting($old);
        if ($data === false) {
            throw new \InvalidArgumentException("Unable to obtain private key from location: " . $location);
        }
        $this->privateKey = $data;
        return $this;
    }

    /**
     * Get the app key for an application.
     *
     * @return string
     */
    public function getAppKey()
    {
        return $this->appKey;
    }

    /**
     * Set the app key for an application.
     *
     * @param string $appKey
     * @return $this
     */
    public function setAppKey($appKey)
    {
        $this->appKey = $appKey;
        return $this;
    }

    /**
     * @return Cache\Cache|string
     */
    public function getCache()
    {
        if (!$this->cache) {
            $this->cache = new Cache\MemoryCache();
        }
        return $this->cache;
    }

    /**
     * @param Cache\Cache $cache
     * @return $this
     */
    public function setCache(Cache\Cache $cache)
    {
        $this->cache = $cache;
        return $this;
    }

    /**
     * @return EventDispatcher\EventDispatcher
     */
    public function getEventDispatcher()
    {
        if (!$this->eventDispatcher) {
            $this->eventDispatcher = new EventDispatcher\SynchronousLocalEventDispatcher();
        }
        return $this->eventDispatcher;
    }

    /**
     * @param EventDispatcher\EventDispatcher $eventDispatcher
     * @return $this
     */
    public function setEventDispatcher(EventDispatcher\EventDispatcher $eventDispatcher)
    {
        $this->eventDispatcher = $eventDispatcher;
        return $this;
    }

    /**
     * @return LoggerInterface
     */
    public function getLogger()
    {
        return $this->logger;
    }

    /**
     * @param LoggerInterface $logger
     * @return $this
     */
    public function setLogger(LoggerInterface $logger)
    {
        $this->logger = $logger;
        return $this;
    }

    /**
     * @return string
     */
    public function getApiBaseUrl()
    {
        return $this->apiBaseUrl;
    }

    /**
     * @param string $apiBaseUrl
     * @return $this
     */
    public function setApiBaseUrl($apiBaseUrl)
    {
        $this->apiBaseUrl = $apiBaseUrl;
        return $this;
    }

    /**
     * @return int
     */
    public function getApiRequestTimeout()
    {
        return $this->apiRequestTimeout;
    }

    /**
     * @param int $apiRequestTimeout
     * @return $this
     */
    public function setApiRequestTimeout($apiRequestTimeout)
    {
        $this->apiRequestTimeout = $apiRequestTimeout;
        return $this;
    }

    /**
     * @return int
     */
    public function getApiConnectTimeout()
    {
        return $this->apiConnectTimeout;
    }

    /**
     * @param int $apiConnectTimeout
     * @return $this
     */
    public function setApiConnectTimeout($apiConnectTimeout)
    {
        $this->apiConnectTimeout = $apiConnectTimeout;
        return $this;
    }
}
