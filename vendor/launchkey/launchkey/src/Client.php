<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK;

use LaunchKey\SDK\Service\ServerSentEventService;

/**
 * LaunchKey SDK Client
 *
 * The client is a domain aggregate for the auth and white label services.  It provides a simple interface to creating
 * and using the underlying services with little knowledge of the services themselves.The client can only be created
 * from the factory method.
 *
 * @package LaunchKey\SDK
 */
class Client
{
    /**
     * @var Service\AuthService
     */
    private $auth;

    /**
     * @var Service\WhiteLabelService
     */
    private $whiteLabel;

    /**
     * @var EventDispatcher\EventDispatcher
     */
    private $eventDispatcher;

    /**
     * @var Cache\Cache
     */
    private $cache;

    /**
     * @var \Psr\Log\LoggerInterface
     */
    private $logger;

    /**
     * @var Service\ServerSentEventService
     */
    private $serverSentEvent;

    /**
     * @param Service\AuthService $authService
     * @param Service\WhiteLabelService $whiteLabelService
     * @param ServerSentEventService $serverSentEventService
     * @param EventDispatcher\EventDispatcher $eventDispatcher
     * @param Cache\Cache $cache
     * @param \Psr\Log\LoggerInterface $logger
     */
    public function __construct(
        Service\AuthService $authService,
        Service\WhiteLabelService $whiteLabelService,
        Service\ServerSentEventService $serverSentEventService,
        EventDispatcher\EventDispatcher $eventDispatcher,
        Cache\Cache $cache,
        \Psr\Log\LoggerInterface $logger = null
    ) {
        $this->eventDispatcher = $eventDispatcher;
        $this->auth = $authService;
        $this->whiteLabel = $whiteLabelService;
        $this->serverSentEvent = $serverSentEventService;
        $this->cache = $cache;
        $this->logger = $logger;
        $this->cache = $cache;
    }

    /**
     * Build a LaunchKey SDK client utilizing the following parameters.  A \LaunchKey\SDk\Config object can be
     * substituted for any of the provided parameters.  The parameters before the config object will
     * override any values within the config object.  All parameters after the config object will be ignored.
     *
     * Example:
     *
     * $config = new \LaunchKey\SDK\Config();
     * $config->setAppKey("config-app-key");
     * $config->setPrivateKeyLocation("/usr/local/etc/private_key.pem");
     * $client = \LaunchKey\SDK\Client::factory("param-app-key", $config, "ignored-private-key");
     *
     * In the previous example, the config object is supplied for the privateKey parameter.  As such, the app key
     * value of "config-app-key" in the config object will be replaced with the "param-app-key" value passed to the
     * appKey parameter and the "ignored-private-key" value passed to the privateKey parameter will be ignored.
     *
     * @param string|Config $appKey
     * @param string|Config|null $secretKey
     * @param string|Config|null $privateKey
     * @param Config|null $config
     * @return self
     */
    public static function factory($appKey, $secretKey = null, $privateKey = null, Config $config = null)
    {
        $config = self::getUpdatedConfig($appKey, $secretKey, $privateKey, $config);
        $cache = $config->getCache();
        $logger = $config->getLogger();
        $eventDispatcher = $config->getEventDispatcher();

        $cryptService = new Service\PhpSecLibCryptService($config->getPrivateKey(), $config->getPrivateKeyPassword());
        $apiService = self::getGuzzleApiService(
            $config->getAppKey(),
            $config->getSecretKey(),
            $config->getApiBaseUrl(),
            $config->getApiConnectTimeout(),
            $config->getApiRequestTimeout(),
            $cryptService,
            $cache,
            $config->getPublicKeyTTL(),
            $logger
        );

        $authService = new Service\BasicAuthService(
            $apiService,
            $eventDispatcher,
            $logger
        );
        $whiteLabelService = new Service\BasicWhiteLabelService(
            $apiService,
            $eventDispatcher,
            $logger
        );

        $serverSentEventService = new Service\BasicServerSentEventService(
            $apiService,
            $cryptService,
            $eventDispatcher,
            $logger
        );

        return new self($authService, $whiteLabelService, $serverSentEventService, $eventDispatcher, $cache, $logger);
    }

    public static function wpFactory($appKey, $secretKey = null, $privateKey = null, $sslVerify = true, Config $config = null)
    {
        $config = self::getUpdatedConfig($appKey, $secretKey, $privateKey, $config);
        $cache = $config->getCache();
        $logger = $config->getLogger();
        $eventDispatcher = $config->getEventDispatcher();

        $cryptService = new Service\PhpSecLibCryptService($config->getPrivateKey(), $config->getPrivateKeyPassword());
        $apiService = self::getWpApiService(
            $config->getAppKey(),
            $config->getSecretKey(),
            $config->getApiBaseUrl(),
            $sslVerify,
            $config->getApiRequestTimeout(),
            $cryptService,
            $cache,
            $config->getPublicKeyTTL(),
            $logger
        );

        $authService = new Service\BasicAuthService(
            $apiService,
            $eventDispatcher,
            $logger
        );
        $whiteLabelService = new Service\BasicWhiteLabelService(
            $apiService,
            $eventDispatcher,
            $logger
        );

        $serverSentEventService = new Service\BasicServerSentEventService(
            $apiService,
            $cryptService,
            $eventDispatcher,
            $logger
        );

        return new self($authService, $whiteLabelService, $serverSentEventService, $eventDispatcher, $cache, $logger);
    }

    /**
     * @param $appKey
     * @param $secretKey
     * @param $privateKey
     * @param Config $config
     * @return Config
     */
    private static function getUpdatedConfig($appKey, $secretKey, $privateKey, $config)
    {
        if ($appKey instanceof Config) {
            $config = $appKey;
        } elseif ($secretKey instanceof Config) {
            $config = $secretKey;
            $config->setAppKey($appKey);
        } elseif ($privateKey instanceof Config) {
            $config = $privateKey;
            $config->setSecretKey($secretKey);
            $config->setAppKey($appKey);
        } else {
            if (is_null($config)) {
                $config = new Config();
            }
            $config->setAppKey($appKey);
            $config->setSecretKey($secretKey);
            $config->setPrivateKey($privateKey);
        }

        return $config;
    }

    /**
     * @param string $appKey
     * @param string $secretKey
     * @param string $apiBaseUrl
     * @param int $connectTimeout
     * @param int $requestTimeout
     * @param Service\CryptService $cryptService
     * @param Cache\Cache $cache
     * @param int $publicKeyTTL
     * @param \Psr\Log\LoggerInterface $logger
     * @return Service\GuzzleApiService
     */
    private static function getGuzzleApiService(
        $appKey,
        $secretKey,
        $apiBaseUrl,
        $connectTimeout,
        $requestTimeout,
        Service\CryptService $cryptService,
        Cache\Cache $cache,
        $publicKeyTTL,
        \Psr\Log\LoggerInterface $logger = null
    ) {
        $guzzle = new \Guzzle\Http\Client($apiBaseUrl, array(
            "redirect.disable" => true,
            'request.options' => array(
                "timeout" => $requestTimeout,
                "connect_timeout" => $connectTimeout,
            )
        ));

        if ($logger) {
            $guzzle->getEventDispatcher()->addListener(
                \Guzzle\Http\Client::CREATE_REQUEST,
                function (\Guzzle\Common\Event $event) use ($logger) {
                    $logger->debug("Guzzle preparing to send request", $event->toArray());
                }
            );
        }

        $apiService = new Service\GuzzleApiService(
            $appKey,
            $secretKey,
            $guzzle,
            $cryptService,
            $cache,
            $publicKeyTTL,
            $logger
        );
        return $apiService;
    }

    private static function getWpApiService(
        $appKey,
        $secretKey,
        $apiBaseUrl,
        $sslVerify,
        $apiRequestTimeout,
        $cryptService,
        $cache,
        $publicKeyTTL,
        $logger
    ) {
        $apiRequestTimeout = $apiRequestTimeout ?: 3600; // Fix for streams timing out when timeout is 0 and thought to be infinite
        return new Service\WordPressApiService(
            new \WP_Http(),
            $cryptService,
            $cache,
            $publicKeyTTL,
            $appKey,
            $secretKey,
            $sslVerify,
            $apiBaseUrl,
            $apiRequestTimeout,
            $logger
        );
    }

    /**
     * @return Service\AuthService
     */
    public function auth()
    {
        return $this->auth;
    }

    /**
     * @return Service\WhiteLabelService
     */
    public function whiteLabel()
    {
        return $this->whiteLabel;
    }

    public function serverSentEvent()
    {
        return $this->serverSentEvent;
    }

    /**
     * @return EventDispatcher\EventDispatcher
     */
    public function eventDispatcher()
    {
        return $this->eventDispatcher;
    }

    /**
     * @return Cache\Cache
     */
    public function getCache()
    {
        return $this->cache;
    }

    /**
     * @return \Psr\Log\LoggerInterface
     */
    public function getLogger()
    {
        return $this->logger;
    }
}
