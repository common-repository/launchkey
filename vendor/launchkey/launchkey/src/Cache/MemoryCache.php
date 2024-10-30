<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Cache;

/**
 * Cache implementation that holds cache items in memory
 *
 * @package LaunchKey\SDK\Cache
 */
class MemoryCache implements Cache
{
    /**
     * @var array
     */
    private $dict = array();

    /**
     * @var array
     */
    private $expiration = array();

    /**
     * Get an item from the cache using the provided key.
     *
     * @param string $key Unique identifier for the item to get.
     * @return null|mixed Value for the key in the cache.  If no value is found or the value is expired, NULL is
     * returned.
     * @throws CacheError When an error occurs interface with the cache implementation
     */
    public function get($key)
    {
        $this->processExpired();
        return isset($this->dict[$key]) ? $this->dict[$key] : null;
    }

    /**
     * Set an item in the cache identified by the provided key.
     *
     * @param string $key Unique identifier for the item to set.
     * @param mixed $value The value of the cache item
     * @param int $ttl Time to live in seconds
     * @return null
     * @throws CacheError When an error occurs interface with the cache implementation
     */
    public function set($key, $value, $ttl)
    {
        $this->dict[$key] = $value;
        $this->expiration[time() + $ttl][] = $key;
        $this->processExpired();
    }

    private function processExpired()
    {
        $dict = $this->dict;
        $expiration = $this->expiration;
        array_walk(
            $this->expiration,
            function ($values, $key) use (&$dict, &$expiration) {
                foreach ($values as $value) {
                    if ($key <= time()) {
                        unset($dict[$value]);
                    }
                    unset($expiration[$key]);
                }
            }
        );
        $this->dict = $dict;
        $this->expiration = $expiration;
    }
}
