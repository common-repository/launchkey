<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Cache;

/**
 * Interface for implementing caching in the LaunchKey SDK
 *
 * @package LaunchKey\SDK\Cache
 */
interface Cache
{
    /**
     * Get an item from the cache using the provided key.
     *
     * @param string $key Unique identifier for the item to get.
     * @return null|mixed Value for the key in the cache.  If no value is found or the value is expired, NULL is
     * returned.
     * @throws CacheError When an error occurs interface with the cache implementation
     */
    public function get($key);

    /**
     * Set an item in the cache identified by the provided key.
     *
     * @param string $key Unique identifier for the item to set.
     * @param mixed $value The value of the cache item
     * @param int $ttl Time to live in seconds
     * @return null
     * @throws CacheError When an error occurs interface with the cache implementation
     */
    public function set($key, $value, $ttl);
}
