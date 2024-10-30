<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2016 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Domain;

use LaunchKey\SDK\Service\CryptService;

/**
 * Results from a rocket config callback
 *
 * @package LaunchKey\SDK\Domain
 */
class RocketCreated
{
    /**
     * @var string Base64 encoded and AES encrypted data provided in the callback request
     */
    private $encryptedRocketKey;

    /**
     * @var string Base64 encoded and AES encrypted data provided in the callback request
     */
    private $encryptedSecret;

    /**
     * @var string
     */
    private $rsaKeyPair;

    /**
     * @var string
     */
    private $rocketName;

    /**
     * @var string
     */
    private $rocketCallbackURL;

    /**
     * @var bool
     */
    private $encryptedWhiteLabel;

    /**
     * RocketCreated constructor.
     *
     * @param string $encryptedRocketKey Base64 encoded and AES encrypted rocket_key provided in the server sent event
     * @param string $encryptedSecret Base64 encoded and AES encrypted secret provided in the server sent event
     * @param bool $encryptedWhiteLabel  Base64 encoded and AES encrypted boolean determining if the rocket is a
     * white label rocket
     * @param string $rocketName Rocket name of the rocket created
     * @param $rocketCallbackURL Callback URL of the rocket created
     * @param RSAKeyPair $rsaKeyPair RSA key pair
     */
    public function __construct(
        $encryptedRocketKey,
        $encryptedSecret,
        $encryptedWhiteLabel,
        $rocketName,
        $rocketCallbackURL,
        RSAKeyPair $rsaKeyPair
    ) {
        $this->encryptedRocketKey  = $encryptedRocketKey;
        $this->encryptedSecret     = $encryptedSecret;
        $this->encryptedWhiteLabel = $encryptedWhiteLabel;
        $this->rocketName          = $rocketName;
        $this->rocketCallbackURL   = $rocketCallbackURL;
        $this->rsaKeyPair          = $rsaKeyPair;
    }

    /**
     * Get the Base64 encoded and AES encrypted rocket key provided in the server sent event request
     *
     * @return string
     */
    public function getEncryptedRocketKey()
    {
        return $this->encryptedRocketKey;
    }

    /**
     * Get the Base64 encoded and AES encrypted secret provided in the server sent event request
     *
     * @return string
     */
    public function getEncryptedSecret()
    {
        return $this->encryptedSecret;
    }

    /**
     * Get the Base64 encoded and AES encrypted boolean flag for white label provided in the server sent event request
     *
     * @return boolean
     */
    public function getEncryptedWhiteLabel()
    {
        return $this->encryptedWhiteLabel;
    }

    /**
     * Get the rocket name provided in the server sent event request
     *
     * @return string
     */
    public function getRocketName()
    {
        return $this->rocketName;
    }

    /**
     * Get the callback URL provided in the server sent event request
     *
     * @return string
     */
    public function getRocketCallbackURL()
    {
        return $this->rocketCallbackURL;
    }

    /**
     * Get the RSA key pair
     *
     * @return RSAKeyPair RSA key pair
     */
    public function getRsaKeyPair()
    {
        return $this->rsaKeyPair;
    }

    /**
     * @param CryptService $cryptService
     * @param $nonce
     *
     * @return RocketConfig
     */
    public function getRocketConfig(CryptService $cryptService, $nonce)
    {
        $key       = substr($nonce, 0, 32);
        $iv        = substr($nonce, -16);
        $rocketKey = $cryptService->decryptAES($this->encryptedRocketKey, $key, $iv, true, true);
        if (empty($rocketKey)) {
            throw new \InvalidArgumentException("The nonce provided was unable to properly decrypt the rocket key");
        }

        $secret = $cryptService->decryptAES($this->encryptedSecret, $key, $iv, true, true);
        if (empty($secret)) {
            throw new \InvalidArgumentException("The nonce provided was unable to properly decrypt the secret");
        }

        $whiteLabelString = $cryptService->decryptAES($this->encryptedWhiteLabel, $key, $iv, true, true);
        if (empty($whiteLabelString)) {
            throw new \InvalidArgumentException("The nonce provided was unable to properly decrypt the white label");
        }
        $whiteLabel = json_decode($whiteLabelString);
        if (! is_bool($whiteLabel)) {
            throw new \InvalidArgumentException("The white label provided did not decode as a JSON boolean");
        }

        return new RocketConfig(
            $rocketKey,
            $secret,
            $this->rocketName,
            $whiteLabel,
            $this->rocketCallbackURL,
            $this->rsaKeyPair->getPrivateKey()
        );
    }
}
