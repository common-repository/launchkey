<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2015 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Service;


use LaunchKey\SDK\Domain\RSAKeyPair;
use phpseclib\Crypt\AES;
use phpseclib\Crypt\RSA;

/**
 * CryptService implementation utilizing phpseclib for cryptography
 *
 * @package LaunchKey\SDK\Service
 */
class PhpSecLibCryptService implements CryptService
{
    /**
     * @var \Crypt_RSA
     */
    private $crypt;

    /**
     * @param $privateKey Private key string
     * @param string|null $password Password for private key
     */
    public function __construct($privateKey, $password = null)
    {
        $this->crypt = $this->getRsaCrypt($privateKey, $password);
        $this->privateKey = $privateKey;
        $this->password = $password;
    }

    /**
     * @inheritdoc
     */
    public function encryptRSA($data, $publicKey, $base64Encode = true)
    {
        $encrypted = $this->getRsaCrypt($publicKey)->encrypt($data);
        $encrypted = $base64Encode ? base64_encode($encrypted) : $encrypted;

        return $encrypted;
    }

    /**
     * @inheritdoc
     */
    public function decryptRSA($data, $base64Encoded = true)
    {
        $data      = $base64Encoded ? base64_decode($data) : $data;
        $decrypted = $this->crypt->decrypt($data);

        return $decrypted;
    }

    /**
     * @inheritdoc
     */
    public function decryptAES($data, $key, $iv, $base64Encoded = true, $pcksPadded = false)
    {
        $data   = $base64Encoded ? base64_decode($data) : $data;
        $cipher = new AES();
        $cipher->setKey($key);
        $cipher->setIV($iv);

        if ($pcksPadded) { // When pcksPadded, let the library handle padding
            $cipher->enablePadding();
            $decrypted = $cipher->decrypt($data);
        } else { // When not pcksPadded, it's space pcksPadded
            $cipher->disablePadding();
            $decrypted = rtrim($cipher->decrypt($data));
        }

        return $decrypted;
    }

    /**
     * @inheritdoc
     */
    public function sign($data, $base64Encode = true, $strength = 256)
    {
        $signature = $this->getSignor($this->privateKey, $this->password, $strength)->sign($data, $strength);
        $signature = $base64Encode ? base64_encode($signature) : $signature;

        return $signature;
    }

    /**
     * @inheritdoc
     */
    public function verifySignature($signature, $data, $publicKey, $base64Encoded = true, $strength = 256)
    {
        $signature = $base64Encoded ? base64_decode($signature) : $signature;

        return $this->getSignor($publicKey, null, $strength)->verify($data, $signature);
    }

    /**
     * @inheritdoc
     */
    public function generateRSAKeyPair($bits = 4096)
    {
        if ($bits < 4) throw new \InvalidArgumentException("bits must be greater than 3");
        $crypt = new RSA();

        $keyProperties = $crypt->createKey($bits);
        if (empty($keyProperties) || empty($keyProperties['privatekey']) || empty($keyProperties['publickey'])) {
            throw new KeyCreationError();
        }

        return new RSAKeyPair($keyProperties['privatekey'], $keyProperties['publickey']);
    }

    /**
     * @param string $rsaKey
     * @param string|null $password
     * @param int $strength
     *
     * @return \Crypt_RSA
     */
    private function getSignor($rsaKey, $password = null, $strength = 256)
    {
        $crypt = new RSA();
        $crypt->loadKey($rsaKey);
        $crypt->setPassword($password);
        $crypt->setHash("sha{$strength}");
        $crypt->setSignatureMode(RSA::SIGNATURE_PKCS1);

        return $crypt;
    }

    /**
     * @param $privateKey
     * @param $password
     *
     * @return \Crypt_RSA
     */
    private function getRsaCrypt($privateKey, $password = null)
    {
        $crypt = new RSA();
        $crypt->loadKey($privateKey);
        $crypt->setPassword($password);

        return $crypt;
    }
}
