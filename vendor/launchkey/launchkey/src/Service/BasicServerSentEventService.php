<?php
/**
 * @author Adam Englander <adam@launchkey.com>
 * @copyright 2016 LaunchKey, Inc. See project license for usage.
 */

namespace LaunchKey\SDK\Service;


use LaunchKey\SDK\Domain\AuthResponse;
use LaunchKey\SDK\Domain\DeOrbitCallback;
use LaunchKey\SDK\Domain\RocketCreated;
use LaunchKey\SDK\Event\AuthResponseEvent;
use LaunchKey\SDK\Event\DeOrbitCallbackEvent;
use LaunchKey\SDK\Event\RocketCreatedEvent;
use LaunchKey\SDK\EventDispatcher\EventDispatcher;
use LaunchKey\SDK\Service\Exception\InvalidRequestError;
use LaunchKey\SDK\Service\Exception\UnknownServerSentEventError;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;

class BasicServerSentEventService implements ServerSentEventService
{
    const LAUNCHKEY_DATE_FORMAT = "Y-m-d H:i:s";

    const LAUNCHKEY_DATE_TZ = "UTC";

    /**
     * @var ApiService
     */
    private $api;

    /**
     * @var EventDispatcher
     */
    private $eventDispatcher;

    /**
     * @var CryptService
     */
    private $crypt;

    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * BasicServerSentEventService constructor.
     *
     * @param ApiService $api
     * @param CryptService $crypt
     * @param EventDispatcher $eventDispatcher
     * @param LoggerInterface $logger
     */
    public function __construct(
        ApiService $api,
        CryptService $crypt,
        EventDispatcher $eventDispatcher,
        LoggerInterface $logger = null
    ) {
        $this->api             = $api;
        $this->crypt           = $crypt;
        $this->eventDispatcher = $eventDispatcher;
        $this->logger          = $logger;
    }

    /**
     * @inheritdoc
     */
    public function handleEvent(RequestInterface $request, ResponseInterface $response, $next = null)
    {
        $this->debugLog("Handling server sent event", array("request" => $request, "response" => $response));

        $result = $this->handleJsonWebTokenCallback($request, $response);

        if ( ! $result) {
            $result = $this->handleHandleLegacyEvent($request);
        }

        if ( ! $result) {
            $this->debugLog("Could not determine server sent event from request", array("request" => $request));
            throw new UnknownServerSentEventError("Could not determine server sent event");
        }

        if ($next) {
            call_user_func($next, $request, $response);
        }

        return $result;
    }

    private function handleHandleLegacyEvent(RequestInterface $request)
    {
        parse_str($request->getUri()->getQuery(), $queryParameters);

        $response = $this->handleAuthResponseEvent($queryParameters);

        if ( ! $response) {
            $response = $this->handleDeOrbitEvent($queryParameters);
        }

        return $response;
    }

    /**
     * @param array $queryParameters
     *
     * @return AuthResponse
     * @throws InvalidRequestError
     *
     */
    private function handleAuthResponseEvent(array $queryParameters)
    {
        if (
            ! isset($queryParameters["auth"])
            || ! isset($queryParameters["auth_request"])
            || ! isset($queryParameters["user_hash"])
        ) {
            return;
        }

        $this->debugLog("Server Sent Event identified as auth response");
        $authRequest      = $queryParameters["auth_request"];
        $authPackage      = $queryParameters["auth"];
        $userHash         = $queryParameters["user_hash"];
        $organizationUser = isset($queryParameters["organization_user"]) ? $queryParameters["organization_user"] : null;
        $userPushId       = isset($queryParameters["user_push_id"]) ? $queryParameters["user_push_id"] : null;

        $auth = json_decode($this->crypt->decryptRSA($authPackage), true);

        if ($authRequest !== $auth["auth_request"]) {
            $this->debugLog(
                "Query auth_request value of did not match query auth package value for auth_request",
                array('Query value' => $authRequest, "Auth package value" => $auth['auth_request'])
            );
            throw new InvalidRequestError("Invalid auth callback auth_request values did not match");
        } elseif ( ! isset($auth["device_id"]) || ! isset($auth["response"])) {
            $this->debugLog("Invalid auth package. Must contain device_id and response", array("package" => $auth));
            throw new InvalidRequestError("Invalid auth callback auth package was invalid");
        }

        $authResponse = new AuthResponse(
            true,
            $authRequest,
            $userHash,
            $organizationUser,
            $userPushId,
            $auth["device_id"],
            $auth["response"] == "true"
        );

        $this->debugLog("Dispatching " . AuthResponseEvent::NAME . " event");
        $this->eventDispatcher->dispatchEvent(AuthResponseEvent::NAME, new AuthResponseEvent($authResponse));

        $this->debugLog("Logging Authenticate: " . ($authResponse->isAuthorized() ? 'true' : 'false'));
        $this->api->log($authResponse->getAuthRequestId(), "Authenticate", $authResponse->isAuthorized());

        return $authResponse;
    }

    /**
     * @param array $queryParameters
     *
     * @return string DeOrbitCallback
     * @throws InvalidRequestError
     *
     */
    private function handleDeOrbitEvent(array $queryParameters)
    {
        if ( ! isset($queryParameters["deorbit"]) || ! isset($queryParameters["signature"])) {
            return;
        }

        $this->debugLog("Server Sent Event determined to be deorbit");

        $deOrbit   = $queryParameters["deorbit"];
        $signature = $queryParameters["signature"];

        if ( ! $this->crypt->verifySignature($signature, $deOrbit, $this->getPublicKey())) {
            throw new InvalidRequestError("Invalid signature for de-orbit callback");
        }

        $data = json_decode($deOrbit, true);
        if ( ! $data || ! isset($data["launchkey_time"]) || ! isset($data["user_hash"])) {
            $this->debugLog(
                "Invalid deorbit package. attributes launchkey_time and user_hash are required",
                array("package" => $deOrbit)
            );
            throw new InvalidRequestError("Invalid package for de-orbit callback");
        }

        $lkTime   = $this->getLaunchKeyDate($data["launchkey_time"]);
        $response = new DeOrbitCallback($lkTime, $data["user_hash"]);

        $this->debugLog("Dispatching " . DeOrbitCallbackEvent::NAME . " event");
        $this->eventDispatcher->dispatchEvent(DeOrbitCallbackEvent::NAME, new DeOrbitCallbackEvent($response));

        return $response;
    }


    private function handleJsonWebTokenCallback(RequestInterface $request, ResponseInterface $response)
    {
        $contentTypes = $request->getHeader('Content-Type');
        $contentType  = $contentTypes ? $contentTypes[0] : null;
        if (
            false === strcasecmp('POST', $request->getMethod())
            || false === strcasecmp('application/json', $contentType)
            || ! $request->hasHeader("signature")
        ) {
            return;
        }

        $signatureHeader      = $request->getHeader("signature");
        $jwtSignatureSegments = explode(".", $signatureHeader[0]);
        if (count($jwtSignatureSegments) !== 3) {
            return;
        }

        $jwtHeader     = json_decode($this->base64UrlDecode($jwtSignatureSegments[0]), true);
        $jwtPayload    = json_decode($this->base64UrlDecode($jwtSignatureSegments[1]), true);
        $jwtSignature  = $this->base64UrlDecode($jwtSignatureSegments[2]);
        $jwtSignedData = sprintf("%s.%s", $jwtSignatureSegments[0], $jwtSignatureSegments[1]);

        $now = time();

        if ($now >= $jwtPayload["exp"]) {
            throw new InvalidRequestError("Expired request");
        } elseif ($now < $jwtPayload["nbf"]) {
            throw new InvalidRequestError("Request to early");
        } elseif ($now < $jwtPayload["iat"]) {
            throw new InvalidRequestError("Request before issued");
        } elseif ($request->getMethod() !== $jwtPayload["Method"]) {
            throw new InvalidRequestError("Method mismatch");
        } elseif ($contentType !== $jwtPayload["Content-Type"]) {
            throw new InvalidRequestError("Content-Type mismatch");
        } elseif ($jwtHeader["alg"] !== $jwtPayload["Signature-Algorithm"]) {
            throw new InvalidRequestError("Algorithm mismatch");
        }

        preg_match('/^RS([\d]+)$/', $jwtHeader['alg'], $matches);
        if ( ! $matches) {
            throw new InvalidRequestError("Invalid signature algorithm");
        }

        if ( ! $this->crypt->verifySignature($jwtSignature, $jwtSignedData, $this->getPublicKey(), false, intval($matches[1]))) {
            throw new InvalidRequestError("JWT signature mismatch");
        }

        $body = "";
        while ($segment = $request->getBody()->read(255)) {
            $body .= $segment;
        }

        if (hash("sha256", trim($body)) !== $jwtPayload["Content-SHA256"]) {
            throw new InvalidRequestError("Content-SHA256 mismatch");
        }


        $encryptedData = json_decode(base64_decode($body), true);
        if ( ! $encryptedData) {
            $this->debugLog("Body could not be JSON decoded", array("Body" => $body));
            throw new InvalidRequestError("Invalid request body");
        }

        $result = $this->handleRocketCreationEvent($encryptedData, $jwtPayload, $response);

        return $result;
    }

    /**
     * @param $encryptedData
     * @param ResponseInterface $response
     *
     * @return RocketCreated
     * @internal param $body
     */
    private function handleRocketCreationEvent(array $encryptedData, array $jwtPayload, ResponseInterface $response)
    {

        if (
            ! isset($encryptedData["secret"]) ||
            ! isset($encryptedData["rocket_key"]) ||
            ! isset($encryptedData["is_whitelabel"]) ||
            ! isset($jwtPayload["aud"]) ||
            ! (substr($jwtPayload["aud"], 0, 4) === "tpa:") ||
            ! isset($jwtPayload["Resource"])
        ) {
            return;
        }

        $this->debugLog("Server Sent Event determined to be rocket created");

        $keyPair = $this->crypt->generateRSAKeyPair();

        $this->debugLog("Writing public key to response", array("public key" => $keyPair->getPublicKey()));
        $response->getBody()->write($keyPair->getPublicKey());

        $result = new RocketCreated(
            $encryptedData["rocket_key"],
            $encryptedData["secret"],
            $encryptedData["is_whitelabel"],
            substr($jwtPayload["aud"], 4),
            $jwtPayload["Resource"],
            $keyPair
        );

        $this->debugLog("Dispatching " . RocketCreatedEvent::NAME . " event");
        $this->eventDispatcher->dispatchEvent(
            RocketCreatedEvent::NAME,
            new RocketCreatedEvent($result)
        );

        return $result;
    }

    /**
     * @param $message
     * @param array $context
     */
    private function debugLog($message, $context = array())
    {
        if ($this->logger) {
            $this->logger->debug($message, $context);
        }
    }

    private function getPublicKey()
    {
        return $this->api->ping()->getPublicKey();
    }

    /**
     * @param $launchkeyTimeString
     *
     * @return \DateTime
     */
    private function getLaunchKeyDate($launchkeyTimeString)
    {
        return \DateTime::createFromFormat(
            static::LAUNCHKEY_DATE_FORMAT,
            $launchkeyTimeString,
            new \DateTimeZone(static::LAUNCHKEY_DATE_TZ)
        );
    }

    private function base64UrlDecode($base64UrlEncoded)
    {
        $replaced = strtr($base64UrlEncoded, '-_', '+/');
        $base64Encoded = $replaced . str_repeat("=", strlen($replaced) % 4);
        return base64_decode($base64Encoded);
    }
}
