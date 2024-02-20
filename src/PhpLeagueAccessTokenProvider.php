<?php
/**
 * Copyright (c) Microsoft Corporation.  All Rights Reserved.
 * Licensed under the MIT License.  See License in the project root
 * for license information.
 */


namespace Microsoft\Kiota\Authentication;


use Exception;
use Http\Promise\FulfilledPromise;
use Http\Promise\Promise;
use Http\Promise\RejectedPromise;
use InvalidArgumentException;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Microsoft\Kiota\Abstractions\Authentication\AccessTokenProvider;
use Microsoft\Kiota\Abstractions\Authentication\AllowedHostsValidator;
use Microsoft\Kiota\Authentication\Oauth\ContinuousAccessEvaluationException;
use Microsoft\Kiota\Authentication\Oauth\ProviderFactory;
use Microsoft\Kiota\Authentication\Cache\AccessTokenCache;
use Microsoft\Kiota\Authentication\Cache\InMemoryAccessTokenCache;
use Microsoft\Kiota\Authentication\Oauth\TokenRequestContext;
use OpenTelemetry\API\Trace\SpanInterface;
use OpenTelemetry\API\Trace\StatusCode;
use OpenTelemetry\API\Trace\TracerInterface;
use OpenTelemetry\Context\Context;

/**
 * Class PhpLeagueAccessTokenProvider
 * @package Microsoft\Kiota\Authentication
 * @copyright 2022 Microsoft Corporation
 * @license https://opensource.org/licenses/MIT MIT License
 * @link https://developer.microsoft.com/graph
 */
class PhpLeagueAccessTokenProvider implements AccessTokenProvider
{

    public const CP1_CLAIM = '{"access_token":{"xms_cc":{"values":["cp1"]}}}';
    /**
     * @var TokenRequestContext {@link TokenRequestContext}
     */
    private TokenRequestContext $tokenRequestContext;
    /**
     * @var AllowedHostsValidator Validates whether a token should be fetched for a request url
     */
    private AllowedHostsValidator $allowedHostsValidator;

    public const LOCALHOST_STRINGS = ['localhost' => true, '::1' => true, '[::1]' => true, '127.0.0.1' => true];
    /**
     * @var array<string>
     */
    private array $scopes;
    /** @var TracerInterface $tracer */
    private TracerInterface $tracer;

    /** @var ObservabilityOptions $observabilityOptions */
    private ObservabilityOptions $observabilityOptions;
    /**
     * @var AbstractProvider OAuth 2.0 provider from PHP League library
     */
    private AbstractProvider $oauthProvider;

    /**
     * @var AccessTokenCache Cache to store access token
     */
    private AccessTokenCache $accessTokenCache;

    /**
     * Creates a new instance
     * @param TokenRequestContext $tokenRequestContext
     * @param array<string> $scopes
     * @param array<string> $allowedHosts
     * @param AbstractProvider|null $oauthProvider when null, defaults to a Microsoft Identity Authentication Provider
     * @param AccessTokenCache|null $accessTokenCache defaults to an in-memory cache
     * @param ObservabilityOptions|null $observabilityOptions
     */
    public function __construct(
        TokenRequestContext $tokenRequestContext,
        array $scopes = [],
        array $allowedHosts = [],
        ?AbstractProvider $oauthProvider = null,
        ?AccessTokenCache $accessTokenCache = null,
        ?ObservabilityOptions $observabilityOptions = null
    )
    {
        $this->tokenRequestContext = $tokenRequestContext;
        $this->scopes = $scopes;
        $this->allowedHostsValidator = new AllowedHostsValidator();
        $this->allowedHostsValidator->setAllowedHosts($allowedHosts);
        $this->oauthProvider = $oauthProvider ?? ProviderFactory::create($tokenRequestContext);
        $this->accessTokenCache = $accessTokenCache === null ? new InMemoryAccessTokenCache() : $accessTokenCache;
        $this->observabilityOptions = $observabilityOptions ?? new ObservabilityOptions();
        $this->tracer = $this->observabilityOptions::getTracer();

    }

    private const TOKEN_GET_RESULT_KEY = "get_authorization_token_success";
    private const TOKEN_FROM_CACHE_KEY = "get_authorization_from_cache";
    private const CONTAINS_CLAIMS_KEY = "com.microsoft.kiota.authentication.additional_claims_provided";
    private const TOKEN_CACHE_EVENT = 'token_cached';
    private const REFRESH_TOKEN_EVENT = 'refresh_token';
    private const TOKEN_REFRESHED = 'token_refreshed';
    private const REQUEST_NEW_TOKEN_EVENT = 'new_token_requested';
    private const SCOPES_KEY = 'com.microsoft.kiota.authentication.scopes';
    private const URL_VALID_KEY = 'com.microsoft.kiota.authentication.is_url_valid';

    /**
     * @inheritDoc
     */
    public function getAuthorizationTokenAsync(string $url, array $additionalAuthenticationContext = []): Promise
    {
        $span = $this->tracer->spanBuilder('getAuthorizationTokenAsync')->startSpan();
        $scope = $span->activate();
        $parsedUrl = parse_url($url);
        $scheme = $parsedUrl["scheme"] ?? null;
        $host = $parsedUrl["host"] ?? '';
        try {
            if (!$this->getAllowedHostsValidator()->isUrlHostValid($url)) {
                $span->setAttribute(self::URL_VALID_KEY, false);
                return new FulfilledPromise(null);
            }

            $isLocalhost = $this->isLocalHostUrl($host);

            if ($scheme !== 'https' && !$isLocalhost) {
                $span->setAttribute(self::URL_VALID_KEY, false);
                throw new InvalidArgumentException("Invalid URL. External URLs MUST use HTTPS and localhost URLs MAY use HTTP.");
            }
            $span->setAttribute(self::URL_VALID_KEY, true);
            $this->scopes = $this->scopes ?: ["{$scheme}://{$host}/.default"];
            $span->setAttribute(self::SCOPES_KEY, implode(',', $this->scopes));
            $params = array_merge($this->tokenRequestContext->getParams(), ['scope' => implode(' ', $this->scopes)]);
            if ($additionalAuthenticationContext['claims'] ?? false) {
                $span->setAttribute(self::CONTAINS_CLAIMS_KEY, true);
                $claims = base64_decode(strval($additionalAuthenticationContext['claims']));
                if ($this->tokenRequestContext->getCacheKey()) {
                    $cachedToken = $this->accessTokenCache->getAccessToken($this->tokenRequestContext->getCacheKey());
                    if ($cachedToken) {
                        $token = $this->tryCAETokenRefresh($cachedToken, $params, $claims, $span);
                        $this->cacheToken($token, $span);
                        $tokenFromCache = $token->getToken();
                        $span->setAttribute(self::TOKEN_FROM_CACHE_KEY, true);
                        $span->setAttribute(self::TOKEN_GET_RESULT_KEY, true);
                        return new FulfilledPromise($tokenFromCache);
                    }
                }
            }

            if ($this->tokenRequestContext->getCacheKey()) {
                $cachedToken = $this->accessTokenCache->getAccessToken($this->tokenRequestContext->getCacheKey());
                if ($cachedToken) {
                    if ($cachedToken->getExpires() && !$cachedToken->hasExpired()) {
                        $span->setAttribute(self::TOKEN_FROM_CACHE_KEY, true);
                        $span->setAttribute(self::TOKEN_GET_RESULT_KEY, true);
                        return new FulfilledPromise($cachedToken->getToken());
                    }
                    if ($cachedToken->getRefreshToken()) {
                        $refreshedToken = $this->refreshToken($cachedToken->getRefreshToken(), [], $span);
                        $this->cacheToken($refreshedToken, $span);
                        $span->setAttribute(self::TOKEN_GET_RESULT_KEY, true);
                        return new FulfilledPromise($refreshedToken->getToken());
                    }
                }
            }
            $token = $this->requestNewToken($params, $span);
            $this->cacheToken($token, $span);
            $result = new FulfilledPromise($token->getToken());
            $span->setAttribute(self::TOKEN_GET_RESULT_KEY, true);
            $span->setStatus(StatusCode::STATUS_OK);
            return $result;
        }
        catch (\Exception $ex) {
            $span->recordException($ex);
            $span->setStatus(StatusCode::STATUS_ERROR);
            return new RejectedPromise($ex);
        } finally {
            $scope->detach();
            $span->end();
        }
    }

    /**
     * Check if the given host string is a localhost string.
     * @param string $host
     * @return bool
     */
    private function isLocalHostUrl(string $host): bool
    {
        $lowerCasedHost = strtolower($host);
        return array_key_exists($lowerCasedHost, self::LOCALHOST_STRINGS) || $lowerCasedHost === ':';
    }
    /**
     * @inheritDoc
     */
    public function getAllowedHostsValidator(): AllowedHostsValidator
    {
        return $this->allowedHostsValidator;
    }

    /**
     * Returns the underlying OAuth provider
     *
     * @return AbstractProvider
     */
    public function getOauthProvider(): AbstractProvider
    {
        return $this->oauthProvider;
    }

    /**
     * Returns the underlying cache
     *
     * @return AccessTokenCache
     */
    public function getAccessTokenCache(): AccessTokenCache
    {
        return $this->accessTokenCache;
    }

    /**
     * @return TokenRequestContext
     */
    public function getTokenRequestContext(): TokenRequestContext
    {
        return $this->tokenRequestContext;
    }

    /**
     * @return array<string>
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * @return array<string>
     */
    public function getAllowedHosts(): array
    {
        return $this->allowedHostsValidator->getAllowedHosts();
    }

    /**
     * Attempts to cache the access token if the TokenRequestContext provides a cache key
     * @param AccessToken $token
     * @param SpanInterface $span
     */
    private function cacheToken(AccessToken $token, SpanInterface $span): void
    {
        $this->tokenRequestContext->setCacheKey($token);
        if ($this->tokenRequestContext->getCacheKey()) {
            $this->accessTokenCache->persistAccessToken($this->tokenRequestContext->getCacheKey(), $token);
            $span->addEvent(self::TOKEN_CACHE_EVENT);
        }
    }

    /**
     * Refreshes token
     * @param string $refreshToken
     * @param array<string, string> $params
     * @param SpanInterface|null $span
     * @return AccessToken
     * @throws IdentityProviderException
     */
    private function refreshToken(string $refreshToken, array $params = [], ?SpanInterface $span = null): AccessToken
    {
        assert($span !== null);
        $span->addEvent(self::REFRESH_TOKEN_EVENT);
        if ($params['claims'] ?? false) {
            $params = $this->mergeClaims(
                $this->tokenRequestContext->getRefreshTokenParams($refreshToken),
                $params['claims']
            );
        }
        $params = array_merge(
            $this->tokenRequestContext->getRefreshTokenParams($refreshToken),
            $params
        );
        $result = $this->oauthProvider->getAccessToken('refresh_token', $params);
        $span->setAttribute(self::TOKEN_REFRESHED, true);
        // @phpstan-ignore-next-line
        return $result;
    }

    /**
     * @param array<string, string> $params
     * @param SpanInterface $span
     * @return AccessToken
     * @throws IdentityProviderException
     */
    private function requestNewToken(array $params, SpanInterface $span): AccessToken
    {
        $span->addEvent(self::REQUEST_NEW_TOKEN_EVENT);
        if ($this->tokenRequestContext->isCAEEnabled()) {
            $params = $this->mergeClaims($params, self::CP1_CLAIM);
        }
        // @phpstan-ignore-next-line
        return $this->oauthProvider->getAccessToken($this->tokenRequestContext->getGrantType(), $params);
    }

    /**
     * Attempts to get a new access token using the refresh token + claims.
     * If that fails, call the redirect callback if it's available. Otherwise, fail with an exception containing the
     * claims
     *
     * @param AccessToken $cachedToken
     * @param array<string, string> $initialParams
     * @param string $claims
     * @param SpanInterface $span
     * @return AccessToken
     * @throws ContinuousAccessEvaluationException
     * @throws IdentityProviderException
     */
    private function tryCAETokenRefresh(AccessToken $cachedToken, array $initialParams, string $claims, SpanInterface $span): AccessToken
    {
        $childSpan = $this->tracer->spanBuilder('tryCAETokenRefresh')
            ->setParent(Context::getCurrent())
            ->addLink($span->getContext())
            ->startSpan();
        $scope = $childSpan->activate();
        try {
            if ($cachedToken->getRefreshToken()) {
                try {
                    $result = $this->refreshToken($cachedToken->getRefreshToken(),
                        ['claims' => $claims],
                        $childSpan);
                    $childSpan->setStatus(StatusCode::STATUS_OK);
                    return $result;
                } catch (\Exception $ex) {
                    $childSpan->recordException($ex);
                    $childSpan->setStatus(StatusCode::STATUS_ERROR);
                    $this->handleFailedCAETokenRefresh($claims, $childSpan);
                    return $this->requestNewToken($initialParams, $childSpan);
                }
            }
            $this->handleFailedCAETokenRefresh($claims, $childSpan);
            return $this->requestNewToken($initialParams, $childSpan);
        } finally {
            $scope->detach();
            $childSpan->end();
        }
    }

    /**
     * @param string $claims
     * @param SpanInterface $span
     * @throws ContinuousAccessEvaluationException
     */
    private function handleFailedCAETokenRefresh(string $claims, SpanInterface $span): void
    {
        $childSpan = $this->tracer->spanBuilder('handleFailedCAETokenRefresh')
            ->setParent(Context::getCurrent())
            ->addLink($span->getContext())
            ->startSpan();
        try {
            if (!$this->tokenRequestContext->getCAERedirectCallback()) {
                $span->setStatus(StatusCode::STATUS_ERROR);
                $ex = new ContinuousAccessEvaluationException(
                    "Token refresh failed and no redirect callback was provided.
                Use the claims property and redirect your customer to the login page",
                    $claims
                );
                $span->recordException($ex);
                throw $ex;
            }
            $promise = $this->tokenRequestContext->getCAERedirectCallback()($claims);
            if (!$promise instanceof Promise) {
                $span->setStatus(StatusCode::STATUS_ERROR);
                $ex = new ContinuousAccessEvaluationException(
                    "Redirect callback should return a promise that resolves to a valid TokenRequestContext",
                    $claims
                );
                $span->recordException($ex);
                throw $ex;
            }
            $context = null;
            try {
                $context = $promise->wait();
            } catch (Exception $exception) {
                $span->setStatus(StatusCode::STATUS_ERROR);
                $span->recordException($exception);
            }
            if (!$context instanceof TokenRequestContext) {
                $span->setStatus(StatusCode::STATUS_ERROR);
                $ex = new ContinuousAccessEvaluationException(
                    "Redirect callback did not return a valid TokenRequestContext",
                    $claims
                );
                $span->recordException($ex);
                throw $ex;
            }
            $this->tokenRequestContext = $context;
        } finally {
            $childSpan->end();
        }
    }

    /**
     * @param array<string, string> $params
     * @param string $claims
     * @return array<string, string>
     */
    private function mergeClaims(array $params, string $claims): array
    {
        if ($params['claims'] ?? false) {
            $paramClaims = json_decode($params['claims'], true);
            $newClaims = json_decode($claims, true);
            if (is_array($paramClaims) && is_array($newClaims)) {
                $mergedClaims = array_merge_recursive($paramClaims, $newClaims);
                $mergedClaimsJson = json_encode($mergedClaims);
                if ($mergedClaimsJson) {
                    $params['claims'] = $mergedClaimsJson;
                    return $params;
                }
            }
        }
        $params['claims'] = $claims;
        return $params;
    }

}
