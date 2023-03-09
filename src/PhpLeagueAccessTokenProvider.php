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
    /**
     * @var array<string>
     */
    private array $scopes;

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
     */
    public function __construct(
        TokenRequestContext $tokenRequestContext,
        array $scopes = [],
        array $allowedHosts = [],
        ?AbstractProvider $oauthProvider = null,
        ?AccessTokenCache $accessTokenCache = null
    )
    {
        $this->tokenRequestContext = $tokenRequestContext;
        $this->scopes = $scopes;
        $this->allowedHostsValidator = new AllowedHostsValidator();
        $this->allowedHostsValidator->setAllowedHosts($allowedHosts);
        $this->oauthProvider = $oauthProvider ?? ProviderFactory::create($tokenRequestContext);
        $this->accessTokenCache = $accessTokenCache === null ? new InMemoryAccessTokenCache() : $accessTokenCache;

    }

    /**
     * @inheritDoc
     */
    public function getAuthorizationTokenAsync(string $url, array $additionalAuthenticationContext = []): Promise
    {
        $parsedUrl = parse_url($url);
        $scheme = $parsedUrl["scheme"] ?? null;
        $host = $parsedUrl["host"] ?? null;

        if ($scheme !== 'https' || !$this->getAllowedHostsValidator()->isUrlHostValid($url)) {
            return new FulfilledPromise(null);
        }

        $this->scopes = $this->scopes ?: ["{$scheme}://{$host}/.default"];
        try {
            $params = array_merge($this->tokenRequestContext->getParams(), ['scope' => implode(' ', $this->scopes)]);
            if ($additionalAuthenticationContext['claims'] ?? false) {
                $claims = base64_decode(strval($additionalAuthenticationContext['claims']));
                if ($this->tokenRequestContext->getCacheKey()) {
                    $cachedToken = $this->accessTokenCache->getAccessToken($this->tokenRequestContext->getCacheKey());
                    if ($cachedToken) {
                        $token = $this->tryCAETokenRefresh($cachedToken,$params, $claims);
                        $this->cacheToken($token);
                        return new FulfilledPromise($token->getToken());
                    }
                }
            }

            if ($this->tokenRequestContext->getCacheKey()) {
                $cachedToken = $this->accessTokenCache->getAccessToken($this->tokenRequestContext->getCacheKey());
                if ($cachedToken) {
                    if ($cachedToken->getExpires() && !$cachedToken->hasExpired()) {
                        return new FulfilledPromise($cachedToken->getToken());
                    }
                    if ($cachedToken->getRefreshToken()) {
                        $refreshedToken = $this->refreshToken($cachedToken->getRefreshToken());
                        $this->cacheToken($refreshedToken);
                        return new FulfilledPromise($refreshedToken->getToken());
                    }
                }
            }
            $token = $this->requestNewToken($params);
            $this->cacheToken($token);
            return new FulfilledPromise($token->getToken());
        } catch (\Exception $ex) {
            return new RejectedPromise($ex);
        }
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
     * Attempts to cache the access token if the TokenRequestContext provides a cache key
     * @param AccessToken $token
     */
    private function cacheToken(AccessToken $token): void
    {
        $this->tokenRequestContext->setCacheKey($token);
        if ($this->tokenRequestContext->getCacheKey()) {
            $this->accessTokenCache->persistAccessToken($this->tokenRequestContext->getCacheKey(), $token);
        }
    }

    /**
     * Refreshes token
     * @param string $refreshToken
     * @param array<string, string> $params
     * @return AccessToken
     * @throws IdentityProviderException
     */
    private function refreshToken(string $refreshToken, array $params = []): AccessToken
    {
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
        // @phpstan-ignore-next-line
        return $this->oauthProvider->getAccessToken('refresh_token', $params);
    }

    /**
     * @param array<string, string> $params
     * @return AccessToken
     * @throws IdentityProviderException
     */
    private function requestNewToken(array $params): AccessToken
    {
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
     * @return AccessToken
     * @throws ContinuousAccessEvaluationException
     * @throws IdentityProviderException
     */
    private function tryCAETokenRefresh(AccessToken $cachedToken, array $initialParams, string $claims): AccessToken
    {
        if ($cachedToken->getRefreshToken()) {
            try {
                return $this->refreshToken($cachedToken->getRefreshToken(), ['claims' => $claims]);
            } catch (\Exception $ex) {
                $this->handleFailedCAETokenRefresh($claims);
                return $this->requestNewToken($initialParams);
            }
        }
        $this->handleFailedCAETokenRefresh($claims);
        return $this->requestNewToken($initialParams);
    }

    /**
     * @param string $claims
     * @throws ContinuousAccessEvaluationException
     */
    private function handleFailedCAETokenRefresh(string $claims): void
    {
        if (!$this->tokenRequestContext->getCAERedirectCallback()) {
            throw new ContinuousAccessEvaluationException(
                "Token refresh failed and no redirect callback was provided.
                Use the claims property and redirect your customer to the login page",
                $claims
            );
        }
        $promise = $this->tokenRequestContext->getCAERedirectCallback()($claims);
        if (!$promise instanceof Promise) {
            throw new ContinuousAccessEvaluationException(
                "Redirect callback should return a promise that resolves to a valid TokenRequestContext",
                $claims
            );
        }
        $context = $promise->wait();
        if (!$context instanceof TokenRequestContext) {
            throw new ContinuousAccessEvaluationException(
                "Redirect callback did not return a valid TokenRequestContext",
                $claims
            );
        }
        $this->tokenRequestContext = $context;
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
