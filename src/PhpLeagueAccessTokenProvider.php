<?php
/**
 * Copyright (c) Microsoft Corporation.  All Rights Reserved.
 * Licensed under the MIT License.  See License in the project root
 * for license information.
 */


namespace Microsoft\Kiota\Authentication;


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
    /**
     * @var TokenRequestContext {@link TokenRequestContext}
     */
    private TokenRequestContext $tokenRequestContext;
    /**
     * @var AllowedHostsValidator Validates whether a token should be fetched for a request url
     */
    private AllowedHostsValidator $allowedHostsValidator;
    /**
     * @var array<string, string>
     */
    private array $scopes;
    /**
     * @var AccessToken|null Token object to re-use before expiry
     */
    private ?AccessToken $cachedToken = null;
    /**
     * @var AbstractProvider OAuth 2.0 provider from PHP League library
     */
    private AbstractProvider $oauthProvider;

    /**
     * Creates a new instance
     * @param TokenRequestContext $tokenRequestContext
     * @param array $scopes
     * @param array $allowedHosts
     * @param AbstractProvider|null $oauthProvider
     */
    public function __construct(TokenRequestContext $tokenRequestContext, array $scopes = [], array $allowedHosts = [], ?AbstractProvider $oauthProvider = null)
    {
        $this->tokenRequestContext = $tokenRequestContext;
        $this->scopes = $scopes;
        $this->allowedHostsValidator = new AllowedHostsValidator();
        $this->allowedHostsValidator->setAllowedHosts($allowedHosts);
        $this->oauthProvider = $oauthProvider ?? ProviderFactory::create($tokenRequestContext);
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
            if (($additionalAuthenticationContext['claims'] ?? false)) {
                $claims = json_decode(base64_decode($additionalAuthenticationContext['claims']), true);
                $this->tryCAETokenRefresh($claims);
            }
            if ($this->cachedToken
                && $this->cachedToken->getExpires()
                && $this->cachedToken->hasExpired()
                && $this->cachedToken->getRefreshToken()
            ) {
                $this->cachedToken = $this->refreshToken();
                return new FulfilledPromise($this->cachedToken->getToken());
            }
            if ($this->tokenRequestContext->isCAEEnabled()) {
                $params = array_merge_recursive(
                    $params,
                    ['claims' => ['access_token' => ['xms_cc' => ['values' => ['cp1']]]]]
                );
            }
            // @phpstan-ignore-next-line
            $this->cachedToken = $this->oauthProvider->getAccessToken($this->tokenRequestContext->getGrantType(), $params);
            return new FulfilledPromise($this->cachedToken->getToken());
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
     * Refreshes token
     * @param array $params
     * @return AccessToken
     * @throws IdentityProviderException
     */
    private function refreshToken(array $params = []): AccessToken
    {
        $params = array_merge_recursive(
            $this->tokenRequestContext->getRefreshTokenParams($this->cachedToken->getRefreshToken()),
            $params
        );
        // @phpstan-ignore-next-line
        return $this->oauthProvider->getAccessToken('refresh_token', $params);
    }

    /**
     * Attempts to get a new access token using the refresh token + claims.
     * If that fails, call the redirect callback if it's available. Otherwise, fail with an exception containing the
     * claims
     *
     * @param string $claims
     * @throws ContinuousAccessEvaluationException
     */
    private function tryCAETokenRefresh(string $claims): void
    {
        if ($this->cachedToken && $this->cachedToken->getRefreshToken()) {
           try {
               $this->cachedToken = $this->refreshToken(['claims' => $claims]);
           } catch (\Exception $ex) {
               $this->handleFailedCAETokenRefresh($claims);
           }
       }
       $this->handleFailedCAETokenRefresh($claims);
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
        $context = $this->tokenRequestContext->getCAERedirectCallback()($claims)->wait();
        if (!$context instanceof TokenRequestContext) {
            throw new ContinuousAccessEvaluationException(
                "Redirect callback did not return a valid TokenRequestContext",
                $claims
            );
        }
        $this->tokenRequestContext = $context;
    }

}
