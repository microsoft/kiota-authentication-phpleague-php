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
use League\OAuth2\Client\Grant\GrantFactory;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\GenericProvider;
use Microsoft\Kiota\Abstractions\Authentication\AccessTokenProvider;
use Microsoft\Kiota\Abstractions\Authentication\AllowedHostsValidator;
use Microsoft\Kiota\Authentication\Cache\AccessTokenCache;
use Microsoft\Kiota\Authentication\Cache\InMemoryAccessTokenCache;
use Microsoft\Kiota\Authentication\Oauth\OnBehalfOfGrant;
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
     * @var GenericProvider OAuth 2.0 provider from PHP League library
     */
    private GenericProvider $oauthProvider;

    /**
     * @var AccessTokenCache Cache to store access token
     */
    private AccessTokenCache $accessTokenCache;

    /**
     * Creates a new instance
     * @param TokenRequestContext $tokenRequestContext
     * @param array $scopes
     * @param array $allowedHosts
     * @param AccessTokenCache|null $accessTokenCache
     */
    public function __construct(TokenRequestContext $tokenRequestContext, array $scopes = [], array $allowedHosts = [], ?AccessTokenCache $accessTokenCache = null)
    {
        $this->tokenRequestContext = $tokenRequestContext;
        $this->scopes = $scopes;
        $this->allowedHostsValidator = new AllowedHostsValidator();
        $this->allowedHostsValidator->setAllowedHosts($allowedHosts);

        $this->accessTokenCache = $accessTokenCache === null ? new InMemoryAccessTokenCache() : $accessTokenCache;

        $this->initOauthProvider();
    }

    /**
     * @inheritDoc
     */
    public function getAuthorizationTokenAsync(string $url): Promise
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
            $accessToken = $this->accessTokenCache->getAccessToken();
            if ($accessToken) {
                if ($accessToken->getExpires() && $accessToken->hasExpired()) {
                    if ($accessToken->getRefreshToken()) {
                        // @phpstan-ignore-next-line
                        $accessToken = $this->oauthProvider->getAccessToken('refresh_token', $this->tokenRequestContext->getRefreshTokenParams($accessToken->getRefreshToken()));
                    } else {
                        // @phpstan-ignore-next-line
                        $accessToken = $this->oauthProvider->getAccessToken($this->tokenRequestContext->getGrantType(), $params);
                    }
                    $this->accessTokenCache->persistAccessToken($accessToken);
                }
                return new FulfilledPromise($accessToken->getToken());
            }
            // @phpstan-ignore-next-line
            $accessToken = $this->oauthProvider->getAccessToken($this->tokenRequestContext->getGrantType(), $params);
            $this->accessTokenCache->persistAccessToken($accessToken);
            return new FulfilledPromise($accessToken->getToken());
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
     * Initialises a PHP League provider
     */
    private function initOauthProvider(): void
    {
        $grantFactory = new GrantFactory();
        // Add our custom grant type to the registry
        $grantFactory->setGrant('urn:ietf:params:Oauth:grant-type:jwt-bearer', new OnBehalfOfGrant());

        $this->oauthProvider = new GenericProvider([
            'urlAccessToken' => "https://login.microsoftonline.com/{$this->tokenRequestContext->getTenantId()}/oauth2/v2.0/token",
            'urlAuthorize' => "https://login.microsoftonline.com/{$this->tokenRequestContext->getTenantId()}/oauth2/v2.0/authorize",
            'urlResourceOwnerDetails' => 'https://graph.microsoft.com/oidc/userinfo',
            'accessTokenResourceOwnerId' => 'id_token'
        ], [
            'grantFactory' => $grantFactory
        ]);
    }

}
