<?php

namespace Microsoft\Kiota\Authentication\Cache;

use InvalidArgumentException;
use League\OAuth2\Client\Token\AccessToken;
use Microsoft\Kiota\Authentication\Oauth\TokenRequestContext;

/**
 * Class InMemoryAccessTokenCache
 *
 * In memory cache for access token
 *
 * @package Microsoft\Kiota\Authentication
 * @copyright 2022 Microsoft Corporation
 * @license https://opensource.org/licenses/MIT MIT License
 * @link https://developer.microsoft.com/graph
 */
class InMemoryAccessTokenCache implements AccessTokenCache
{
    /**
     * @var array<string, AccessToken>
     */
    private array $accessTokens = [];

    /**
     * Initializes the InMemoryAccessTokenCache with an access token and its related context. To add more access tokens
     * use withToken().
     *
     * @param TokenRequestContext|null $tokenRequestContext
     * @param AccessToken|null $accessToken
     */
    public function __construct(?TokenRequestContext $tokenRequestContext = null, ?AccessToken $accessToken = null)
    {
        if ($tokenRequestContext && $accessToken) {
            $this->withToken($tokenRequestContext, $accessToken);
        }
    }

    /**
     * Initializes the InMemoryAccessTokenCache with an access token and its related context.
     *
     * @param TokenRequestContext $tokenRequestContext
     * @param AccessToken $accessToken
     * @return self
     * @throws InvalidArgumentException if the cache key cannot be initialized
     * OR the cache already contains an access token with the same identity/TokenRequestContext
     */
    public function withToken(TokenRequestContext $tokenRequestContext, AccessToken $accessToken): self
    {
        $tokenRequestContext->setCacheKey($accessToken);
        if (!$tokenRequestContext->getCacheKey()) {
            throw new InvalidArgumentException("Unable to initialize cache key for context using access token");
        }
        if (array_key_exists($tokenRequestContext->getCacheKey(), $this->accessTokens)) {
            throw new InvalidArgumentException("Cache already contains an access token with the same identity");
        }
        $this->accessTokens[$tokenRequestContext->getCacheKey()] = $accessToken;
        return $this;
    }

    /**
     * Returns the access token with the given identity from the cache
     *
     * @param string $identity
     * @return AccessToken|null
     */
    public function getAccessToken(string $identity): ?AccessToken
    {
        return $this->accessTokens[$identity] ?? null;
    }

    /**
     * Adds an access token with the given identity to the cache
     *
     * @param string $identity
     * @param AccessToken $accessToken
     * @return void
     */
    public function persistAccessToken(string $identity, AccessToken $accessToken): void
    {
        $this->accessTokens[$identity] = $accessToken;
    }

    /**
     * Returns the access token given the token request context
     *
     * @param TokenRequestContext $tokenRequestContext
     * @return AccessToken|null
     * @throws InvalidArgumentException if $tokenRequestContext has a null cache key
     */
    public function getTokenWithContext(TokenRequestContext $tokenRequestContext): ?AccessToken {
        if (is_null($tokenRequestContext->getCacheKey())) {
            throw new InvalidArgumentException("Unable to get token using context with a null cache key");
        }
        return $this->getAccessToken($tokenRequestContext->getCacheKey());
    }
}
