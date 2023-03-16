<?php

namespace Microsoft\Kiota\Authentication\Test\Stub;

use League\OAuth2\Client\Token\AccessToken;
use Microsoft\Kiota\Authentication\Cache\AccessTokenCache;

class StubAccessTokenCache implements AccessTokenCache
{
    /**
     * @var array<string, AccessToken>
     */
    public array $accessTokens = [];

    public function getAccessToken(string $identity): ?AccessToken
    {
        return $this->accessTokens[$identity] ?? null;
    }

    public function persistAccessToken(string $identity, AccessToken $accessToken): void
    {
        $this->accessTokens[$identity] = $accessToken;
    }
}
