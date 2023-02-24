<?php

namespace Microsoft\Kiota\Authentication\Cache;

use League\OAuth2\Client\Token\AccessToken;

class InMemoryAccessTokenCache implements AccessTokenCache
{
    private ?AccessToken $accessToken = null;

    public function getAccessToken(): ?AccessToken
    {
        return $this->accessToken;
    }

    public function persistAccessToken(AccessToken $accessToken): void
    {
        $this->accessToken = $accessToken;
    }
}
