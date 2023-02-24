<?php

namespace Microsoft\Kiota\Authentication\Test\Stub;

use League\OAuth2\Client\Token\AccessToken;
use Microsoft\Kiota\Authentication\Cache\AccessTokenCache;

class StubAccessTokenCache implements AccessTokenCache
{
    public ?AccessToken $accessToken = null;

    public function getAccessToken(): ?AccessToken
    {
        return $this->accessToken;
    }

    public function persistAccessToken(AccessToken $accessToken): void
    {
        $this->accessToken = $accessToken;
    }
}
