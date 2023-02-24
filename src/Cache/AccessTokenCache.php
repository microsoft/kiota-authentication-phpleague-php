<?php

namespace Microsoft\Kiota\Authentication\Cache;

use League\OAuth2\Client\Token\AccessToken;

interface AccessTokenCache
{
    public function getAccessToken(): ?AccessToken;

    public function persistAccessToken(AccessToken $accessToken): void;
}
