<?php

namespace Microsoft\Kiota\Authentication\Cache;

use League\OAuth2\Client\Token\AccessToken;

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
