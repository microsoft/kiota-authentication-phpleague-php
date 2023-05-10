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
    /**
     * @var array<string, AccessToken>
     */
    private array $accessTokens = [];

    public function getAccessToken(string $identity): ?AccessToken
    {
        return $this->accessTokens[$identity] ?? null;
    }

    public function persistAccessToken(string $identity, AccessToken $accessToken): void
    {
        $this->accessTokens[$identity] = $accessToken;
    }
}
