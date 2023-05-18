<?php

namespace Microsoft\Kiota\Authentication\Cache;

use League\OAuth2\Client\Token\AccessToken;

/**
 * Interface AccessTokenCache
 * @package Microsoft\Kiota\Authentication
 * @copyright 2022 Microsoft Corporation
 * @license https://opensource.org/licenses/MIT MIT License
 * @link https://developer.microsoft.com/graph
 */
interface AccessTokenCache
{
    /**
     * Return cached access token if available, else return null
     *
     * @param string $identity
     * @return AccessToken|null
     */
    public function getAccessToken(string $identity): ?AccessToken;

    /**
     * Persist access token in cache
     *
     * @param string $identity
     * @param AccessToken $accessToken
     * @return void
     */
    public function persistAccessToken(string $identity, AccessToken $accessToken): void;
}
