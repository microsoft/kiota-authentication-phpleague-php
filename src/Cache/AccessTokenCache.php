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
     * @return AccessToken|null
     */
    public function getAccessToken(): ?AccessToken;

    /**
     * Persist access token in cache
     *
     * @param AccessToken $accessToken
     * @return void
     */
    public function persistAccessToken(AccessToken $accessToken): void;
}
