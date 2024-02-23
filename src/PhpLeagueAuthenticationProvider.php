<?php
/**
 * Copyright (c) Microsoft Corporation.  All Rights Reserved.
 * Licensed under the MIT License.  See License in the project root
 * for license information.
 */


namespace Microsoft\Kiota\Authentication;


use Microsoft\Kiota\Abstractions\Authentication\BaseBearerTokenAuthenticationProvider;
use Microsoft\Kiota\Authentication\Oauth\TokenRequestContext;

/**
 * Class PhpLeagueAuthenticationProvider
 *
 * Authenticate requests using PHP League's providers to fetch the access token
 *
 * @package Microsoft\Kiota\Authentication
 * @copyright 2022 Microsoft Corporation
 * @license https://opensource.org/licenses/MIT MIT License
 * @link https://developer.microsoft.com/graph
 */
class PhpLeagueAuthenticationProvider extends BaseBearerTokenAuthenticationProvider
{
    /**
     * @var PhpLeagueAccessTokenProvider
     */
    private PhpLeagueAccessTokenProvider $accessTokenProvider;

    /**
     * @param TokenRequestContext $tokenRequestContext
     * @param array<string> $scopes
     * @param array<string> $allowedHosts
     */
    public function __construct(TokenRequestContext $tokenRequestContext, array $scopes = [], array $allowedHosts = [])
    {
        $this->accessTokenProvider = new PhpLeagueAccessTokenProvider($tokenRequestContext, $scopes, $allowedHosts);
        parent::__construct($this->accessTokenProvider);
    }

    public function getAccessTokenProvider(): PhpLeagueAccessTokenProvider
    {
        return $this->accessTokenProvider;
    }

    /**
     * Get an instance of PhpLeagueAuthenticationProvider your custom PhpLeagueAccessTokenProvider
     *
     * @param PhpLeagueAccessTokenProvider $phpLeagueAccessTokenProvider
     * @return self
     */
    public static function createWithAccessTokenProvider(
        PhpLeagueAccessTokenProvider $phpLeagueAccessTokenProvider
        ): self
    {
        $authProvider = new PhpLeagueAuthenticationProvider(
            $phpLeagueAccessTokenProvider->getTokenRequestContext(),
            $phpLeagueAccessTokenProvider->getScopes(),
            $phpLeagueAccessTokenProvider->getAllowedHosts()
        );
        $authProvider->accessTokenProvider = $phpLeagueAccessTokenProvider;
        return $authProvider;
    }

}
