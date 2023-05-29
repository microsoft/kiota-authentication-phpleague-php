<?php

namespace Microsoft\Kiota\Authentication\Oauth;

use InvalidArgumentException;
use League\OAuth2\Client\Grant\GrantFactory;
use League\OAuth2\Client\Provider\GenericProvider;

class ProviderFactory
{
    /**
     * Initialises a PHP League provider for the Microsoft Identity platform
     * @param TokenRequestContext $tokenRequestContext
     * @param array<string, object> $collaborators
     * @param string $tokenServiceBaseUrl Base URL for the token and authorize endpoint. Defaults to
     * https://login.microsoftonline.com
     * @param string $userInfoServiceBaseUrl Base URL for the user info endpoint. Defaults to
     * https://graph.microsoft.com
     * @return GenericProvider
     */
    public static function create(
        TokenRequestContext $tokenRequestContext,
        array $collaborators = [],
        string $tokenServiceBaseUrl = 'https://login.microsoftonline.com',
        string $userInfoServiceBaseUrl = 'https://graph.microsoft.com'
    ): GenericProvider
    {
        $grantFactory = new GrantFactory();
        // Add our custom grant type to the registry
        $grantFactory->setGrant('urn:ietf:params:Oauth:grant-type:jwt-bearer', new OnBehalfOfGrant());

        return new GenericProvider([
            'urlAccessToken' => "$tokenServiceBaseUrl/{$tokenRequestContext->getTenantId()}/oauth2/v2.0/token",
            'urlAuthorize' => "$tokenServiceBaseUrl/{$tokenRequestContext->getTenantId()}/oauth2/v2.0/authorize",
            'urlResourceOwnerDetails' => "$userInfoServiceBaseUrl/oidc/userinfo",
            'accessTokenResourceOwnerId' => 'id_token'
        ], $collaborators + [
            'grantFactory' => $grantFactory
        ]);
    }
}
