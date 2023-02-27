<?php

namespace Microsoft\Kiota\Authentication\Oauth;

use League\OAuth2\Client\Grant\GrantFactory;
use League\OAuth2\Client\Provider\GenericProvider;

class ProviderFactory
{
    /**
     * Initialises a PHP League provider for the Microsoft Identity platform
     * @param TokenRequestContext $tokenRequestContext
     * @param array<string, object> $collaborators
     */
    public static function create(TokenRequestContext $tokenRequestContext, array $collaborators = []): GenericProvider
    {
        $grantFactory = new GrantFactory();
        // Add our custom grant type to the registry
        $grantFactory->setGrant('urn:ietf:params:Oauth:grant-type:jwt-bearer', new OnBehalfOfGrant());

        return new GenericProvider([
            'urlAccessToken' => "https://login.microsoftonline.com/{$tokenRequestContext->getTenantId()}/oauth2/v2.0/token",
            'urlAuthorize' => "https://login.microsoftonline.com/{$tokenRequestContext->getTenantId()}/oauth2/v2.0/authorize",
            'urlResourceOwnerDetails' => 'https://graph.microsoft.com/oidc/userinfo',
            'accessTokenResourceOwnerId' => 'id_token'
        ], $collaborators + [
            'grantFactory' => $grantFactory
        ]);
    }
}
