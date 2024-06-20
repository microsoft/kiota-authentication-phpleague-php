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
     * @param string|null $tokenServiceBaseUrl Base URL for the token and authorize endpoint. Defaults to
     * https://login.microsoftonline.com
     * @param string|null $userInfoServiceBaseUrl Base URL for the user info endpoint. Defaults to
     * https://graph.microsoft.com
     * @param array<string, string> $clientOptions Additional client options to pass to the underlying http client.
     * @return GenericProvider
     */
    public static function create(
        TokenRequestContext $tokenRequestContext,
        array $collaborators = [],
        ?string $tokenServiceBaseUrl = null,
        ?string $userInfoServiceBaseUrl = null,
        array $clientOptions = []
    ): GenericProvider
    {
        if ($tokenServiceBaseUrl === null || empty(trim($tokenServiceBaseUrl))) {
            $tokenServiceBaseUrl = 'https://login.microsoftonline.com';
        }
        if ($userInfoServiceBaseUrl === null || empty(trim($userInfoServiceBaseUrl))) {
            $userInfoServiceBaseUrl = 'https://graph.microsoft.com';
        }

        $grantFactory = new GrantFactory();
        // Add our custom grant type to the registry
        $grantFactory->setGrant('urn:ietf:params:Oauth:grant-type:jwt-bearer', new OnBehalfOfGrant());

        $allOptions = array_merge(
            [
                'urlAccessToken' => "$tokenServiceBaseUrl/{$tokenRequestContext->getTenantId()}/oauth2/v2.0/token",
                'urlAuthorize' => "$tokenServiceBaseUrl/{$tokenRequestContext->getTenantId()}/oauth2/v2.0/authorize",
                'urlResourceOwnerDetails' => "$userInfoServiceBaseUrl/oidc/userinfo",
                'accessTokenResourceOwnerId' => 'id_token'
            ], $clientOptions
        );
        return new GenericProvider($allOptions, $collaborators + [
            'grantFactory' => $grantFactory
        ]);
    }
}
