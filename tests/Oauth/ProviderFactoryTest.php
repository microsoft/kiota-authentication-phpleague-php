<?php

namespace Microsoft\Kiota\Authentication\Test\Oauth;

use GuzzleHttp\Client;
use InvalidArgumentException;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessToken;
use Microsoft\Kiota\Authentication\Oauth\ClientCredentialContext;
use Microsoft\Kiota\Authentication\Oauth\ProviderFactory;
use PHPUnit\Framework\TestCase;

class ProviderFactoryTest extends TestCase
{
    public function testCustomHttpClient(): void
    {
        $httpClient = new Client();

        $provider = ProviderFactory::create(
            new ClientCredentialContext('_', '_', '_'),
            [
                'httpClient' => $httpClient,
            ]
        );

        self::assertSame($httpClient, $provider->getHttpClient());
    }

    public function testDefaultConfiguration(): void
    {
        $oauthProvider = ProviderFactory::create(new ClientCredentialContext(
            '1', 'client', 'secret'
        ));
        $this->assertInstanceOf(GenericProvider::class, $oauthProvider);
        $this->assertEquals("https://graph.microsoft.com/oidc/userinfo", $oauthProvider->getResourceOwnerDetailsUrl(
            $this->createMock(AccessToken::class)
        ));
        $this->assertEquals("https://login.microsoftonline.com/1/oauth2/v2.0/token", $oauthProvider->getBaseAccessTokenUrl([]));
        $this->assertEquals("https://login.microsoftonline.com/1/oauth2/v2.0/authorize", $oauthProvider->getBaseAuthorizationUrl());
    }

    public function testUpdatingBaseURLs(): void
    {
        $chinaCloudUserInfo = 'https://microsoftgraph.chinacloudapi.cn';
        $chinaCloudTokenService = 'https://login.chinacloudapi.cn';
        $oauthProvider = ProviderFactory::create(new ClientCredentialContext(
            '1', 'client', 'secret'
        ), [], $chinaCloudTokenService, $chinaCloudUserInfo);
        $this->assertInstanceOf(GenericProvider::class, $oauthProvider);
        $this->assertEquals("$chinaCloudUserInfo/oidc/userinfo",$oauthProvider->getResourceOwnerDetailsUrl(
            $this->createMock(AccessToken::class)
        ));
        $this->assertEquals("$chinaCloudTokenService/1/oauth2/v2.0/token", $oauthProvider->getBaseAccessTokenUrl([]));
        $this->assertEquals("$chinaCloudTokenService/1/oauth2/v2.0/authorize", $oauthProvider->getBaseAuthorizationUrl());
    }
}
