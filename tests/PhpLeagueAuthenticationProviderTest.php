<?php

namespace Microsoft\Kiota\Authentication\Test;

use Microsoft\Kiota\Authentication\Oauth\ClientCredentialContext;
use Microsoft\Kiota\Authentication\PhpLeagueAccessTokenProvider;
use Microsoft\Kiota\Authentication\PhpLeagueAuthenticationProvider;
use PHPUnit\Framework\TestCase;

class PhpLeagueAuthenticationProviderTest extends TestCase
{
    private PhpLeagueAuthenticationProvider $defaultAuthProvider;

    protected function setUp(): void
    {
        $this->defaultAuthProvider = new PhpLeagueAuthenticationProvider(
            new ClientCredentialContext('tenantId', 'clientId', 'secret'),
            ['https://graph.microsoft.com/.default']
        );
    }

    public function testCorrectOauthProviderEndpointsExposed(): void
    {
        $expected = "https://login.microsoftonline.com/tenantId/oauth2/v2.0/authorize";
        $this->assertEquals($expected, $this->defaultAuthProvider->getAccessTokenProvider()->getOauthProvider()->getBaseAuthorizationUrl());
    }

    public function testCreateWithAccessTokenProvider(): void
    {
        $context = new ClientCredentialContext('tenantId', 'clientId', 'secret');
        $scopes = ['https://graph.microsoft.com/.default'];
        $allowedHosts = [];
        $authenticationProvider = PhpLeagueAuthenticationProvider::createWithAccessTokenProvider(
            new PhpLeagueAccessTokenProvider(
                $context,
                $scopes,
                $allowedHosts
            )
        );
        $this->assertInstanceOf(PhpLeagueAuthenticationProvider::class, $authenticationProvider);
        $this->assertInstanceOf(PhpLeagueAccessTokenProvider::class, $authenticationProvider->getAccessTokenProvider());
        $this->assertEquals($context, $authenticationProvider->getAccessTokenProvider()->getTokenRequestContext());
        $this->assertEquals($scopes, $authenticationProvider->getAccessTokenProvider()->getScopes());
        $this->assertEquals($allowedHosts, $authenticationProvider->getAccessTokenProvider()->getAllowedHosts());
    }
}
