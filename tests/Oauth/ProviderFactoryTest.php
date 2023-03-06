<?php

namespace Microsoft\Kiota\Authentication\Test\Oauth;

use GuzzleHttp\Client;
use Microsoft\Kiota\Authentication\Oauth\ClientCredentialContext;
use Microsoft\Kiota\Authentication\Oauth\ProviderFactory;
use PHPUnit\Framework\TestCase;

class ProviderFactoryTest extends TestCase
{
    public function testCustomHttpClient()
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
}
