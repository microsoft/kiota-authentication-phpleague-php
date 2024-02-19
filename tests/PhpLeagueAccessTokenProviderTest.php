<?php

namespace Microsoft\Kiota\Authentication\Test;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Http\Promise\FulfilledPromise;
use InvalidArgumentException;
use League\OAuth2\Client\Token\AccessToken;
use Microsoft\Kiota\Authentication\Cache\InMemoryAccessTokenCache;
use Microsoft\Kiota\Authentication\Oauth\AuthorizationCodeCertificateContext;
use Microsoft\Kiota\Authentication\Oauth\AuthorizationCodeContext;
use Microsoft\Kiota\Authentication\Oauth\ClientCredentialCertificateContext;
use Microsoft\Kiota\Authentication\Oauth\ClientCredentialContext;
use Microsoft\Kiota\Authentication\Oauth\ContinuousAccessEvaluationException;
use Microsoft\Kiota\Authentication\Oauth\OnBehalfOfCertificateContext;
use Microsoft\Kiota\Authentication\Oauth\OnBehalfOfContext;
use Microsoft\Kiota\Authentication\Oauth\TokenRequestContext;
use Microsoft\Kiota\Authentication\PhpLeagueAccessTokenProvider;
use Microsoft\Kiota\Authentication\Test\Stub\StubAccessTokenCache;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use function PHPUnit\Framework\assertEquals;
use function PHPUnit\Framework\assertNotEmpty;
use function PHPUnit\Framework\assertNotNull;

class PhpLeagueAccessTokenProviderTest extends TestCase
{
    private PhpLeagueAccessTokenProvider $defaultTokenProvider;
    private string $testJWT;

    protected function setUp(): void
    {
        $this->defaultTokenProvider = new PhpLeagueAccessTokenProvider(
            new ClientCredentialContext('tenantId', 'clientId', 'clientSecret'),
            ['https://graph.microsoft.com/.default']
        );
        $this->testJWT = "headers.".base64_encode(json_encode(['sub' => '123'])).".signature";
    }

    public function testPassingMultipleScopes(): void
    {
        $tokenProvider = new PhpLeagueAccessTokenProvider(new ClientCredentialContext(
            'tenantId', 'clientId', 'secret'
        ), ['User.Read', 'Calendar.ReadWrite']);
        $mockResponses = [
            function (RequestInterface $request) {
                parse_str($request->getBody()->getContents(), $requestBodyMap);
                $this->assertArrayHasKey('scope', $requestBodyMap);
                $this->assertEquals('User.Read Calendar.ReadWrite', $requestBodyMap['scope']);
                return new Response(200);
            }
        ];
        $tokenProvider->getOauthProvider()->setHttpClient($this->getMockHttpClient($mockResponses));
        $tokenProvider->getAuthorizationTokenAsync('https://example.com');
    }

    public function testGetAuthorizationTokenWithSuccessfulTokenResponse(): void
    {
        $oauthContexts = $this->getOauthContexts();
        foreach ($oauthContexts as $tokenRequestContext) {
            $tokenProvider = new PhpLeagueAccessTokenProvider($tokenRequestContext);
            $mockResponses = [
                function (Request $request) use ($tokenRequestContext) {
                    $expectedUrl = 'https://login.microsoftonline.com/tenantId/oauth2/v2.0/token';
                    $this->assertEquals($expectedUrl, strval($request->getUri()));
                    $expectedBody = array_merge($tokenRequestContext->getParams(), [
                        'scope' => 'https://graph.microsoft.com/.default'
                    ]);
                    parse_str($request->getBody()->getContents(), $requestBodyMap);
                    $this->assertEquals($expectedBody, $requestBodyMap);
                    return new Response(200, [], json_encode(['access_token' => 'abc']));
                }
            ];
            $tokenProvider->getOauthProvider()->setHttpClient($this->getMockHttpClient($mockResponses));
            $this->assertEquals('abc', $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com')->wait());
        }
    }

    public function testGetAuthorizationTokenCachesInMemoryByDefault(): void
    {
        $oauthContexts = $this->getOauthContexts();
        foreach ($oauthContexts as $tokenRequestContext) {
            $tokenProvider = new PhpLeagueAccessTokenProvider($tokenRequestContext);
            $mockResponses = [
                new Response(200, [], json_encode(['access_token' => $this->testJWT, 'expires_in' => 5])),
                new Response(200, [], json_encode(['access_token' => 'xyz', 'expires_in' => 5]))
            ];
            $tokenProvider->getOauthProvider()->setHttpClient($this->getMockHttpClient($mockResponses));
            $this->assertEquals($this->testJWT, $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com')->wait());
            // Second call happens before token expires. We should get the existing access token
            $this->assertEquals($this->testJWT, $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com')->wait());
        }
    }

    public function testGetAuthorizationTokenUsesCachedToken(): void
    {
        $oauthContexts = $this->getOauthContexts();
        /** @var TokenRequestContext $tokenRequestContext */
        foreach ($oauthContexts as $tokenRequestContext) {
            $cache = new InMemoryAccessTokenCache($tokenRequestContext, new AccessToken(['access_token' => $this->testJWT, 'expires' => time() + 5]));
            $tokenProvider = new PhpLeagueAccessTokenProvider($tokenRequestContext, [], [], null, $cache);
            $mockResponses = [
                new Response(400),
            ];
            $tokenProvider->getOauthProvider()->setHttpClient($this->getMockHttpClient($mockResponses));
            $this->assertEquals($this->testJWT, $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com')->wait());
        }
    }

    public function testNewAccessTokenIsUpdatedToTheCache(): void
    {
        $oauthContexts = $this->getOauthContexts();
        /** @var TokenRequestContext $tokenRequestContext */
        foreach ($oauthContexts as $tokenRequestContext) {
            $cache = new InMemoryAccessTokenCache();
            $tokenProvider = new PhpLeagueAccessTokenProvider($tokenRequestContext, [], [], null, $cache);
            $mockResponses = [
                new Response(200, [], json_encode(['access_token' => $this->testJWT, 'expires_in' => 5])),
            ];
            $tokenProvider->getOauthProvider()->setHttpClient($this->getMockHttpClient($mockResponses));
            $this->assertEquals($this->testJWT, $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com')->wait());
            $this->assertEquals($this->testJWT, $cache->getTokenWithContext($tokenRequestContext));
        }
    }

    public function testGetAuthorizationTokenWhenAllowedHostsNotDefined(): void
    {
        $oauthContexts = $this->getOauthContexts();
        foreach ($oauthContexts as $tokenRequestContext) {
            $tokenProvider = new PhpLeagueAccessTokenProvider($tokenRequestContext);
            $mockResponses = [
                new Response(200, [], json_encode(['access_token' => $this->testJWT, 'expires_in' => 5])),
                new Response(200, [], json_encode(['access_token' => 'xyz', 'expires_in' => 5]))
            ];
            $tokenProvider->getOauthProvider()->setHttpClient($this->getMockHttpClient($mockResponses));
            $this->assertEquals($this->testJWT, $tokenProvider->getAuthorizationTokenAsync('https://example.com')->wait());
            // Second call happens before token expires. We should get the existing access token
            $this->assertEquals($this->testJWT, $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com')->wait());
        }
    }

    public function testGetAuthorizationTokenRefreshesTokenIfExpired(): void
    {
        $oauthContexts = $this->getOauthContexts();
        foreach ($oauthContexts as $tokenRequestContext) {
            $tokenProvider = new PhpLeagueAccessTokenProvider($tokenRequestContext, ['https://graph.microsoft.com/.default']);
            $mockResponses = [
                new Response(200, [], json_encode(['access_token' => $this->testJWT, 'expires_in' => 0.1, 'refresh_token' => 'refresh'])),
                function (Request $request) {
                    parse_str($request->getBody()->getContents(), $requestBodyMap);
                    $this->assertArrayHasKey('refresh_token', $requestBodyMap);
                    $this->assertEquals('refresh', $requestBodyMap['refresh_token']);
                    return new Response(200, [], json_encode(['access_token' => 'xyz', 'expires_in' => 1]));
                },
            ];
            $tokenProvider->getOauthProvider()->setHttpClient($this->getMockHttpClient($mockResponses));
            $this->assertEquals($this->testJWT, $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com')->wait());
            sleep(1);
            // Second call happens when token has already expired
            $this->assertEquals('xyz', $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com')->wait());
        }
    }

    public function testGetAuthorizationTokenFetchesNewTokenIfNoRefreshTokenExists(): void
    {
        $oauthContexts = $this->getOauthContexts();
        foreach ($oauthContexts as $tokenRequestContext) {
            $tokenProvider = new PhpLeagueAccessTokenProvider($tokenRequestContext, ['https://graph.microsoft.com/.default']);
            $mockResponses = [
                new Response(200, [], json_encode(['access_token' => $this->testJWT, 'expires_in' => 0.1])),
                function (Request $request) use ($tokenRequestContext) {
                    parse_str($request->getBody()->getContents(), $requestBodyMap);
                    $expectedBody = array_merge($tokenRequestContext->getParams(), [
                        'scope' => 'https://graph.microsoft.com/.default'
                    ]);
                    $this->assertEquals($expectedBody, $requestBodyMap);
                    return new Response(200, [], json_encode(['access_token' => 'xyz', 'expires_in' => 1]));
                },
            ];
            $tokenProvider->getOauthProvider()->setHttpClient($this->getMockHttpClient($mockResponses));
            $this->assertEquals($this->testJWT, $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com')->wait());
            sleep(1);
            // Second call happens when token has already expired
            $this->assertEquals('xyz', $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com')->wait());
        }
    }

    public function testGetAuthTokenWithInsecureUrlDoesntReturnAccessToken(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->defaultTokenProvider->getAuthorizationTokenAsync('http://example.com')->wait();
    }

    public function testGetAccessTokenWithLocalhostStringWithHttpReturnsAccessToken(): void
    {
        $tokenRequestContext  = new ClientCredentialContext('tenant', 'client', 'secret');
        foreach(array_keys(PhpLeagueAccessTokenProvider::LOCALHOST_STRINGS) as $host) {
            $mockResponses = [
                function (Request $request) use ($tokenRequestContext, $host) {
                    parse_str($request->getBody()->getContents(), $requestBodyMap);
                    $expectedBody = array_merge($tokenRequestContext->getParams(), [
                        'scope' => "http://$host/.default"
                    ]);
                    $this->assertEquals($expectedBody, $requestBodyMap);
                    return new Response(200, [], json_encode(['access_token' => 'xyz', 'expires_in' => 1]));
                },
            ];
            $tokenProvider = new PhpLeagueAccessTokenProvider($tokenRequestContext, ["http://$host/.default"]);
            $tokenProvider->getOauthProvider()->setHttpClient($this->getMockHttpClient($mockResponses));
            $token         = $tokenProvider->getAuthorizationTokenAsync("http://$host")->wait();
            assertNotEmpty($token);
        }
    }

    public function testCAEMergingClaims(): void
    {
        $additionalClaims = ['claims' => '{"access_token":{"acrs":{"essential":true,"value":"c25"}}}'];
        $oauthContext = new ClientCredentialContext('tenant', 'client', 'secret', $additionalClaims);
        $oauthContext->setCAEEnabled(true);
        $tokenProvider = new PhpLeagueAccessTokenProvider($oauthContext);
        $mockResponses = [
            function (Request $request) {
                parse_str($request->getBody()->getContents(), $requestBodyMap);
                $this->assertArrayHasKey('claims', $requestBodyMap);
                $expected = '{"access_token":{"acrs":{"essential":true,"value":"c25"},"xms_cc":{"values":["cp1"]}}}';
                $this->assertEquals($expected, $requestBodyMap['claims']);
                return new Response(200, [], json_encode(['access_token' => 'xyz', 'expires_in' => 1]));
            }
        ];
        $tokenProvider->getOauthProvider()->setHttpClient($this->getMockHttpClient($mockResponses));
        $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com/users')->wait();
    }

    public function testCAEEnabledAddsCp1ClaimToTokenRequest(): void
    {
        $oauthContexts = $this->getOauthContexts();
        foreach ($oauthContexts as $context) {
            $context->setCAEEnabled(true);
            $tokenProvider = new PhpLeagueAccessTokenProvider($context);
            $mockResponses = [
                function (Request $request) {
                    parse_str($request->getBody()->getContents(), $requestBodyMap);
                    $this->assertArrayHasKey('claims', $requestBodyMap);
                    $this->assertEquals(PhpLeagueAccessTokenProvider::CP1_CLAIM, $requestBodyMap['claims']);
                    return new Response(200, [], json_encode(['access_token' => 'xyz', 'expires_in' => 1]));
                }
            ];
            $tokenProvider->getOauthProvider()->setHttpClient($this->getMockHttpClient($mockResponses));
            $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com/users')->wait();
        }
    }

    public function testCAETokenRefreshContainsClaims(): void
    {
        $oauthContexts = $this->getOauthContexts();
        foreach ($oauthContexts as $context) {
            $context->setCAEEnabled(true);
            $tokenProvider = new PhpLeagueAccessTokenProvider($context);
            $mockResponses = [
                function (Request $request) {
                    parse_str($request->getBody()->getContents(), $requestBodyMap);
                    $this->assertArrayHasKey('claims', $requestBodyMap);
                    $this->assertEquals(PhpLeagueAccessTokenProvider::CP1_CLAIM, $requestBodyMap['claims']);
                    return new Response(200, [], json_encode(['access_token' => $this->testJWT, 'refresh_token' => 'refresh', 'expires_in' => 5]));
                },
                function (Request $refreshTokenRequest) {
                    parse_str($refreshTokenRequest->getBody()->getContents(), $requestBodyMap);
                    $this->assertArrayHasKey('refresh_token', $requestBodyMap);
                    $this->assertEquals('refresh', $requestBodyMap['refresh_token']);
                    $this->assertArrayHasKey('claims', $requestBodyMap);
                    $this->assertEquals(
                        'eyJhY2Nlc3NfdG9rZW4iOnsiYWNycyI6eyJlc3NlbnRpYWwiOnRydWUsInZhbHVlIjoiY3AxIn19fQ==',
                        base64_encode($requestBodyMap['claims'])
                    );
                    return new Response(200, [], json_encode(['access_token' => 'abc', 'refresh_token' => 'refresh', 'expires_in' => 5]));
                }
            ];
            $tokenProvider->getOauthProvider()->setHttpClient($this->getMockHttpClient($mockResponses));
            $this->assertEquals($this->testJWT, $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com/users')->wait());
            // while cached token exists, make a claims request
            $this->assertEquals('abc', $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com/users', [
                'claims' => 'eyJhY2Nlc3NfdG9rZW4iOnsiYWNycyI6eyJlc3NlbnRpYWwiOnRydWUsInZhbHVlIjoiY3AxIn19fQ=='
            ])->wait());
        }
    }

    public function testFailedCAETokenRefreshWithoutCallbackThrowsException(): void
    {
        $oauthContexts = $this->getOauthContexts();
        foreach ($oauthContexts as $context) {
            $context->setCAEEnabled(true);
            $tokenProvider = new PhpLeagueAccessTokenProvider($context);
            $mockResponses = [
                new Response(200, [], json_encode(['access_token' => $this->testJWT, 'refresh_token' => 'refresh', 'expires_in' => 5])),
                function (Request $refreshTokenRequest) {
                    throw new Exception("Refresh token failed");
                }
            ];
            $tokenProvider->getOauthProvider()->setHttpClient($this->getMockHttpClient($mockResponses));
            $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com/users')->wait();
            // while cached token exists, make a claims request
            try {
                $claims = 'eyJhY2Nlc3NfdG9rZW4iOnsiYWNycyI6eyJlc3NlbnRpYWwiOnRydWUsInZhbHVlIjoiY3AxIn19fQ==';
                $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com/users', [
                    'claims' => $claims
                ])->wait();
            } catch (\Exception $ex) {
                $this->assertInstanceOf(ContinuousAccessEvaluationException::class, $ex);
                $this->assertEquals(base64_decode($claims), $ex->getClaims());
            }
        }
    }

    public function testFailedCAETokenRefreshCallsRedirectCallback(): void
    {
        $oauthContexts = $this->getOauthContexts();
        foreach ($oauthContexts as $context) {
            $context->setCAEEnabled(true);
            $callbackExecuted = false;
            $context->setCAERedirectCallback(function () use (&$callbackExecuted, $context) {
                $callbackExecuted = true;
                return new FulfilledPromise($context);
            });
            $tokenProvider = new PhpLeagueAccessTokenProvider($context);
            $mockResponses = [
                new Response(200, [], json_encode(['access_token' => $this->testJWT, 'refresh_token' => 'refresh', 'expires_in' => 5])),
                function (Request $refreshTokenRequest) {
                    throw new Exception("Refresh token failed");
                }
            ];
            $tokenProvider->getOauthProvider()->setHttpClient($this->getMockHttpClient($mockResponses));
            $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com/users')->wait();
            // while cached token exists, make a claims request
            try {
                $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com/users', [
                    'claims' => 'eyJhY2Nlc3NfdG9rZW4iOnsiYWNycyI6eyJlc3NlbnRpYWwiOnRydWUsInZhbHVlIjoiY3AxIn19fQ=='
                ])->wait();
            } catch (\Exception $ex) {
                $this->assertTrue($callbackExecuted);
            }
        }
    }

    public function testFailedCAERefreshUsingCallbackWithWrongResponseTypeThrowsException(): void
    {
        $oauthContexts = $this->getOauthContexts();
        foreach ($oauthContexts as $context) {
            $context->setCAEEnabled(true);
            $callbackExecuted = false;
            $context->setCAERedirectCallback(function () use (&$callbackExecuted) {
                $callbackExecuted = true;
                return new FulfilledPromise(null);
            });
            $tokenProvider = new PhpLeagueAccessTokenProvider($context);
            $mockResponses = [
                new Response(200, [], json_encode(['access_token' => $this->testJWT, 'refresh_token' => 'refresh', 'expires_in' => 5])),
                function (Request $refreshTokenRequest) {
                    throw new Exception("Refresh token failed");
                }
            ];
            $tokenProvider->getOauthProvider()->setHttpClient($this->getMockHttpClient($mockResponses));
            $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com/users')->wait();
            // while cached token exists, make a claims request
            try {
                $claims = 'eyJhY2Nlc3NfdG9rZW4iOnsiYWNycyI6eyJlc3NlbnRpYWwiOnRydWUsInZhbHVlIjoiY3AxIn19fQ==';
                $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com/users', [
                    'claims' => $claims
                ])->wait();
            } catch (\Exception $ex) {
                $this->assertInstanceOf(ContinuousAccessEvaluationException::class, $ex);
                $this->assertEquals(base64_decode($claims), $ex->getClaims());
            }
        }
    }

    public function testTryCAERefreshWithoutRefreshTokenFails(): void
    {
        $oauthContexts = $this->getOauthContexts();
        foreach ($oauthContexts as $context) {
            $context->setCAEEnabled(true);
            $tokenProvider = new PhpLeagueAccessTokenProvider($context);
            $mockResponses = [
                function (Request $request) {
                    parse_str($request->getBody()->getContents(), $requestBodyMap);
                    $this->assertArrayHasKey('claims', $requestBodyMap);
                    $this->assertEquals(PhpLeagueAccessTokenProvider::CP1_CLAIM, $requestBodyMap['claims']);
                    return new Response(200, [], json_encode(['access_token' => $this->testJWT, 'expires_in' => 5]));
                },
                function (Request $refreshTokenRequest) {
                    parse_str($refreshTokenRequest->getBody()->getContents(), $requestBodyMap);
                    $this->assertArrayHasKey('refresh_token', $requestBodyMap);
                    $this->assertEquals('refresh', $requestBodyMap['refresh_token']);
                    $this->assertArrayHasKey('claims', $requestBodyMap);
                    $this->assertEquals(
                        'eyJhY2Nlc3NfdG9rZW4iOnsiYWNycyI6eyJlc3NlbnRpYWwiOnRydWUsInZhbHVlIjoiY3AxIn19fQ==',
                        base64_encode($requestBodyMap['claims'])
                    );
                    return new Response(200, [], json_encode(['access_token' => 'abc', 'refresh_token' => 'refresh', 'expires_in' => 5]));
                }
            ];
            $tokenProvider->getOauthProvider()->setHttpClient($this->getMockHttpClient($mockResponses));
            $this->assertEquals($this->testJWT, $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com/users')->wait());
            // while cached token exists, make a claims request
            $this->expectException(ContinuousAccessEvaluationException::class);
            $this->assertEquals('abc', $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com/users', [
                'claims' => 'eyJhY2Nlc3NfdG9rZW4iOnsiYWNycyI6eyJlc3NlbnRpYWwiOnRydWUsInZhbHVlIjoiY3AxIn19fQ=='
            ])->wait());
        }
    }

    public function testAuthenticationContinuesAfterCAETokenRefreshSuccess(): void
    {
        $oauthContexts = $this->getOauthContexts();
        foreach ($oauthContexts as $context) {
            $context->setCAEEnabled(true);
            $callbackExecuted = false;
            $context->setCAERedirectCallback(function () use (&$callbackExecuted, $context) {
                $callbackExecuted = true;
                return new FulfilledPromise($context);
            });
            $tokenProvider = new PhpLeagueAccessTokenProvider($context);
            $mockResponses = [
                new Response(200, [], json_encode(['access_token' => $this->testJWT, 'refresh_token' => 'refresh', 'expires_in' => 5])),
                function (Request $refreshTokenRequest) {
                    throw new Exception("Refresh token failed");
                },
                new Response(200, [], json_encode(['access_token' => 'xyz', 'refresh_token' => 'refresh', 'expires_in' => 5])),
            ];
            $tokenProvider->getOauthProvider()->setHttpClient($this->getMockHttpClient($mockResponses));
            $this->assertEquals($this->testJWT, $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com/users')->wait());
            // while cached token exists, make a claims request
            $claims = 'eyJhY2Nlc3NfdG9rZW4iOnsiYWNycyI6eyJlc3NlbnRpYWwiOnRydWUsInZhbHVlIjoiY3AxIn19fQ==';
            $this->assertEquals('xyz', $tokenProvider->getAuthorizationTokenAsync('https://graph.microsoft.com/users', [
                'claims' => $claims
            ])->wait());
            $this->assertTrue($callbackExecuted);
        }
    }

    private function getMockHttpClient(array $mockResponses): Client
    {
        return new Client(['handler' => new MockHandler($mockResponses)]);
    }

    /**
     * @param string $tenantId
     * @return array<TokenRequestContext>
     */
    private function getOauthContexts(string $tenantId = 'tenantId'): array
    {
        $clientId = 'clientId';
        $clientSecret = 'clientSecret';
        $certificatePath = __DIR__. DIRECTORY_SEPARATOR .'sample_cert.pem';
        $privateKeyPath = __DIR__ . DIRECTORY_SEPARATOR . 'sample_private_key.pem';
        $privateKeyPassphrase = 'pass';
        $authCode = '123';
        $redirectUri = 'http://localhost:1234';
        $assertion = 'jwtToken';

        return [
            new ClientCredentialContext($tenantId, $clientId, $clientSecret),
            new ClientCredentialCertificateContext($tenantId, $clientId, $certificatePath, $privateKeyPath, $privateKeyPassphrase),
            new AuthorizationCodeContext($tenantId, $clientId, $clientSecret, $authCode, $redirectUri),
            new AuthorizationCodeCertificateContext($tenantId, $clientId, $authCode, $redirectUri, $certificatePath, $privateKeyPath, $privateKeyPassphrase),
            new OnBehalfOfContext($tenantId, $clientId, $tenantId, $assertion),
            new OnBehalfOfCertificateContext($tenantId, $clientId, $assertion, $certificatePath, $privateKeyPath, $privateKeyPassphrase),
        ];
    }
}
