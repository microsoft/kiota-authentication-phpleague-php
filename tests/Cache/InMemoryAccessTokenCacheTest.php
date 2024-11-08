<?php

namespace Microsoft\Kiota\Authentication\Test\Cache;

use League\OAuth2\Client\Token\AccessToken;
use Microsoft\Kiota\Authentication\Cache\InMemoryAccessTokenCache;
use Microsoft\Kiota\Authentication\Oauth\AuthorizationCodeContext;
use Microsoft\Kiota\Authentication\Oauth\ClientCredentialContext;
use Microsoft\Kiota\Authentication\Oauth\TokenRequestContext;
use PHPUnit\Framework\TestCase;

class InMemoryAccessTokenCacheTest extends TestCase
{
    private ClientCredentialContext $testTokenRequestContext;
    private string $testTokenRequestContextCacheKey = "tenantId-clientId";

    public function setUp(): void {
        $this->testTokenRequestContext = new ClientCredentialContext("tenantId", "clientId", "clientSecret");
    }

    public function testConstructorWorksWithEmptyArguments() {
        $cache = new InMemoryAccessTokenCache();
        $this->assertInstanceOf(InMemoryAccessTokenCache::class, $cache);
    }

    public function testConstructorInitialisesCache() {
        $cache = new InMemoryAccessTokenCache($this->testTokenRequestContext, $this->createMock(AccessToken::class));
        $this->assertInstanceOf(AccessToken::class, $cache->getTokenWithContext($this->testTokenRequestContext));
    }

    public function tesWithTokenInitialisesCache() {
        $cache = new InMemoryAccessTokenCache();
        $cache->withToken($this->testTokenRequestContext, $this->createMock(AccessToken::class));
        $this->assertInstanceOf(AccessToken::class, $cache->getTokenWithContext($this->testTokenRequestContext));
    }

    public function testWithTokenThrowsExceptionIfCacheKeyCannotBeInitialised() {
        $tokenRequestContext = $this->createMock(TokenRequestContext::class);
        $tokenRequestContext->method('getCacheKey')->willReturn(null);
        $cache = new InMemoryAccessTokenCache();
        $this->expectException(\InvalidArgumentException::class);
        $cache->withToken($tokenRequestContext, $this->createMock(AccessToken::class));
    }

    public function testWithTokenThrowsExceptionIfTokenRequestContextAlreadyExists() {
        $cache = new InMemoryAccessTokenCache($this->testTokenRequestContext, $this->createMock(AccessToken::class));
        $this->expectException(\InvalidArgumentException::class);
        $cache->withToken($this->testTokenRequestContext, $this->createMock(AccessToken::class));
    }

    public function testWithTokenAddsMultipleTokensToCache() {
        $secondContext = $this->createMock(TokenRequestContext::class);
        $secondContext->method('getCacheKey')->willReturn('second-key');

        $cache = (new InMemoryAccessTokenCache())
            ->withToken($this->testTokenRequestContext, $this->createMock(AccessToken::class))
            ->withToken($secondContext, $this->createMock(AccessToken::class));

        $this->assertInstanceOf(AccessToken::class, $cache->getTokenWithContext($this->testTokenRequestContext));
        $this->assertInstanceOf(AccessToken::class, $cache->getTokenWithContext($secondContext));
    }

    public function testCacheKeyIsSetForNonJWTToken() {
        $accessToken = $this->createMock(AccessToken::class);
        $accessToken->method('getToken')->willReturn('token');

        $cache = new InMemoryAccessTokenCache();
        $delegatedTokenRequestContext = new AuthorizationCodeContext("tenantId", "clientId", "clientSecret", "redirectUri", "code");
        $cache->withToken($delegatedTokenRequestContext, $accessToken);

        $this->assertNotEmpty($delegatedTokenRequestContext->getCacheKey());
    }
}
