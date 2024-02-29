<?php
/**
 * Copyright (c) Microsoft Corporation.  All Rights Reserved.
 * Licensed under the MIT License.  See License in the project root
 * for license information.
 */


namespace Microsoft\Kiota\Authentication\Oauth;


use League\OAuth2\Client\Token\AccessToken;
use \InvalidArgumentException;

trait ApplicationPermissionTrait
{
    use CAEConfigurationTrait;

    /**
     * @var string|null
     */
    private ?string $cacheKey = null;

    /**
     * @return string
     */
    abstract public function getClientId(): string;

    /**
     * @return string
     */
    abstract public function getTenantId(): string;

    /**
     * Set the identity of the user/application. This is used as the unique cache key
     * For delegated permissions the key is {tenantId}-{clientId}-{userId}
     * For application permissions, they key is {tenantId}-{clientId}
     * @param AccessToken|null $accessToken
     * @return void
     */
    public function setCacheKey(?AccessToken $accessToken = null): void
    {
        $this->cacheKey = "{$this->getTenantId()}-{$this->getClientId()}";
    }

    /**
     * Set the cache identifier for a user/application.
     *
     * @param string $identifier
     * @return void
     */
    public function setCustomCacheKey(string $identifier): void
    {
        if (!$identifier) {
            throw new InvalidArgumentException("Cache key cannot be set to an empty string");
        }
        $this->cacheKey = $identifier;
    }

    /**
     * Return the identity of the user/application. This is used as the unique cache key
     * For delegated permissions the key is {tenantId}-{clientId}-{userId}
     * For application permissions, they key is {tenantId}-{clientId}
     * @return string|null
     */
    public function getCacheKey(): ?string
    {
        return $this->cacheKey;
    }
}
