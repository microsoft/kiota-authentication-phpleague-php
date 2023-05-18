<?php
/**
 * Copyright (c) Microsoft Corporation.  All Rights Reserved.
 * Licensed under the MIT License.  See License in the project root
 * for license information.
 */


namespace Microsoft\Kiota\Authentication\Oauth;


use League\OAuth2\Client\Token\AccessToken;


trait DelegatedPermissionTrait
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
        if ($accessToken && $accessToken->getToken()) {
            $tokenParts = explode('.', $accessToken->getToken());
            if (count($tokenParts) == 3) {
                $payload = json_decode(base64_decode($tokenParts[1]), true);
                if (is_array($payload) && array_key_exists('sub', $payload)) {
                    $subject = $payload['sub'];
                    $this->cacheKey = ($subject) ? "{$this->getTenantId()}-{$this->getClientId()}-{$subject}" : null;
                }
            }
        }
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
