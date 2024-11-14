<?php
/**
 * Copyright (c) Microsoft Corporation.  All Rights Reserved.
 * Licensed under the MIT License.  See License in the project root
 * for license information.
 */


namespace Microsoft\Kiota\Authentication\Oauth;

use League\OAuth2\Client\Token\AccessToken;
use Http\Promise\Promise;

/**
 * Interface TokenRequestContext
 * @package Microsoft\Kiota\Authentication
 * @copyright 2022 Microsoft Corporation
 * @license https://opensource.org/licenses/MIT MIT License
 * @link https://developer.microsoft.com/graph
 */
interface TokenRequestContext
{
    /**
     * Return dictionary with OAuth 2.0 request parameters to be passed to PHP League's OAuth provider
     *
     * @return array<string, string>
     */
    public function getParams(): array;

    /**
     * Returns subset of parameters to be used for refresh_token requests
     *
     * @param string $refreshToken refresh token in currently cached token
     * @return array<string, string>
     */
    public function getRefreshTokenParams(string $refreshToken): array;

    /**
     * @return string Grant type
     */
    public function getGrantType(): string;

    /**
     * Return the tenantId
     * @return string
     */
    public function getTenantId(): string;

    /**
     * Set the identity of the user/application. This is used as the unique cache key
     * For delegated permissions the key is {tenantId}-{clientId}-{accessTokenHash}
     * For application permissions, they key is {tenantId}-{clientId}
     * @param AccessToken|null $accessToken
     * @return void
     */
    public function setCacheKey(?AccessToken $accessToken = null): void;

    /**
     * Return the identity of the user/application. This is used as the unique cache key
     * For delegated permissions the key is {tenantId}-{clientId}-{accessTokenHash}
     * For application permissions, they key is {tenantId}-{clientId}
     *
     * @return string|null
     */
    public function getCacheKey(): ?string;

    /**
     * Whether the client should be enabled for Continuous Access Evaluation
     * https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-continuous-access-evaluation
     * Currently only works with Microsoft Identity
     * @return bool
     */
    public function isCAEEnabled(): bool;

    /**
     * Returns a callback that can be called to redirect the logged-in user to the Microsoft Identity login page
     * when this lib is unable to refresh the token using CAE claims.
     * If this callback returns a Promise that resolves to a new token request context with the new authentication
     * code/assertion then a new token is requested.
     *
     * @return null|callable(string $claims): Promise<TokenRequestContext>
     */
    public function getCAERedirectCallback(): ?callable;
}
