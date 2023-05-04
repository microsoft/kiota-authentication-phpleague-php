<?php
/**
 * Copyright (c) Microsoft Corporation.  All Rights Reserved.
 * Licensed under the MIT License.  See License in the project root
 * for license information.
 */


namespace Microsoft\Kiota\Authentication\Oauth;

use InvalidArgumentException;

/**
 * Class OnBehalfOfCertificateContext
 *
 * on_behalf_of flow using certificate
 *
 * @package Microsoft\Kiota\Authentication\Oauth
 * @copyright 2022 Microsoft Corporation
 * @license https://opensource.org/licenses/MIT MIT License
 * @link https://developer.microsoft.com/graph
 */
class OnBehalfOfCertificateContext extends BaseCertificateContext implements TokenRequestContext
{
    use DelegatedPermissionTrait;

    /**
     * @var string
     */
    private string $assertion;
    /**
     * @var array<string,string>
     */
    private array $additionalParams;

    /**
     * @param string $tenantId
     * @param string $clientId
     * @param string $assertion
     * @param string $certificatePath
     * @param string $privateKeyPath
     * @param string $privateKeyPassphrase
     * @param array<string,string> $additionalParams
     */
    public function __construct(string $tenantId, string $clientId, string $assertion, string $certificatePath, string $privateKeyPath, string $privateKeyPassphrase = '', array $additionalParams = [])
    {
        if (!$assertion) {
            throw new InvalidArgumentException("Assertion cannot be empty");
        }
        $this->assertion = $assertion;
        $this->additionalParams = $additionalParams;
        parent::__construct($tenantId, $clientId, $certificatePath, $privateKeyPath, $privateKeyPassphrase);
    }

    /**
     * @inheritDoc
     */
    public function getParams(): array
    {
        return array_merge($this->additionalParams, parent::getParams(), [
            'assertion' => $this->assertion,
            'grant_type' => $this->getGrantType(),
            'requested_token_use' => 'on_behalf_of'
        ]);
    }

    /**
     * @inheritDoc
     */
    public function getGrantType(): string
    {
        return 'urn:ietf:params:Oauth:grant-type:jwt-bearer';
    }
}
