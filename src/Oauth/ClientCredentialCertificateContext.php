<?php
/**
 * Copyright (c) Microsoft Corporation.  All Rights Reserved.
 * Licensed under the MIT License.  See License in the project root
 * for license information.
 */


namespace Microsoft\Kiota\Authentication\Oauth;

/**
 * Class ClientCredentialCertificateContext
 *
 * client_credentials flow using certificate
 *
 * @package Microsoft\Kiota\Authentication\Oauth
 * @copyright 2022 Microsoft Corporation
 * @license https://opensource.org/licenses/MIT MIT License
 * @link https://developer.microsoft.com/graph
 */
class ClientCredentialCertificateContext extends BaseCertificateContext implements TokenRequestContext
{
    use ApplicationPermissionTrait;

    /** @var array<string,string>  */
    private array $additionalParams;

    /**
     * @param string $tenantId
     * @param string $clientId
     * @param string $certificatePath
     * @param string $privateKeyPath
     * @param string $privateKeyPassphrase
     * @param array<string, string> $additionalParams
     */
    public function __construct(string $tenantId,
                                string $clientId,
                                string $certificatePath,
                                string $privateKeyPath,
                                string $privateKeyPassphrase = '',
                                array $additionalParams = [])
    {
        $this->additionalParams = $additionalParams;
        parent::__construct($tenantId, $clientId, $certificatePath, $privateKeyPath, $privateKeyPassphrase);
    }

    /**
     * Request body parameters for client_credentials flow
     *
     * @return array<string, string>
     */
    public function getParams(): array
    {
        return array_merge($this->additionalParams, parent::getParams(), [
            'grant_type' => $this->getGrantType(),
        ]);
    }

    /**
     * Returns the Grant type
     * @return string
     */
    public function getGrantType(): string
    {
        return 'client_credentials';
    }
}
