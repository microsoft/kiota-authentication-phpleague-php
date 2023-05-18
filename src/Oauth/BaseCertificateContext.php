<?php
/**
 * Copyright (c) Microsoft Corporation.  All Rights Reserved.
 * Licensed under the MIT License.  See License in the project root
 * for license information.
 */


namespace Microsoft\Kiota\Authentication\Oauth;


use Firebase\JWT\JWT;
use Ramsey\Uuid\Uuid;
use InvalidArgumentException;

/**
 * Class BaseCertificateContext
 * @package Microsoft\Kiota\Authentication\Oauth
 * @copyright 2023 Microsoft Corporation
 * @license https://opensource.org/licenses/MIT MIT License
 * @link https://learn.microsoft.com/en-us/openapi/kiota/
 */
class BaseCertificateContext
{
    /**
     * @var string Tenant Id
     */
    private string $tenantId;
    /**
     * @var string Client Id
     */
    private string $clientId;
    /**
     * @var string
     */
    private string $certificateFingerprint;
    /**
     * @var string JWT token signed with the private key
     */
    private string $clientAssertion;

    /**
     * @param string $tenantId
     * @param string $clientId
     * @param string $certificatePath PEM file containing the certificate
     * @param string $privateKeyPath PEM file containing the certificate's private key
     * @param string $privateKeyPassphrase password protecting the private key
     */
    public function __construct(string $tenantId,
                                string $clientId,
                                string $certificatePath,
                                string $privateKeyPath,
                                string $privateKeyPassphrase = '')
    {
        if (!$tenantId || !$clientId || !$certificatePath || !$privateKeyPath) {
            throw new InvalidArgumentException(
                '$tenantId, $clientId, $certificatePath or $privateKeyPath cannot be empty.'
            );
        }
        $this->tenantId = $tenantId;
        $this->clientId = $clientId;
        $certificateContents = file_get_contents($certificatePath);
        if (!$certificateContents) {
            throw new InvalidArgumentException("Unable to read certificate file content at $certificatePath.");
        }
        $certificate = openssl_x509_read($certificateContents);
        if (!$certificate) {
            throw new InvalidArgumentException("Could not read X.509 certificate at $certificatePath.");
        }
        $fingerPrint = openssl_x509_fingerprint($certificate);
        if (!$fingerPrint) {
            throw new InvalidArgumentException(
                "Failed to calculate the fingerprint of the X.509 certificate at $certificatePath."
            );
        }
        $this->certificateFingerprint = $fingerPrint;
        $privateKeyContents = file_get_contents($privateKeyPath);
        if (!$privateKeyContents) {
            throw new InvalidArgumentException("Unable to read private key file contents at $privateKeyPath.");
        }
        $privateKey = openssl_pkey_get_private($privateKeyContents, $privateKeyPassphrase);
        if (!$privateKey) {
            throw new InvalidArgumentException(
                "Failed to read the private key at $privateKeyPath using passphrase $privateKeyPassphrase."
            );
        }
        if (!openssl_x509_check_private_key($certificate, $privateKey)) {
            throw new InvalidArgumentException(
                "Private Key at $privateKeyPath does not correspond to the certificate at $certificatePath."
            );
        }
        $this->clientAssertion = $this->getClientAssertion($privateKey);
    }

    /**
     * @return array<string, string>
     */
    public function getParams(): array
    {
        return [
            'client_id' => $this->clientId,
            'client_assertion' => $this->clientAssertion,
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        ];
    }

    /**
     * @param string $refreshToken
     * @return array<string, string>
     */
    public function getRefreshTokenParams(string $refreshToken): array
    {
        return [
            'client_id' => $this->clientId,
            'client_assertion' => $this->clientAssertion,
            'client_assertion_type' => 'urn:ietf:params:Oauth:client-assertion-type:jwt-bearer',
            'refresh_token' => $refreshToken,
            'grant_type' => 'refresh_token'
        ];
    }

    /**
     * @return string
     */
    public function getTenantId(): string
    {
        return $this->tenantId;
    }

    /**
     * @return string
     */
    public function getClientId(): string
    {
        return $this->clientId;
    }

    /**
     * Generates JSON Web Token ref (https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials)
     * @param $privateKey
     * @return string
     * @phpstan-ignore-next-line
     */
    private function getClientAssertion($privateKey): string
    {
        $currentTimeSecs = time();
        $claims = [
            'aud' => "https://login.microsoftonline.com/{$this->tenantId}/v2.0",
            'iss' => $this->clientId,
            'jti' => Uuid::uuid4(), // random UUID based on RFC 4122
            'sub' => $this->clientId,
            'iat' => $currentTimeSecs,
            'nbf' => $currentTimeSecs,
            'exp' => $currentTimeSecs + (5 * 60), // add 5 minutes to iat
        ];
        $hexBinInput = hex2bin($this->certificateFingerprint);
        return JWT::encode($claims, $privateKey, 'RS256', null, [
            'x5t' => JWT::urlsafeB64Encode($hexBinInput ?: '')
        ]);
    }
}
