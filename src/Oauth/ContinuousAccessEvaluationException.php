<?php
/**
 * Copyright (c) Microsoft Corporation.  All Rights Reserved.
 * Licensed under the MIT License.  See License in the project root
 * for license information.
 */


namespace Microsoft\Kiota\Authentication\Oauth;

use Throwable;

/**
 * Class ContinuousAccessEvaluationException
 *
 * Exception thrown when continuous access evaluation fails i.e.
 * Built in refresh token request with the claims fails
 * OR no redirect callback is provided
 * OR redirect callback fails
 *
 * @package Microsoft\Kiota\Authentication\Oauth
 * @copyright 2023 Microsoft Corporation
 * @license https://opensource.org/licenses/MIT MIT License
 * @link https://developer.microsoft.com/graph
 */
class ContinuousAccessEvaluationException extends \Exception
{
    /**
     * @var string
     */
    private string $claims = '';

    /**
     * @param string $message
     * @param string $claims
     * @param int $code
     * @param Throwable|null $previous
     */
    public function __construct(string $message = "", string $claims = '', int $code = 0, Throwable $previous = null)
    {
        $this->claims = $claims;
        parent::__construct($message, $code, $previous);
    }

    /**
     * @return string
     */
    public function getClaims(): string
    {
        return $this->claims;
    }
}
