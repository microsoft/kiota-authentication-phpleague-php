<?php

namespace Microsoft\Kiota\Authentication;

use Microsoft\Kiota\Abstractions\RequestOption;

class ObservabilityOptions implements RequestOption
{
    public static function getTracerInstrumentationName(): string
    {
        return "microsoft.kiota.authentication:kiota-authentication-phpleague";
    }
}
