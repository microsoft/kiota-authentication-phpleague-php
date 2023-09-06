<?php

namespace Microsoft\Kiota\Authentication;

class ObservabilityOptions
{
    public static function getTracerInstrumentationName(): string
    {
        return "microsoft.kiota.authentication:kiota-authentication-phpleague";
    }
}
