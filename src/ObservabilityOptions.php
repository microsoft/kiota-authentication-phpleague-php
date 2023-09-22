<?php

namespace Microsoft\Kiota\Authentication;

use OpenTelemetry\API\Globals;
use OpenTelemetry\API\Trace\TracerInterface;

class ObservabilityOptions
{
    private static ?TracerInterface $tracer = null;
    public static function getTracerInstrumentationName(): string
    {
        return "microsoft.kiota.authentication:kiota-authentication-phpleague";
    }

    /**
     * @return TracerInterface
     */
    public static function getTracer(): TracerInterface
    {
        if (self::$tracer === null) {
            self::$tracer = Globals::tracerProvider()->getTracer(
                self::getTracerInstrumentationName(),
                Constants::VERSION);
        }
        return self::$tracer;
    }

    /**
     * @param TracerInterface $tracer
     * @return void
     */
    public static function setTracer(TracerInterface $tracer): void
    {
        self::$tracer = $tracer;
    }
}
