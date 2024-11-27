# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

## [1.3.1] - 2024-11-27

### Changed

- Makes cache keys reproducible in Delegated permission contexts
- Makes auth code optional to support cases when AuthCodeContext is used with an already cached token

## [1.3.0] - 2024-11-14

### Changed
- Fix caching access tokens for delegated permissions. [#98](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/98)

## [1.2.0]

### Added
- Add client options to the `ProviderFactory::create` by @SilasKenneth in https://github.com/microsoft/kiota-authentication-phpleague-php/pull/88

## [1.1.0]

### Added
- Enables initialising the `InMemoryAccessTokenCache` with tokens for re-use by the auth provider
- Exposes the access token cache used in the `PhpLeagueAccessTokenProvider` using `getAccessTokenCache()`

## [1.0.2]

### Changed
- Removed direct dependency on `php-http/promise`. `kiota-abstractions` should determine which promise lib version is installed

## [1.0.1]

### Changed
- Exclude non-prod files from the shipped archive

## [1.0.0] - 2023-11-01

### Changed
- Bump abstractions package to 1.0.0
- Use stable OpenTelemetry library
- Mark package as stable

## [0.9.0] - 2023-10-30

### Added
- Adds CHANGELOG. [#54](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/54)
- Adds Generics to Promise return types. [#59](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/59)

### Changed
- Allow `http` scheme for localhost urls. [#56](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/56)
- Disable PHP-HTTP discovery plugin. [#58](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/58)

## [0.8.3] - 2023-10-05

### Added
- Adds missing fabric bot configuration. [#46](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/46)
- Add support for tracing. [#48](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/48)

## [0.8.2] - 2023-06-30

### Changed
- Disable pipeline runs for forks. [#40](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/40)
- Update microsoft/kiota-abstractions requirement from `^0.7.0 to ^0.7.0 || ^0.8.0`. [#42](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/42)

## [0.8.1] - 2023-06-30

### Changed
- Allow changing default token service URL and user info URL. [#37](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/37)

## [0.8.0] - 2023-05-18

### Changed
- Bump abstractions. [#32](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/32)

## [0.7.0] - 2023-05-18

### Added
- Abstract token caching. [#29](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/29)
- CAE support. [#28](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/29)

### Changed
- Fix static analysis issues. [#21](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/21)

## [0.6.0] - 2023-03-07

### Added
- adds dependabot auto-merge and conflicts workflows. [#12](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/12)
- Test coverage reporting. [#13](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/13)
- Support custom http client. [#16](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/16)

### Changed
- Remove default graph scopes and valid hosts. [#10](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/10)
- Tell SonarCloud the Source and Tests folder. [#14](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/14)
- Bump abstractions. [#15](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/15)
- Change workflow to use strategy matrix for PHP versions . [#11](https://github.com/microsoft/kiota-authentication-phpleague-php/pull/11)


*For previous versions, please see the [Release Notes](https://github.com/microsoft/kiota-authentication-phpleague-php/releases)*
