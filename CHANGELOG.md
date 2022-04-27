# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [v0.3.1](https://github.com/aws-beam/aws_signature/tree/v0.3.1) (2022-04-27)

### Fixed

- Signature for URLs with explicit port component ([#18](https://github.com/aws-beam/aws_signature/pull/18))

## [v0.3.0](https://github.com/aws-beam/aws_signature/tree/v0.3.0) (2022-04-12)

This release changes the default behaviour of `sign_v4_query_params`. Instead of
setting the body digest to "UNSIGNED-PAYLOAD" it now computes the digest of an
empty string. To retain the current behaviour you need to pass an option:

```diff
-sign_v4_query_params(AccessKeyID, SecretAccessKey, Region, Service, DateTime, Method, URL, []).
+sign_v4_query_params(AccessKeyID, SecretAccessKey, Region, Service, DateTime, Method, URL, [{body_digest, <<"UNSIGNED-PAYLOAD">>}]).
```

### Added

- Support for body signing in presigned requests ([#15](https://github.com/aws-beam/aws_signature/pull/15))

### Changed

- Default body digest in `sign_v4_query_params` signature ([#15](https://github.com/aws-beam/aws_signature/pull/15))

## [v0.2.0](https://github.com/aws-beam/aws_signature/tree/v0.2.0) (2021-09-27)

### Changed

- Changed `sign_v4_query_params` signatures to also accept HTTP method ([#11](https://github.com/aws-beam/aws_signature/pull/11))

## [v0.1.1](https://github.com/aws-beam/aws_signature/tree/v0.1.1) (2021-08-28)

### Added

- Support for query string signature ([#7](https://github.com/aws-beam/aws_signature/pull/7))

## [v0.1.0](https://github.com/aws-beam/aws_signature/tree/v0.1.0) (2021-08-17)

Initial release
