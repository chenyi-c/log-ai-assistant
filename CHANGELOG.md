# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project uses semantic versioning when releases are cut.

## [Unreleased]

### Added

- Engineering quality audit baseline and reproducible backend quality checks
- Pre-commit hooks and GitHub Actions CI workflow
- Windows-compatible operations file-lock fallback with regression coverage

### Changed

- Made periodic-baseline test time deterministic through optional `end_date` injection
- Removed verified unused imports and local variables
