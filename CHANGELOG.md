# Changelog

All notable changes to this project will be documented in this file.

## [2.2.0] - 2026-02-16

### Added
- `CreditsUsed` field on all result types for tracking API credit consumption
- Voice analysis (`AnalyzeVoiceAsync`) with multipart file upload
- Image analysis (`AnalyzeImageAsync`) with multipart file upload
- GDPR account management (delete, export, consent, rectify, audit logs)
- Breach management (log, list, get, update)
- Webhook management (list, create, update, delete, test, regenerate secret)
- Pricing endpoints (overview and detailed)
- Usage tracking (history, by tool, monthly)

## [1.0.0] - 2025-02-06

### Added
- Initial release
- Full support for all Tuteliq API endpoints
- Bullying detection
- Grooming detection
- Unsafe content detection
- Quick analysis (combined detection)
- Emotion analysis
- Action plan generation
- Incident report generation
- External ID and metadata tracking
- Automatic retry with exponential backoff
- Comprehensive error handling
- Unity 2021.3+ support
