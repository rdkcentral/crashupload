# Feature Files

This directory contains functional test specifications written in Gherkin language.

## Gherkin Syntax

Gherkin uses a simple, readable syntax to describe test scenarios:

```gherkin
Feature: Brief description of functionality
  Background information about the feature

  Scenario: Specific test case description
    Given initial context or preconditions
    When action or event occurs
    Then expected outcome or verification
    And additional steps (optional)
```

### Keywords

- **Feature**: Groups related scenarios, describes what is being tested
- **Scenario**: Individual test case with specific conditions
- **Given**: Sets up initial state or preconditions
- **When**: Describes the action or trigger event
- **Then**: Specifies expected results or assertions
- **And/But**: Continues the previous step type

### Example

```gherkin
Feature: Crash dump upload

  Scenario: Upload core dump successfully
    Given a valid core dump file exists
    And network connectivity is available
    When the upload process runs
    Then the dump file is uploaded to the server
    And a success telemetry event is sent
```

## File Organization

Each `.feature` file should focus on a specific module or functionality:
- `config.feature` - Configuration management tests
- `upload.feature` - Upload workflow tests
- `platform.feature` - Platform detection tests

See [test/functional-tests/tests/](../tests/) for the Python test implementations.
