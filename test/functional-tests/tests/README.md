# Functional Test Implementation

This directory contains pytest-based functional tests that execute the Gherkin scenarios defined in [features/](../features/).

## Overview

Tests are implemented using **pytest-bdd**, which maps Gherkin steps to Python functions:

```python
@given('a valid core dump file exists')
def create_dump_file(context):
    # Implementation

@when('the upload process runs')
def run_upload(context):
    # Implementation

@then('the dump file is uploaded to the server')
def verify_upload(context):
    # Assert expected behavior
```

## Running Tests

```bash
# Run all functional tests
pytest test/functional-tests/tests/

# Run specific feature
pytest test/functional-tests/tests/test_upload.py

# Verbose output
pytest -v test/functional-tests/tests/
```

## Test Structure

- Each `.py` file implements steps for corresponding `.feature` files
- Test fixtures in `conftest.py` provide common setup/teardown
- Step definitions are reusable across multiple scenarios
- Tests run against actual compiled binaries for integration validation

See [features/](../features/) for test specifications in Gherkin format.
