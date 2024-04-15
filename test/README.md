#  applications.security.amber.trustauthority-client-for-python

Intel Trust Authority Python Client unit tests are based on unittest framework.
### Prerequisites
```
poetry add coverage
poetry update
```

### Run unit tests with coverage enabled:
```
poetry run coverage run --source=../src/inteltrustauthorityclient/ -m unittest discover -p 'test_*.py'
```

### Generate coverage report:
```
poetry run coverage report -m
```