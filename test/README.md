#  applications.security.amber.trustauthority-client-for-python

Intel Trust Authority Python Client unit tests are based on unittest framework.

### Supported OS
- Ubuntu 20.04
  

### Prerequisites
```
poetry add coverage
poetry update
```

### Run unit tests from **/applications.security.amber.trustauthority-client-for-python/test** with coverage enabled:
```
poetry run coverage run --source=/inteltrustauthorityclient/src/ -m unittest discover -p 'test_*.py'
```

### Generate coverage report:
```
poetry run coverage report -m
```