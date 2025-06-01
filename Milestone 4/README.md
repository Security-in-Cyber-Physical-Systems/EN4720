# Smart Home Security - Attack Detection

## Requirements

1. Install the GeoIP2 database and library:
    ```
    pip install geoip2
    ```

2. Download the GeoLite2 City database from MaxMind:
    https://dev.maxmind.com/geoip/geoip2/geolite2/
    
**Note:** The GeoLite2 City database has already downloaded and inserted into the repository.

## How to Run Tests

1. Open terminal in the project folder (`Milestone 4`)
2. Run the tests:

```bash
# Run all tests
python -m unittest tests.test_failed_login
python -m unittest tests.test_geo_anomaly
python -m unittest tests.test_password_reset
python -m unittest tests.test_power_anomaly
python -m unittest tests.test_role_anomaly
python -m unittest tests.test_toggle_spam
python -m unittest tests.test_unauthorized_access
```

```bash
# Run only unit tests
python -m unittest tests.test_power_anomaly.TestPowerAnomalyDetector

# Run only integration tests
python -m unittest tests.test_power_anomaly.TestPowerIntegration
```

After running tests:
All detected anomalies will be logged to logs.json