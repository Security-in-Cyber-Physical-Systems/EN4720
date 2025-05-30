# Smart Home Security - Attack Detection

## How to Run Tests

1. Open terminal in the project folder (`Milestone 4`)
2. Run the tests:
```bash
# Run all auth tests
python -m unittest tests.test_power_anomaly

# Run only unit tests
python -m unittest tests.test_power_anomaly.TestPowerAnomalyDetector

# Run only integration tests
python -m unittest tests.test_power_anomaly.TestPowerIntegration
```

After running tests:
All detected anomalies will be logged to logs.json