Set up a virtual environment:  
```bash
python -m venv .venv
source .venv/Scripts/activate
```

Install dependancies
```bash
pip install -r requirements.txt
```

Start the Flask server locally
```bash
py app.py
```

To test the API endpoints locally run the below code
 ```
python test_crypto_api.py
```

The Flask server is deployed on Railway. Use the following URL to test the endpoints in Swagger
https://en4720-production-d82d.up.railway.app/
