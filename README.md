# EN4720---Security-in-Cyber-Physical-Systems
python -m venv venv  # Create a virtual environment

source venv/bin/activate  # Activate on macOS/Linux
venv\Scripts\activate  # Activate on Windows

pip install -r requirements.txt

# To run the flask app
$evn:FLASK_APP = "crypto_api.py"
flask run

# To access swagger API docs visit
http://127.0.0.1:5000/apidocs





