# Run the application

## Create a virtual environment
python -m venv venv  

## Activate on 

### macOS/Linux
source venv/bin/activate  

### Windows
venv\Scripts\activate   

## Install packages
pip install -r requirements.txt 

## Run the flask app
$evn:FLASK_APP = "crypto_api.py"

flask run

## To access swagger API docs after running the flask app visit
http://127.0.0.1:5000/apidocs





