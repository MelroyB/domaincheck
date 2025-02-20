#!/bin/bash

# Controleer of de REPO_URL variabele is ingesteld
if [ -z "$REPO_URL" ]; then
  echo "REPO_URL environment variable is not set. Exiting."
  exit 1
fi

# Clone de repository
git clone $REPO_URL repo

# Ga naar de directory van de repository
cd repo

# Installeer Python dependencies
pip install -r requirements.txt

# Start de Flask applicatie
python app.py


