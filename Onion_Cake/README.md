# Onion_Cake

This is a tool for creating MITRE ATT&CK Navigator json files from CSVs

usage: onion_cake.py [-h] [-f PROCESS_FILE] -o OUTPUT_FILENAME [-m MATRIX] [-aV ATTACK_VERSION]

Example usage: onion_layers.py -f example.csv -o layers.json

optional arguments:
  -h, --help            show this help message and exit
  -f PROCESS_FILE, --file PROCESS_FILE
                        File to process
  -o OUTPUT_FILENAME, --output OUTPUT_FILENAME
                        Output file name
  -m MATRIX, --matrix MATRIX
                        Which MITRE ATT&CK matrix, defaults to enterprise
  -aV ATTACK_VERSION, --attackVersion ATTACK_VERSION
                        Which MITRE ATT&CK version, defaults to latest
