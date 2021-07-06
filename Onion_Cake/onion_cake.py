import json
import requests
import datetime
import csv
import argparse


def fetch_attack(matrix='Enterprise', version=None, debug=True):
    """Returns MITRE ATT&CK as list of STIX objects"""

    index_url = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json'
    attack_json = ''
    results = []

    # chooses appropriate MITRE ATT&CK data, defaults to most recent version of Enterprise matrix
    with requests.get(index_url) as request:
        if request.status_code == 200:
            index = json.loads(request.text)
            for collection in index['collections']:
                if matrix.upper() in collection['name'].upper():
                    if not version:
                        attack_json = collection['versions'][0]['url']
                        if debug:
                            print(f"Fetching version {collection['versions'][0]['version']} of {collection['name']}")
                            print(f"URL: {attack_json}")
                    else:
                        for each in collection['versions']:
                            if version == each['version']:
                                attack_json = each['url']
                                if debug:
                                    print(f"Fetching version {each['version']} of {collection['name']}")
                                    print(f"URL: {attack_json}")

    # Removes the unnecessary clutter from the JSON object and builds list
    if debug:
        print("Building list...")
    with requests.get(attack_json) as request:
        if request.status_code == 200:
            data = json.loads(request.text)
            for stix_object in data['objects']:
                if stix_object['type'] == 'attack-pattern':
                    if 'x_mitre_deprecated' in stix_object.keys() and stix_object['x_mitre_deprecated']:
                        continue
                    if 'revoked' in stix_object.keys() and stix_object['revoked'] == True:
                        continue
                    results.append(stix_object)

    if debug:
        print("Finished!")
    return results


def get_technique_ids(data):
    """Returns a list of MITRE ATT&CK Techniques given list of STIX ATT&CK Objects"""
    results = []

    for each in data:
        for ref in each['external_references']:
            if 'source_name' in ref.keys():
                if 'mitre-attack' in ref['source_name']:
                    results.append(ref['external_id'])

    results = sorted(results)
    return results


def disable_all(data):
    """Builds & disables every technique. For Navigator 'techniques':[]"""
    results = []

    template = {'techniqueID': None,
                'tactic': None,
                'color': '',
                'score': 0,
                'comment': '',
                'enabled': False,
                'metadata': [],
                'showSubtechniques': False}

    for index, item in enumerate(data):

        for phase in item['kill_chain_phases']:
            results.append(template.copy())

            results[-1]['tactic'] = phase['phase_name']

            for ref in item['external_references']:
                if 'source_name' in ref.keys() and 'mitre-attack' in ref['source_name']:
                    results[-1]['techniqueID'] = ref['external_id']

    return results


class Navigator:
    """MITRE ATT&CK Navigator object"""

    attack = None
    data = None
    empty_navigator = 'empty_navigator.json'

    def __init__(self, attack=None, debug=True):

        if not attack:
            self.attack = fetch_attack('Enterprise', debug=debug)
        else:
            self.attack = attack

        with open(self.empty_navigator, 'r') as infile:
            self.data = json.load(infile)

        self.data['techniques'] = disable_all(self.attack)

    def write(self, filename=None):

        if filename is not None:
            if '.json' not in filename[-5:]:
                filename = filename + '.json'
        else:
            filename = f"Navigator_{str(datetime.datetime.utcnow()).split('.')[0]}.json"

        with open(filename, 'w') as outfile:
            json.dump(self.data, outfile)
            print(f"Saved {filename}!")

    def update_technique(self, technique_id=None, tactic=None, score=None, comment=None):
        for index, technique in enumerate(self.data['techniques']):
            if technique['techniqueID'] == technique_id:

                # if it's a subtechnique, enable the parent
                if technique_id.split('.'):
                    for p_index, parent in enumerate(self.data['techniques']):
                        if technique_id.split('.')[0] == parent['techniqueID']:
                            self.data['techniques'][index]['enabled'] = True
                            self.data['techniques'][index]['showSubtechniques'] = True

                if tactic:
                    if self.data['techniques'][index]['tactic'] == tactic.lower():
                        self.data['techniques'][index]['score'] += int(score)
                        self.data['techniques'][index]['comment'] = self.data['techniques'][index][
                                                                        'comment'] + '\n' + comment
                        self.data['techniques'][index]['enabled'] = True

                else:
                    self.data['techniques'][index]['score'] += int(score)
                    self.data['techniques'][index]['comment'] = self.data['techniques'][index][
                                                                    'comment'] + '\n' + comment
                    self.data['techniques'][index]['enabled'] = True

    def add_layer_from_csv(self, layer_file='example.csv'):

        header = None

        with open(layer_file, 'r') as infile:
            for index, row in enumerate(csv.reader(infile, delimiter=',', quotechar='"')):
                if index == 0:
                    header = row.copy()
                else:
                    _technique_id = row[header.index('techniqueID')]
                    _tactic = row[header.index('tactic')]
                    _score = row[header.index('score')]
                    _color = row[header.index('color')]
                    _comment = row[header.index('comment')]

                    self.update_technique(technique_id=_technique_id,
                                          tactic=_tactic,
                                          score=_score,
                                          comment=_comment)


if __name__ == "__main__":

    _attack = None
    _navigator = None

    # TODO Write a better description
    parser = argparse.ArgumentParser(description='Example usage: onion_layers.py -f example.csv -o layers.json')

    parser.add_argument('-f',
                        '--file',
                        dest='process_file',
                        type=str,
                        help='File to process')

    # parser.add_argument('-d',
    #                     '--dir',
    #                     dest='process_dir',
    #                     type=str,
    #                     help='Dir to process')

    parser.add_argument('-o',
                        '--output',
                        required=True,
                        dest='output_filename',
                        type=str,
                        help='Output file name')

    parser.add_argument('-m',
                        '--matrix',
                        dest='matrix',
                        type=str,
                        help='Which MITRE ATT&CK matrix, defaults to enterprise')

    parser.add_argument('-aV',
                        '--attackVersion',
                        dest='attack_version',
                        type=str,
                        help='Which MITRE ATT&CK version, defaults to latest')

    args = parser.parse_args()

    if args.matrix and not args.attack_version:
        _attack = fetch_attack(matrix=args.matrix)
    elif args.attack_version and not args.matrix:
        _attack = fetch_attack(version=args.attack_version)
    elif args.attack_version and args.matrix:
        _attack = fetch_attack(matrix=args.matrix, version=args.attack_version)
    else:
        _attack = fetch_attack()

    _navigator = Navigator(attack=_attack)

    if args.process_file:
        print(f"Processing {args.process_file}...")
        _navigator.add_layer_from_csv(layer_file=args.process_file)
        _navigator.write(filename=args.output_filename)

    # if args.process_dir:
    #     # TODO
    #     print(f"Not implemented yet....")

