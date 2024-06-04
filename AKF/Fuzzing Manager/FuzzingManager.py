import subprocess
import json
import time
import DynamicGrammar
import StateModelGenerator
import AutomaticComparator

class FuzzingManager:
    def __init__(self, devices, pin):
        self.devices = devices
        self.pin = pin
        self.keys = {}
        self.key_counter = 0

    def run_adb_command(self, device, command):
        result = subprocess.run(['adb', '-s', device] + command.split(), capture_output=True, text=True)
        return result.stdout.strip()

    def send_file(self, device, local_path, remote_path):
        self.run_adb_command(device, f'push {local_path} {remote_path}')

    def receive_file(self, device, remote_path, local_path):
        self.run_adb_command(device, f'pull {remote_path} {local_path}')

    def authenticate_device(self, device):
        self.run_adb_command(device, 'shell input keyevent 26') 
        self.run_adb_command(device, 'shell input swipe 300 1000 300 500')  
        for digit in self.pin:
            self.run_adb_command(device, f'shell input text {digit}')  
        self.run_adb_command(device, 'shell input keyevent 66')  

    def process_input_format(self, input_format, device):
        with open(input_format, 'r') as file:
            data = file.read()

        for api_call in data:
            if 'keyBlob' in api_call:
                if 'generateKey' in api_call:
                    if api_call['generateKey']['algorithm'] in self.keys:
                        api_call['keyBlob'] = self.keys[api_call['generateKey']['algorithm']]
                    else:
                        self.keys[api_call['generateKey']['algorithm']] = self.generate_key(device, api_call['generateKey']['algorithm'])
                        api_call['keyBlob'] = self.keys[api_call['generateKey']['algorithm']]
                else:
                    api_call['keyBlob'] = self.retrieve_key_blob(device, api_call['keyBlob'])
        return data

    def generate_key(self, device, algorithm):
        self.key_counter += 1
        if self.key_counter % 100 == 0:
            return self.create_new_key(device, algorithm)
        else:
            return self.keys.get(algorithm, self.create_new_key(device, algorithm))


    def retrieve_key_blob(self, device):
        with open("combined_output", 'r') as outputFile:
            with open(input_format, 'r') as file:
                results = file.read()
                keyBlob=results.split(",")[file.read().split(",").index(generateKey)]
        return keyBlob

    def fuzz_device(self, device, input_format):
        self.authenticate_device(device)
        processed_input = self.process_input_format(input_format, device)
        with open('processed_input', 'w') as file:
            json.dump(processed_input, file)
        self.send_file(device, 'processed_input', '/data/local/tmp/processed_input')
        self.run_adb_command(device, 'shell FuzzingBinary /data/local/tmp/processed_input >> /data/local/tmp/combined_output')
        self.receive_file(self, device, "/data/local/tmp/combined_output", "."):

    def manage_fuzzing(self, input_format):

        with open("initial_rules.xml", 'r') as initialFile:
        initial_rules = file.read()
    

        grammar = DynamicGrammar(initial_rules)
    

        
        for device in self.devices:
            self.fuzz_device(device, input_format)

        with open("combined_output", 'r') as outputFile:
            results = file.read()
        AutomaticComparator()
        grammar.process_fuzzing_results(input_format, results)

        grammar.save_grammar_to_file("dynamic_grammar.json")


if __name__ == "__main__":
    devices = ["device1", "device2"]  # Replace with actual device identifiers
    pin = "1234"  # Replace with the actual PIN
    input_format = "input_format"

    manager = FuzzingManager(devices, pin)
    manager.manage_fuzzing(input_format)
