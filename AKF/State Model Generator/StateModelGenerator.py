import random
import xml.etree.ElementTree as ET
from xml.dom import minidom
import re

class StateModelGenerator:
    def __init__(self, api_calls, max_api_calls=3):
        self.api_calls = api_calls
        self.max_api_calls = max_api_calls
        self.call_count = {}
        for call in self.api_calls:

            self.call_count[call] = 0 

    def generate_sequence(self, max_sequence_length):
        sequence = []
        total_calls = random.randint(1, max_sequence_length)
        while len(sequence) < total_calls:
            api_call = self.select_api_call()
            if api_call:
                sequence.append(api_call)
                self.call_count[api_call] += 1
                if self.call_count[api_call] >= self.max_api_calls:
                    self.api_calls = [call for call in self.api_calls if call != api_call]
            else:
                break
        return sequence

    def select_api_call(self):
        valid_api_calls = [call for call in self.api_calls if self.call_count[call] < self.max_api_calls]
        if not valid_api_calls:
            return None
        return random.choice(valid_api_calls)

    def validate_sequence(self, sequence):
        with open("dynamic_grammar.json",'r') as file:
            currentRules=file.read()
            rules=re.findall(r'.*-->.*', currentRules)
            for rule in rules:
                if rule.split("-->")[1] in sequence:
                    if sequence.index(rule.split("-->")[1]) < sequence.index(rule.split("-->")[0]):
                        return false

        return True

    def generate_state_model(self, num_sequences, max_sequence_length):
        state_model = []
        for _ in range(num_sequences):
            self.reset_call_count()
            sequence = self.generate_sequence(max_sequence_length)
            if self.validate_sequence(sequence):
                state_model.append(sequence)
        return state_model

    def reset_call_count(self):
        for call in api_calls:
            self.call_count[call]: 0 

    def save_state_model_to_xml(self, state_model, filename):
        root = ET.Element('StateModel')

        for sequence in state_model:
            sequence_element = ET.SubElement(root, 'Sequence')
            for call in sequence:
                call_element = ET.SubElement(sequence_element, 'APICall')
                ET.SubElement(call_element,call).text = call

        tree = ET.ElementTree(root)
        xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="   ")
        with open(filename, 'w') as file:
            file.write(xml_str)

if __name__ == "__main__":
    api_calls = [
        "getHardwareInfo",
        "getHmacSharingParameters",
        "computeSharedHmac",
        "verifyAuthorization",
        "addRngEntropy",
        "generateKey",
        "importKey",
        "getKeyCharacteristics",
        "exportKey",
        "attestKey",
        "upgradeKey",
        "deleteKey",
        #DANGEROUS FUNCTIONS
        #"deleteAllKeys",
        #"destroyAttestationIds()",
        "begin",
        "update",
        "finish",
        "abort",
        "enroll",
        "verify",
        "deleteUser",
        "deleteAllUsers"
    ]

    

    generator = StateModelGenerator(api_calls)
    state_model = generator.generate_state_model(num_sequences=1, max_sequence_length=20)
    generator.save_state_model_to_xml(state_model, "state_model.xml")
