import json
from collections import defaultdict, deque
import random

class DynamicGrammar:
    def __init__(self, initial_rules):
        self.rules = initial_rules
        self.stale_sequences = deque(maxlen=100)
        self.frequency_table = defaultdict(int)

    def update_grammar(self, new_rules):
        for key, value in new_rules.items():
            if key in self.rules:
                self.rules[key].update(value)
            else:
                self.rules[key] = value

    def process_fuzzing_results(self, test_cases, results):
        for i, test_case in enumerate(test_cases):
            if self.is_significantly_different(results[i]):
                self.add_new_rule(test_cases)
            else:
                self.stale_sequences.append(test_case)
                self.update_frequency_table(test_case)

        self.check_and_update_stale_sequences()

    def is_significantly_different(self, result):
        if not result_set:
            return False
        
        return_values = [result['return_value'] for result in result_set]
        
        return_types = [type(return_value) for return_value in return_values]
        if len(set(return_types)) > 1:
            return True

        return_lengths = [len(return_value) if isinstance(return_value, (str, bytes)) else None for return_value in return_values]
        if len(set(return_lengths)) > 1:
            return True

        bitwise_differences = []
        for i in range(len(return_values) - 1):
            bitwise_difference = sum(c1 != c2 for c1, c2 in zip(return_values[i], return_values[i + 1])) / max(len(return_values[i]), len(return_values[i + 1]))
            bitwise_differences.append(bitwise_difference)

        if any(difference > 0.1 for difference in bitwise_differences):
            return True

        return False

    def add_new_rule(self, test_cases):
        for sequence1, seqence2 in zip(test_cases[0], test_cases[1]):
            if sequence1 != sequence2:
                sequence_diff = {}
                for call1 in sequence1:
                    if call1 != sequence2[0]:
                        sequence_diff = [call1, call2]
                if sequence_diff in self.rules:
                    continue
                else:
                    self.rules.append(sequence_diff)

    def update_frequency_table(self, sequence):
        for i in range(len(sequence) - 1):
            subsequence = (sequence[i]['name'], sequence[i+1]['name'])
            self.frequency_table[subsequence] += 1

    def check_and_update_stale_sequences(self):
        threshold = 100 
        for subsequence, frequency in self.frequency_table.items():
            if frequency > threshold:
                self.add_staleness_rule(subsequence)

    def add_staleness_rule(self, subsequence):
        api1, api2 = subsequence
        if api1 in self.rules:
            if 'disallowed' not in self.rules[api1]:
                self.rules[api1]['disallowed'] = []
            self.rules[api1]['disallowed'].append(api2)

    def save_grammar_to_file(self, filename):
        with open(filename, 'w') as file:
            json.dump(self.rules, file, indent=4)



