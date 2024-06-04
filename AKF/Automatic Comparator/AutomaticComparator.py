import json

class AutomaticComparator:
    def __init__(self, comparison_rules):
        self.comparison_rules = comparison_rules

    def compare_responses(self, responses):
        results = []
        for api_call, response_set in responses.items():
            rule = self.comparison_rules.get(api_call)
            if not rule:
                continue

            if rule == "type":
                result = self.compare_return_types(response_set)
            elif rule == "format":
                result = self.compare_return_types(response_set)
                result = self.compare_return_formats(response_set)
            elif rule == "value":
                result = self.compare_return_types(response_set)
                result = self.compare_return_formats(response_set)
                result = self.compare_return_values(response_set)
            else:
                result = {"api_call": api_call, "status": "unknown rule"}

            results.append(result)
        return results

    def compare_return_types(self, response_set):
        types = [type(response) for response in response_set]
        consistent = all(t == types[0] for t in types)
        return {"api_call": response_set['api_call'], "comparison": "type", "consistent": consistent}

    def compare_return_formats(self, response_set):
        sizes = [len(response) if isinstance(response, (str, bytes)) else None for response in response_set]
        consistent = all(size == sizes[0] for size in sizes if size is not None)
        return {"api_call": response_set['api_call'], "comparison": "format", "consistent": consistent}

    def compare_return_values(self, response_set):
        values = [response for response in response_set]
        consistent = all(value == values[0] for value in values)
        return {"api_call": response_set['api_call'], "comparison": "value", "consistent": consistent}

    def load_responses_from_file(self, filename):
        with open(filename, 'r') as file:
            return json.load(file)

    def save_comparison_results_to_file(self, results, filename):
        with open(filename, 'w') as file:
            json.dump(results, file, indent=4)

    comparison_rules = {
        "getHardwareInfo" : "format",
        "getHmacSharingParameters" : "format",
        "computeSharedHmac" : "format",
        "verifyAuthorization" : "format",
        "addRngEntropy" : "format",
        "generateKey" : "format",
        "importKey" : "format",
        "getKeyCharacteristics" : "value",
        "exportKey" : "type",
        "attestKey" : "value",
        "upgradeKey" : "format",
        "deleteKey" : "type",
        #DANGEROUS FUNCTIONS
        #"deleteAllKeys" : "type",
        #"destroyAttestationIds()" : "type",
        "begin" : "type",
        "update" : "type",
        "finish" : "value",
        "abort" : "type",
        "enroll" : "type",
        "verify" : "format",
        "deleteUser" : "type",
        "deleteAllUsers" : "type"
    }

    comparator = AutomaticComparator(comparison_rules)

    responses = comparator.load_responses_from_file("responses")
    comparison_results = comparator.compare_responses(responses)
    comparator.save_comparison_results_to_file(comparison_results, "comparison_results")
