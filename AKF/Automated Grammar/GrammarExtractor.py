import re
import requests
import base64

url = "https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal?format=TEXT"
response = requests.get(url)
file_content = base64.b64decode(response.content).decode()

url = "https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/types.hal?format=TEXT"
response = requests.get(url)
types_content = base64.b64decode(response.content).decode()




type_pattern = re.compile(r'typedef\s+(\w+)\s+(\w+);')
types = type_pattern.findall(types_content)

struct_pattern = re.compile(r'struct\s+(\w+)\s*{([^}]*)};')
structs = struct_pattern.findall(types_content)

enum_pattern = re.compile(r'enum.*: .*?.* ')
enums = enum_pattern.findall(types_content)

type_mapping = {user_type: base_type for base_type, user_type in types}


def convert_type(user_type):
    if user_type in type_mapping:
        resolved_type = type_mapping[user_type]
        if isinstance(resolved_type, list):
            if all(isinstance(item, str) for item in resolved_type):
                return f"({'|'.join(resolved_type)})"
            return " ".join([convert_type(member_type) for member_type, _ in resolved_type])
        else:
            return resolved_type
    vector_pattern = re.match(r'Vector<(\w+)>', user_type)
    if vector_pattern:
        element_type = vector_pattern.group(1)
        resolved_element_type = convert_type(element_type)
        return f"vector<{resolved_element_type}>"
    return user_type

def resolve_struct_members(struct_members):
    member_patterns = re.findall(r'(\w+)\s+(\w+);', struct_members)
    resolved_members = []
    for member_type, member_name in member_patterns:
        resolved_type = convert_type(member_type)
        resolved_members.append((resolved_type, member_name))
    return resolved_members

for enum in enums:
    enum_name=enum.split(":")[0].split(" ")[1].strip()
    enum_type=enum.split(":")[1].strip()

    type_mapping[enum_name] = enum_type

for struct_name, struct_members in structs:
    type_mapping[struct_name] = resolve_struct_members(struct_members)






func_pattern = re.compile(r"[a-z].*\(.*\).*\s*generates.*;")

def write_state_rule(rule):
    with open("initial_grammar.xml", "a") as file:
        file.write(rule)

def parse_functions(content):
    functions = []
    for match in func_pattern.finditer(content):
        return_type = match.group(0).split("generates")[1].split('(')[1].split(')')[0].split(", ")
        func_name = match.group(0).split('(')[0]
        params = match.group(0).split('(')[1].split(')')[0].split(", ")
        param_list = params
        functions.append((return_type, func_name, param_list))

    for func in functions:
    	for func2 in functions:
    		for datatype in func[0]:
    			if datatype in func2[2]:
    				write_state_rule(func[1]+"-->"+func2[1]+"\n")

    return functions

functions = parse_functions(file_content)




def generate_fuzzing_grammar(functions):
    grammar = []
    grammar.append("<?xml version=\"1.0\"?>")	
    grammar.append("<Peach>")
    grammar.append("  <DataModel name=\"IKeymasterDevice\">")
    for return_type, func_name, param_list in functions:
        grammar.append(f"    <Block name=\"{func_name}\">")
        for param in param_list:
            if param:
                param_type, param_name = param.rsplit(' ', 1)
                converted_param_type = convert_type(param_type)
                grammar.append(f"      <{converted_param_type} name=\"{param_name}\"/>")
        grammar.append("    </Block>")
    grammar.append("  </DataModel>")
    grammar.append("</Peach>")
    return "\n".join(grammar)

fuzzing_grammar = generate_fuzzing_grammar(functions)

with open("initial_grammar.xml", "a") as file:
    file.write(fuzzing_grammar)

