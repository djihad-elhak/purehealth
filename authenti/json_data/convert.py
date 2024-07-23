import json

def convert_to_int(data, fields):
    """
    Convert specified fields of a list of dictionaries to integers.
    """
    for item in data:
        for field in fields:
            item[field] = int(item[field])

def update_json_file(file_path, fields):
    """
    Load a JSON file, convert specified fields to integers, and save the updated data back to the file.
    """
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)

    convert_to_int(data, fields)

    with open(file_path, 'w', encoding='utf-8') as file:
        json.dump(data, file, ensure_ascii=False, indent=4)

# Update wilaya.json
update_json_file('wilaya.json', ['id', 'code'])

# Update city.json
update_json_file('city.json', ['id', 'wilaya_id'])
