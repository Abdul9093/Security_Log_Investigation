
def check_firewall_line(line):
    parts = line.strip().split()

    # A normal entry should have 8 parts
    if len(parts) != 8:
        return False

    # Check the firewall action
    if parts[2] not in ["ALLOWED", "BLOCKED"]:
        return False

    # Extract the key-value fields
    fields = {}

    for item in parts[3:]:
        if "=" not in item:
            return False

        key, value = item.split("=", 1)

        if value == "":
            return False

        fields[key] = value

    # Check that all required fields exist
    required = ["src", "dst", "proto", "port", "bytes"]

    for field in required:
        if field not in fields:
            return False

    return True


# Read and check the actual firewall log
valid_count = 0
malformed_count = 0

try:
    with open("firewall.log", "r") as file:

        for line_number, line in enumerate(file, start=1):

            if check_firewall_line(line):
                valid_count += 1
            else:
                malformed_count += 1
                print("Malformed line:", line_number)

    print("\nFIREWALL FILE CHECK")
    print("-------------------")
    print("Valid lines:", valid_count)
    print("Malformed lines:", malformed_count)

except FileNotFoundError:
    print("Error: firewall.log was not found.")
