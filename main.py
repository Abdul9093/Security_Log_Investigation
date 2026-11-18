
# Function to check whether a firewall log line is valid
def check_firewall_line(line):

    # Split the line into separate parts
    parts = line.strip().split()

    # A normal entry should have 8 parts
    if len(parts) != 8:
        return False

    # Check the firewall action
    if parts[2] not in ["ALLOWED", "BLOCKED"]:
        return False

    # Store the key-value fields in a dictionary
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

# Function to extract information from an authentication log line
def parse_authentication_line(line):

    parts = line.strip().split()

    # Check that the line has enough information
    if len(parts) < 3:
        return None

    event = {
        "date": parts[0],
        "time": parts[1],
        "event": parts[2]
    }

    # Extract username and source IP
    for item in parts[3:]:
        if "=" in item:
            key, value = item.split("=", 1)
            event[key] = value

    return event


# Function to count authentication events
def analyse_authentication_log(authentication_data):

    # Create counters
    login_success = 0
    login_failed = 0
    account_locked = 0

    # Read each line from the authentication data
    for line in authentication_data:

        # Extract information from the line
        event = parse_authentication_line(line)

        # Skip invalid lines
        if event is None:
            continue

        # Check the event type
        if event["event"] == "LOGIN_SUCCESS":
            login_success += 1

        elif event["event"] == "LOGIN_FAILED":
            login_failed += 1

        elif event["event"] == "ACCOUNT_LOCKED":
            account_locked += 1

    # Return all three results
    return login_success, login_failed, account_locked


# Initialise firewall line counters
valid_count = 0
malformed_count = 0

# Read and check the firewall log file
try:
    with open("firewall.log", "r") as file:

        # Read each line with its line number
        for line_number, line in enumerate(file, start=1):

            # Check whether the line is valid
            if check_firewall_line(line):
                valid_count += 1
            else:
                malformed_count += 1
                print("Malformed line:", line_number)

    # Display firewall validation results
    print("\nFIREWALL FILE CHECK")
    print("-------------------")
    print("Valid lines:", valid_count)
    print("Malformed lines:", malformed_count)

except FileNotFoundError:
    print("Error: firewall.log was not found.")


# STEP 1: Read both security log files
print("\nSTEP 1: READING SECURITY LOG FILES")
print("----------------------------------")

try:
    # Open the firewall log file and read all lines
    with open("firewall.log", "r") as file:
        firewall_data = file.readlines()

    # Open the authentication log file and read all lines
    with open("authentication.log", "r") as file:
        authentication_data = file.readlines()

    # Display the total number of lines in each file
    print("Firewall lines:", len(firewall_data))
    print("Authentication lines:", len(authentication_data))

except FileNotFoundError:
    print("Error: One of the log files was not found.")


# Initialise firewall action counters
allowed_count = 0
blocked_count = 0

# Analyse firewall actions
try:
    # Open the firewall log file
    with open("firewall.log", "r") as file:

        # Read each line from the firewall log
        for line in file:

            # Check whether the line is valid
            if check_firewall_line(line):

                parts = line.strip().split()
                action = parts[2]

                # Count allowed firewall events
                if action == "ALLOWED":
                    allowed_count += 1

                # Count blocked firewall events
                elif action == "BLOCKED":
                    blocked_count += 1

    # Display firewall action results
    print("\nFIREWALL ACTION ANALYSIS")
    print("------------------------")
    print("Allowed events:", allowed_count)
    print("Blocked events:", blocked_count)

except FileNotFoundError:
    print("Error: firewall.log was not found.")
    
    
unique_ips = set()

try:
    with open("firewall.log", "r") as file:

        for line in file:

            # Process only valid firewall entries
            if check_firewall_line(line):

                parts = line.strip().split()

                # Find the source IP address
                for item in parts[3:]:
                    if item.startswith("src="):

                        source_ip = item.split("=", 1)[1]

                        # Store IP without duplicates
                        unique_ips.add(source_ip)

    # Display results after reading the entire file
    print("\nUNIQUE SOURCE IP ANALYSIS")
    print("-------------------------")
    print("Total unique source IPs:", len(unique_ips))

except FileNotFoundError:
    print("Error: firewall.log was not found.")
    
blocked_ips = {}

try:
    with open("firewall.log", "r") as file:

        for line in file:

            # Process only valid firewall entries
            if check_firewall_line(line):

                parts = line.strip().split()

                # Check if the event is BLOCKED
                if parts[2] == "BLOCKED":

                    # Find the source IP
                    for item in parts[3:]:
                        if item.startswith("src="):

                            source_ip = item.split("=", 1)[1]

                            # Count blocked attempts
                            if source_ip in blocked_ips:
                                blocked_ips[source_ip] += 1
                            else:
                                blocked_ips[source_ip] = 1

    # Display the top blocked IPs
    print("\nTOP BLOCKED IP ADDRESSES")
    print("------------------------")

    sorted_ips = sorted(
        blocked_ips.items(),
        key=lambda item: item[1],
        reverse=True
    )

    for ip, count in sorted_ips[:5]:
        print(ip, ":", count, "blocked attempts")

except FileNotFoundError:
    print("Error: firewall.log was not found.")
    # Create an empty dictionary to count target ports
port_counts = {}

try:
    with open("firewall.log", "r") as file:

        for line in file:

            # Process only valid firewall entries
            if check_firewall_line(line):

                parts = line.strip().split()

                # Find the destination port
                for item in parts[3:]:
                    if item.startswith("port="):

                        port = item.split("=", 1)[1]

                        # Count port activity
                        if port in port_counts:
                            port_counts[port] += 1
                        else:
                            port_counts[port] = 1

    # Display the most targeted ports
    print("\nTARGETED PORT ANALYSIS")
    print("----------------------")

    sorted_ports = sorted(
        port_counts.items(),
        key=lambda item: item[1],
        reverse=True
    )

    for port, count in sorted_ports[:5]:
        print("Port", port, ":", count, "events")

except FileNotFoundError:
    print("Error: firewall.log was not found.")
    

# Read the first 5 lines of authentications log
try:
    #Open the authenticatioin loig file
    with open("authentication.log", "r") as file:
        
        #Display the heading
        print("\nAUTHENTICATION LOG FILE")
        print("------------")
        
        #Read the file line by line
        for line_number, line in enumerate(file, start=1):
            
            #Dislpay the curetn line
            print(line.strip())
            
            # stop after reading 5 lines
            if line_number == 5:
                break
            
    #handles missing file error
except FileNotFoundError:
    print("Error: authentication.log was not found.")
    
    
    # Analyse authentication events using the function

login_success, login_failed, account_locked = analyse_authentication_log(authentication_data)

# Display login analysis results
print("\nLOGIN ANALYSIS")
print("-------------------------")
print("Successful logins:", login_success)
print("Failed logins:", login_failed)
print("Account locked events:", account_locked)
    
    
       # Count failed login attempts by source IP

failed_login_ips = {}

try:
    # Open the authentication log file
    with open("authentication.log", "r") as file:

        # Read each line
        for line in file:

            parts = line.strip().split()

            # Check for failed login events
            if len(parts) >= 3 and parts[2] == "LOGIN_FAILED":

                # Find the source IP
                for item in parts[3:]:
                    if item.startswith("src="):

                        source_ip = item.split("=", 1)[1]

                        # Count failed login attempts
                        if source_ip in failed_login_ips:
                            failed_login_ips[source_ip] += 1
                        else:
                            failed_login_ips[source_ip] = 1

    # Display the results
    print("\nTOP FAILED LOGIN SOURCE IPS")
    print("---------------------------")

    sorted_ips = sorted(
        failed_login_ips.items(),
        key=lambda item: item[1],
        reverse=True
    )

    # Display the top 5 IP addresses
    for ip, count in sorted_ips[:5]:
        print(ip, ":", count, "failed attempts")

except FileNotFoundError:
    print("Error: authentication.log was not found.")
    
    

# Count failed login attempts by username

failed_usernames = {}

try:
    with open("authentication.log", "r") as file:
        for line in file:
            parts = line.strip().split()

            if len(parts) >= 3 and parts[2] == "LOGIN_FAILED":

                for item in parts[3:]:
                    if item.startswith("user="):

                        username = item.split("=", 1)[1]

                        # Ignore empty usernames
                        if username != "":

                            if username in failed_usernames:
                                failed_usernames[username] += 1
                            else:
                                failed_usernames[username] = 1

    print("\nTOP FAILED LOGIN USERNAMES")
    print("--------------------------")

    sorted_users = sorted(
        failed_usernames.items(),
        key=lambda item: item[1],
        reverse=True
    )

    for username, count in sorted_users[:5]:
        print(username, ":", count, "failed attempts")

except FileNotFoundError:
    print("Error: authentication.log was not found.")

    
    # Sav failed login username results in  TXT file

try:
    # Create a text report
    with open("username_report.txt", "w") as report:

        report.write("FAILED LOGIN USERNAME REPORT\n")
        report.write("-----------------------------\n\n")

        # Sort usernames by failed login count
        sorted_users = sorted(
            failed_usernames.items(),
            key=lambda item: item[1],
            reverse=True
        )

        # Write results into the file
        for username, count in sorted_users:
            report.write(
                username + " : " +
                str(count) + " failed attempts\n"
            )

    print("\nTXT REPORT")
    print("Username report saved successfully!")

except Exception as error:
    print("Error saving report:", error)
    
    
# Save the complete security investigation report

try:
    with open("security_report.txt", "w") as report:

        report.write("SECURITY LOG INVESTIGATION REPORT\n")
        report.write("=================================\n\n")

        # Firewall file check
        report.write("FIREWALL FILE CHECK\n")
        report.write("-------------------\n")
        report.write("Total lines: " + str(len(firewall_data)) + "\n")
        report.write("Valid lines: " + str(valid_count) + "\n")
        report.write("Malformed lines: " + str(malformed_count) + "\n\n")

        # Firewall action analysis
        report.write("FIREWALL ACTION ANALYSIS\n")
        report.write("------------------------\n")
        report.write("Allowed events: " + str(allowed_count) + "\n")
        report.write("Blocked events: " + str(blocked_count) + "\n")
        report.write("Unique source IPs: " + str(len(unique_ips)) + "\n\n")

        # Top blocked IP addresses
        report.write("TOP BLOCKED IP ADDRESSES\n")
        report.write("------------------------\n")

        sorted_ips = sorted(
            blocked_ips.items(),
            key=lambda item: item[1],
            reverse=True
        )

        for ip, count in sorted_ips[:5]:
            report.write(ip + " : " + str(count) + " blocked attempts\n")

        # Targeted ports
        report.write("\nTARGETED PORTS\n")
        report.write("--------------\n")

        sorted_ports = sorted(
            port_counts.items(),
            key=lambda item: item[1],
            reverse=True
        )

        for port, count in sorted_ports[:5]:
            report.write("Port " + port + " : " + str(count) + " events\n")

        # Authentication analysis
        report.write("\nAUTHENTICATION ANALYSIS\n")
        report.write("-----------------------\n")
        report.write("Successful logins: " + str(login_success) + "\n")
        report.write("Failed logins: " + str(login_failed) + "\n")
        report.write("Account locked events: " + str(account_locked) + "\n\n")

        # Top failed login source IPs
        report.write("TOP FAILED LOGIN SOURCE IPS\n")
        report.write("----------------------------\n")

        sorted_failed_ips = sorted(
            failed_login_ips.items(),
            key=lambda item: item[1],
            reverse=True
        )

        for ip, count in sorted_failed_ips[:5]:
            report.write(ip + " : " + str(count) + " failed attempts\n")

        # Top failed login usernames
        report.write("\nTOP FAILED LOGIN USERNAMES\n")
        report.write("--------------------------\n")

        sorted_users = sorted(
            failed_usernames.items(),
            key=lambda item: item[1],
            reverse=True
        )

        for username, count in sorted_users[:5]:
            report.write(username + " : " + str(count) + " failed attempts\n")

    print("\nCOMPLETE SECURITY REPORT")
    print("Security report saved successfully!")

except Exception as error:
    print("Error saving report:", error)


# Import the CSV module
import csv

# Save the complete security report as a CSV file

try:
    with open("security_report.csv", "w", newline="", encoding="utf-8") as report_file:

        writer = csv.writer(report_file)

        # Write column headings
        writer.writerow(["Section", "Item", "Count"])

        # Firewall file check
        writer.writerow(["Firewall", "Total Lines", len(firewall_data)])
        writer.writerow(["Firewall", "Valid Lines", valid_count])
        writer.writerow(["Firewall", "Malformed Lines", malformed_count])

        # Firewall action analysis
        writer.writerow(["Firewall", "Allowed Events", allowed_count])
        writer.writerow(["Firewall", "Blocked Events", blocked_count])
        writer.writerow(["Firewall", "Unique Source IPs", len(unique_ips)])

        # Top blocked IPs
        for ip, count in sorted(blocked_ips.items(), key=lambda item: item[1], reverse=True)[:5]:
            writer.writerow(["Top Blocked IPs", ip, count])

        # Targeted ports
        for port, count in sorted(port_counts.items(), key=lambda item: item[1], reverse=True)[:5]:
            writer.writerow(["Targeted Ports", port, count])

        # Authentication analysis
        writer.writerow(["Authentication", "Successful Logins", login_success])
        writer.writerow(["Authentication", "Failed Logins", login_failed])
        writer.writerow(["Authentication", "Account Locked", account_locked])

        # Top failed login IPs
        for ip, count in sorted(failed_login_ips.items(), key=lambda item: item[1], reverse=True)[:5]:
            writer.writerow(["Failed Login IPs", ip, count])

        # Top failed login usernames
        for username, count in sorted(failed_usernames.items(), key=lambda item: item[1], reverse=True)[:5]:
            writer.writerow(["Failed Login Usernames", username, count])

    print("\nCSV REPORT")
    print("CSV report saved successfully!")

except Exception as error:
    print("Error saving CSV report:", error)

# Import the JSON module
import json

# Create the security report data
security_data = {
    "firewall": {
        "total_lines": len(firewall_data),
        "valid_lines": valid_count,
        "malformed_lines": malformed_count,
        "allowed_events": allowed_count,
        "blocked_events": blocked_count,
        "unique_source_ips": len(unique_ips),
        "top_blocked_ips": dict(
            sorted(blocked_ips.items(), key=lambda item: item[1], reverse=True)[:5]
        ),
        "targeted_ports": dict(
            sorted(port_counts.items(), key=lambda item: item[1], reverse=True)[:5]
        )
    },

    "authentication": {
        "successful_logins": login_success,
        "failed_logins": login_failed,
        "account_locked": account_locked,
        "top_failed_login_ips": dict(
            sorted(failed_login_ips.items(), key=lambda item: item[1], reverse=True)[:5]
        ),
        "top_failed_login_usernames": dict(
            sorted(failed_usernames.items(), key=lambda item: item[1], reverse=True)[:5]
        )
    }
}

# Save the report as a JSON file
try:
    with open("security_report.json", "w", encoding="utf-8") as report_file:
        json.dump(security_data, report_file, indent=4)

    print("\nJSON REPORT")
    print("JSON report saved successfully!")

except Exception as error:
    print("Error saving JSON report:", error)
    



    



