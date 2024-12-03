import re
import csv
from collections import defaultdict
import os
from datetime import datetime

# Dynamically get the script's directory
script_directory = os.path.dirname(os.path.abspath(__file__))

# Define the log file name and output file
LOG_FILE_PATH = os.path.join(script_directory, "sample.log")
OUTPUT_CSV_PATH = os.path.join(script_directory, "log_analysis_results.csv")

# Configurable threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

# Function to parse the log file
def parse_log(log_file_path):
    ip_request_counts = defaultdict(int)
    endpoint_access_counts = defaultdict(int)
    failed_login_attempts = defaultdict(int)
    hourly_traffic_distribution = defaultdict(int)

    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            # Extract IP Address
            ip_match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip_address = ip_match.group(1)
                ip_request_counts[ip_address] += 1
            
            # Extract Endpoint
            endpoint_match = re.search(r'\"[A-Z]+\s(\/\S*)\sHTTP', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_access_counts[endpoint] += 1
            
            # Detect Failed Logins
            if "401" in line or "Invalid credentials" in line:
                if ip_match:
                    failed_login_attempts[ip_address] += 1
            
            # Analyze Hourly Traffic
            time_match = re.search(r'\[(\d+/\w+/\d+:\d+):', line)
            if time_match:
                time_str = time_match.group(1)
                log_time = datetime.strptime(time_str, "%d/%b/%Y:%H")
                hourly_traffic_distribution[log_time.strftime("%H:00")] += 1

    return ip_request_counts, endpoint_access_counts, failed_login_attempts, hourly_traffic_distribution

# Function to save results to a CSV file
def save_to_csv(ip_counts, endpoint_counts, failed_logins, hourly_traffic):
    with open(OUTPUT_CSV_PATH, mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        writer.writerow([])  # Blank line

        # Write Most Accessed Endpoint
        most_accessed_endpoint = max(endpoint_counts.items(), key=lambda x: x[1])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        writer.writerow([])  # Blank line

        # Write Suspicious Activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in failed_logins.items():
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, count])

        writer.writerow([])  # Blank line

        # Write Hourly Traffic Distribution
        writer.writerow(["Hourly Traffic Distribution"])
        writer.writerow(["Hour", "Request Count"])
        for hour, count in sorted(hourly_traffic.items()):
            writer.writerow([hour, count])

# Main function
def main():
    print("Parsing log file...")
    ip_counts, endpoint_counts, failed_logins, hourly_traffic = parse_log(LOG_FILE_PATH)

    # Display Requests per IP
    print("\nRequests per IP Address:")
    print(f"{'IP Address':<20}{'Request Count':<15}")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20}{count:<15}")

    # Display Most Accessed Endpoint
    most_accessed_endpoint = max(endpoint_counts.items(), key=lambda x: x[1])
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    # Display Suspicious Activity
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20}{'Failed Login Attempts':<25}")
    for ip, count in failed_logins.items():
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:<20}{count:<25}")

    # Display Hourly Traffic Distribution
    print("\nHourly Traffic Distribution:")
    print(f"{'Hour':<10}{'Request Count':<15}")
    for hour, count in sorted(hourly_traffic.items()):
        print(f"{hour:<10}{count:<15}")

    # Save to CSV
    print("\nSaving results to CSV...")
    save_to_csv(ip_counts, endpoint_counts, failed_logins, hourly_traffic)
    print(f"Results saved to {OUTPUT_CSV_PATH}")

if __name__ == "__main__":
    main()
