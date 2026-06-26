"""
This module defines the TestRunner class, which is responsible for
executing individual firewall tests and analyzing their results.
"""

import json
import re
import subprocess
import sys
from . import containers

class TestRunner:
    """Orchestrates the execution of tests and interpretation of outcomes."""

    def _list_open_ports(self, port:str, protocol: str, container_id: str) -> bool:
        """
        Checks if there is a open port on container, checking port and protocol.

        Args:
            port (str): The port to be tested.
            protocol (str): The protocol to use (TCP, UDP).
            container_id (str): The ID of the source container.

        Returns:
            boolean: Returns true if there is a port open on container, otherwise, returns false
        """

        # filter tcp: ss -tln | grep <port>
        # filter upd: ss -uln | grep <port>

        if protocol.lower() == "tcp":
            flag = "-tln"
        else:
            flag = "-uln"

        check_port_command = f"ss {flag} | grep {port}"

        docker_command = [
            "docker", "exec", container_id,
            "sh", "-c", check_port_command
        ]

        try:
            result = subprocess.run(docker_command, capture_output=True, text=True, encoding='utf-8', timeout=10)
            
            if result.returncode != 0 or (not result.stdout):
                return False
            
            return True

        except Exception as e:
            error_msg = str(e)
            if hasattr(e, 'stderr') and e.stderr:
                error_msg = e.stderr.strip()
            
            print(f"Error TestRunner: {error_msg}", file=sys.stderr)
            sys.stderr.flush()
            error_result = {"status": "1", "status_msg": f"Execution Error: {error_msg}"}
            return False, error_result

    def run_single_test(self, container_id_src, dst_ip, protocol, dst_port, container_id_dest):
        """
        Runs a single client test inside a container and returns the result.

        Args:
            container_id_src (str): The ID of the source container.
            dst_ip (str): The destination IP address or hostname.
            protocol (str): The protocol to use (TCP, UDP, ICMP).
            dst_port (str): The destination port.
            container_id_dest: The ID of the destination container

        Returns:
            tuple: A tuple containing a boolean for success and a dictionary
                   with the test result.
        """
        processed_dst_ip = self._extract_destination_host(dst_ip)
        if not processed_dst_ip:
            error_result = {"status": "1", "status_msg": f"Invalid destination: {dst_ip}"}
            print(f"Invalid destiny: {dst_ip}", file=sys.stderr)
            sys.stderr.flush()
            return False, error_result

        if(protocol.lower() != 'icmp'):
            is_port_open = self._list_open_ports(dst_port,protocol, container_id_dest)
            if not is_port_open:
                result_dict_warn = {
                    "status": "warning",
                    "status_msg": "port is not open on destination container"
                }
                return False, result_dict_warn

        command = [
            "docker", "exec", container_id_src,
            "python3",
            # "/firewallTester/src/client.py",
            "core/client.py",
            processed_dst_ip,
            protocol.lower(),
            dst_port,
            "1", "2025", "0" 
        ]
        
        try:
            result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', timeout=10)
            
            
            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, command, stderr=result.stderr)
                
            if not result.stdout:
                raise json.JSONDecodeError("The script output was empty.", "", 0)

            result_dict = json.loads(result.stdout)
            return True, result_dict

        except Exception as e:
            error_msg = str(e)
            if hasattr(e, 'stderr') and e.stderr:
                error_msg = e.stderr.strip()
            
            print(f"Error TestRunner: {error_msg}", file=sys.stderr)
            sys.stderr.flush()
            error_result = {"status": "1", "status_msg": f"Execution Error: {error_msg}"}
            return False, error_result


    def analyze_test_result(self, expected_result, test_output):
        """
        Analyzes the output of a test to determine if it passed or failed.

        Args:
            expected_result (str): The expected outcome ('yes' for pass, 'no' for fail).
            test_output (dict): The JSON output from the client test script.

        Returns:
            tuple: A tuple containing a dictionary with analysis details
                   (result, flow, data) and a tag for UI color-coding.
        """
        expected = expected_result.lower()

        if test_output.get("status", "1") != '0':
            result_status = "ERROR"
            network_flow = "Not Sent"
            tag = "error"

        elif test_output.get("server_response"):
            network_flow = "Sent/Received"
            if expected in ["yes", "permitido"]:
                result_status = "Pass"
                tag = "yes"
            else:
                result_status = "Fail"
                tag = "no" 

        elif not test_output.get("server_response"):
            network_flow = "Sent"
            if expected in ["no", "bloqueado"]:
                result_status = "Pass"
                tag = "yesFail"
            else:
                result_status = "Fail"
                tag = "no"

        if "dnat" in test_output:
            network_flow += " (DNAT)"

        return {"result": result_status, "flow": network_flow, "data": str(test_output)}, tag
    def _extract_destination_host(self, destination):
        if ip_match := re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', destination):
            return ip_match[1]
        regex_ip = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        regex_domain = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(regex_ip, destination) or re.match(regex_domain, destination):
            return destination

        return None