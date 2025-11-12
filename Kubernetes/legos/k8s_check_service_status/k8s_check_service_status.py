##
##  Copyright (c) 2023 unSkript, Inc
##  All rights reserved.
##
from typing import Tuple, Optional
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import requests
from pydantic import BaseModel, Field
from datetime import datetime
import ssl
import socket
from OpenSSL import crypto  # requires: pip install pyOpenSSL

# Disable insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class InputSchema(BaseModel):
    endpoints: list = Field(
        ...,
        description='List of endpoints to check. Example: ["https://www.google.com", "http://example.com"]',
        title='List of URLs'
    )
    threshold: Optional[int] = Field(
        30,
        description='Number of days before expiry to consider SSL certificate as at-risk.',
        title='SSL Expiry Threshold'
    )


def k8s_check_service_status_printer(output):
    status, results = output
    if status:
        print("All services are healthy.")
        return

    if "Error" in results[0]:
        print(f"Error: {results[0]['Error']}")
        return

    print("\n" + "=" * 100)
    for result in results:
        print(f"Service:\t{result['endpoint']}")
        print("-" * 100)
        print(f"Status: {result['status']}")
        if "Reason" in result:
            print(f"Reason: {result['Reason']}")
        print("=" * 100)


def check_ssl_expiry(endpoint: str, threshold: int) -> Tuple[int, bool]:
    """
    Check SSL certificate expiry date for a given endpoint.
    Works with self-signed and valid certificates using pyOpenSSL.
    """
    hostname = endpoint.split("//")[-1].split("/")[0]
    try:
        context = ssl._create_unverified_context()

        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                der_cert = ssl_sock.getpeercert(binary_form=True)

        # Decode certificate using OpenSSL
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)
        not_after_str = x509.get_notAfter().decode("ascii")
        expiry_date = datetime.strptime(not_after_str, "%Y%m%d%H%M%SZ").date()
        days_remaining = (expiry_date - datetime.utcnow().date()).days

        print(f"✅ SSL certificate for {hostname} expires on {expiry_date} ({days_remaining} days remaining)")

        return (days_remaining, days_remaining > threshold)

    except Exception as e:
        print(f"❌ Error while fetching SSL expiry for {hostname}: {e}")
        raise e


def k8s_check_service_status(handle, endpoints: list, threshold: int = 30) -> Tuple:
    """
    Checks both HTTP & HTTPS endpoints:
      - HTTPS: uses pyOpenSSL for expiry check (ignores CA verification)
      - HTTP: uses original status code logic
    """
    failed_endpoints = []

    for endpoint in endpoints:
        status_info = {"endpoint": endpoint}

        if endpoint.startswith("https://"):
            try:
                # Allow self-signed and unverified certs
                response = requests.get(endpoint, verify=False, timeout=5)
                days_remaining, is_healthy = check_ssl_expiry(endpoint, threshold)

                if not (response.status_code == 200 and is_healthy):
                    status_info["status"] = "unhealthy"
                    reason = (
                        f"SSL expiring in {days_remaining} days."
                        if not is_healthy
                        else f"Status code: {response.status_code}"
                    )
                    status_info["Reason"] = reason
                    failed_endpoints.append(status_info)

            except Exception as e:
                status_info["status"] = "unhealthy"
                status_info["Reason"] = f"HTTPS error: {str(e)}"
                failed_endpoints.append(status_info)

        else:
            # HTTP — keep your previous working logic
            try:
                response = requests.get(endpoint, timeout=5)
                if response.status_code != 200:
                    status_info["status"] = "unhealthy"
                    status_info["Reason"] = f"Status code: {response.status_code}"
                    failed_endpoints.append(status_info)
            except requests.RequestException as e:
                status_info["status"] = "unhealthy"
                status_info["Reason"] = f"Error: {str(e)}"
                failed_endpoints.append(status_info)

    if failed_endpoints:
        return (False, failed_endpoints)
    else:
        return (True, None)
