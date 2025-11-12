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

# Disabling insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class InputSchema(BaseModel):
    endpoints: list = Field(
        ...,
        description='The URLs of the endpoint whose SSL certificate is to be checked. Eg: ["https://www.google.com", "https://expired.badssl.com/"]',
        title='List of URLs'
    )
    threshold: Optional[int] = Field(
        30,
        description='The number of days within which, if the certificate is set to expire is considered a potential issue.',
        title='SSL Expiry Threshold'
    )


def k8s_check_service_status_printer(output):
    print('Test: k8s_check_service_status_printer function')
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
        print(f"Status: {result['status']}\n")
        print("=" * 100)


from OpenSSL import crypto  # make sure pyOpenSSL is installed: pip install pyOpenSSL

def check_ssl_expiry(endpoint, threshold, allow_unverified=False):
    print('Test: check_ssl_expiry function (no CA check, using pyOpenSSL)')
    hostname = endpoint.split("//")[-1].split("/")[0]

    try:
        context = ssl._create_unverified_context()

        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                # Fetch binary (DER) certificate data
                der_cert = ssl_sock.getpeercert(binary_form=True)

        # Load it with OpenSSL
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)

        # Extract the notAfter field (bytes → string → datetime)
        not_after_str = x509.get_notAfter().decode("ascii")
        expiry_date = datetime.strptime(not_after_str, "%Y%m%d%H%M%SZ").date()
        days_remaining = (expiry_date - datetime.utcnow().date()).days

        print(f"✅ SSL certificate for {hostname} expires on {expiry_date} ({days_remaining} days remaining)")

        if days_remaining <= threshold:
            return (days_remaining, False)
        else:
            return (days_remaining, True)

    except Exception as e:
        print(f"❌ Error while fetching SSL expiry: {e}")
        raise e

def k8s_check_service_status(handle, endpoints: list, threshold: int = 30) -> Tuple:
    """
    k8s_check_service_status
    Checks the health status of the provided endpoints.

    :param endpoints: The URLs of the endpoint whose SSL certificate is to be checked.
    :param threshold: The number of days within which if the certificate expires is an issue.
    :return: Tuple (Boolean, List of service status details)
    """

    failed_endpoints = []

    for endpoint in endpoints:
        status_info = {"endpoint": endpoint}

        # HTTPS Endpoint
        if endpoint.startswith("https://"):
            try:
                # Try with standard certificate validation
                requests.get(endpoint, verify=True, timeout=5)
                days_remaining, is_healthy = check_ssl_expiry(endpoint, threshold)

            except requests.exceptions.SSLError as ssl_err:
                # Retry unverified if cert is self-signed or not trusted
                if "CERTIFICATE_VERIFY_FAILED" in str(ssl_err):
                    try:
                        requests.get(endpoint, verify=False, timeout=5)
                        days_remaining, is_healthy = check_ssl_expiry(endpoint, threshold, allow_unverified=True)
                    except Exception as e:
                        status_info["status"] = 'unhealthy'
                        status_info["Reason"] = f'SSL error after skipping validation: {str(e)}'
                        failed_endpoints.append(status_info)
                        continue
                else:
                    status_info["status"] = 'unhealthy'
                    status_info["Reason"] = f'SSL error: {str(ssl_err)}'
                    failed_endpoints.append(status_info)
                    continue

        # HTTP / Non-HTTPS
        else:
            try:
                response = requests.get(endpoint, timeout=5)
                if response.status_code != 200:
                    status_info["status"] = 'unhealthy'
                    status_info["Reason"] = f'Status code: {response.status_code}'
                    failed_endpoints.append(status_info)
                    continue
                else:
                    continue
            except requests.RequestException as e:
                status_info["status"] = 'unhealthy'
                status_info["Reason"] = f'Error: {str(e)}'
                failed_endpoints.append(status_info)
                continue

        # SSL expiry health status evaluation
        if not is_healthy:
            status_info["status"] = 'unhealthy'
            status_info["Reason"] = f'SSL certificate expiring in {days_remaining} days'
            failed_endpoints.append(status_info)

    if failed_endpoints:
        return (False, failed_endpoints)
    else:
        return (True, None)


