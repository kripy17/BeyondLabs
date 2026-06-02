import socket
import ssl


def name_tuple_to_dict(name_tuple):
    result = {}

    for item in name_tuple:
        for key, value in item:
            result[key] = value

    return result


def get_ssl_certificate(hostname: str, port: int = 443) -> dict:
    try:
        context = ssl.create_default_context()

        with socket.create_connection((hostname, port), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()

        return {
            "subject": name_tuple_to_dict(cert.get("subject", [])),
            "issuer": name_tuple_to_dict(cert.get("issuer", [])),
            "version": cert.get("version"),
            "serial_number": cert.get("serialNumber"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "subject_alt_names": cert.get("subjectAltName", []),
        }

    except Exception as e:
        return {
            "error": str(e)
        }
