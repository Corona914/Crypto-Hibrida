import hashlib

def sign_raw_rsa(data_bytes, d, n):
    """Firma el hash de los datos utilizando el exponente privado d"""
    h = hashlib.sha256(data_bytes).digest()
    h_int = int.from_bytes(h, byteorder='big')
    signature_int = pow(h_int, d, n)
    return str(signature_int)

def verify_raw_rsa(data_bytes, signature_str, e, n):
    """Verifica si la firma coincide con el hash de los datos enviados"""
    h = hashlib.sha256(data_bytes).digest()
    h_int = int.from_bytes(h, byteorder='big')
    try:
        signature_int = int(signature_str)
        return pow(signature_int, e, n) == h_int
    except Exception:
        return False