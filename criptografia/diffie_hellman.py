# Parámetros globales
DH_G = 5
DH_N = 23  

def dh_exchange(base, secret, mod):
    """Calcula la llave pública o el secreto compartido (base^secret mod mod)"""
    return pow(base, secret, mod)