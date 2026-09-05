def detectar_extension(data_bytes):
    """Analiza los Magic Bytes para sugerir una extensión al descargar"""
    if data_bytes.startswith(b'%PDF'):
        return ".pdf"
    elif data_bytes.startswith(b'\x89PNG'):
        return ".png"
    elif data_bytes.startswith(b'\xff\xd8\xff'):
        return ".jpg"
    else:
        try:
            data_bytes.decode('utf-8')
            return ".txt"
        except UnicodeDecodeError:
            return ".bin"