from flask import Flask, render_template_string, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64
import os

app = Flask(__name__)

# ==========================================
# PARÁMETROS GLOBALES DIFFIE-HELLMAN
# ==========================================
DH_G = 5
DH_N = 23  

# ==========================================
# FUNCIONES CRIPTOGRÁFICAS
# ==========================================
def dh_exchange(base, secret, mod):
    return pow(base, secret, mod)

def derive_aes_params(secret_k, secret_iv):
    key = hashlib.sha256(str(secret_k).encode()).digest()
    iv = hashlib.sha256(str(secret_iv).encode()).digest()[:16]
    return key, iv

def encrypt_aes_cbc(data_bytes, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_aes_cbc(ciphertext_b64, key, iv):
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(ciphertext)
    return unpad(padded_data, AES.block_size)

def sign_raw_rsa(data_bytes, d, n):
    h = hashlib.sha256(data_bytes).digest()
    h_int = int.from_bytes(h, byteorder='big')
    signature_int = pow(h_int, d, n)
    return str(signature_int)

def verify_raw_rsa(data_bytes, signature_str, e, n):
    h = hashlib.sha256(data_bytes).digest()
    h_int = int.from_bytes(h, byteorder='big')
    try:
        signature_int = int(signature_str)
        return pow(signature_int, e, n) == h_int
    except Exception:
        return False

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
            return ".bin" # Archivo binario desconocido

# ==========================================
# INTERFAZ GRÁFICA (HTML + Tailwind)
# ==========================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Criptografía Híbrida</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-100 min-h-screen p-8 font-sans">
    <div class="max-w-6xl mx-auto bg-white p-8 rounded-xl shadow-lg border border-slate-200">
        <h1 class="text-3xl font-bold text-slate-800 text-center mb-8">Práctica: Criptografía Híbrida</h1>

        {% if error %}
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-6">
            <strong class="font-bold">Error:</strong> <span class="block sm:inline">{{ error }}</span>
        </div>
        {% endif %}
        
        {% if success_msg %}
        <div class="bg-blue-100 border border-blue-400 text-blue-700 px-4 py-3 rounded relative mb-6">
            <strong class="font-bold">¡Éxito!</strong> <span class="block sm:inline">{{ success_msg }}</span>
        </div>
        {% endif %}

        <form method="POST" enctype="multipart/form-data" class="grid grid-cols-1 md:grid-cols-2 gap-8">
            
            <!-- ALICIA (EMISOR) -->
            <div class="bg-blue-50 p-6 rounded-lg border border-blue-200 shadow-sm">
                <h2 class="text-xl font-semibold text-blue-800 mb-4 border-b border-blue-200 pb-2">👩‍💻 Alicia (Emisor)</h2>
                
                <div class="mb-4 bg-white p-4 rounded border">
                    <label class="block text-sm font-bold text-slate-800 mb-2">1. ¿Qué deseas enviar?</label>
                    <textarea name="message" rows="2" class="w-full p-2 border rounded-md mb-2 text-sm" placeholder="Escribe un mensaje aquí..."></textarea>
                    <input type="file" name="file_to_encrypt" class="w-full text-sm text-slate-500 file:mr-4 file:py-1 file:px-2 file:rounded file:border-0 file:text-xs file:bg-blue-50 file:text-blue-700">
                </div>

                <div class="mb-4 bg-white p-4 rounded border">
                    <label class="block text-sm font-bold text-slate-800 mb-2">2. Servicios a aplicar</label>
                    <div class="flex items-center mb-3 border-b pb-2">
                        <input type="checkbox" name="apply_encryption" id="apply_encryption" class="mr-2 h-4 w-4" checked readonly onclick="return false;">
                        <label for="apply_encryption" class="text-sm font-semibold">Cifrado de Datos (AES-CBC)</label>
                    </div>
                    <div class="flex items-start">
                        <input type="checkbox" name="apply_signature" id="apply_signature" class="mr-2 mt-1 h-4 w-4">
                        <div class="w-full">
                            <label for="apply_signature" class="text-sm font-semibold block mb-1">Añadir Firma Digital (RSA)</label>
                            <input type="file" name="alice_priv_key" accept=".txt" class="w-full text-xs text-slate-500 file:mr-2 file:py-1 file:px-2 file:rounded file:border-0 file:bg-red-50 file:text-red-700">
                        </div>
                    </div>
                </div>
                
                <div class="bg-white p-4 rounded border mb-4">
                    <h3 class="text-sm font-bold text-slate-800 mb-2">3. Secretos Diffie-Hellman (Alicia)</h3>
                    <div class="grid grid-cols-2 gap-2">
                        <div>
                            <label class="text-xs text-slate-500">Secreto 'a'</label>
                            <input type="number" name="alice_a" value="6" class="w-full p-1 border rounded text-sm bg-slate-50">
                        </div>
                        <div>
                            <label class="text-xs text-slate-500">Secreto 'c'</label>
                            <input type="number" name="alice_c" value="8" class="w-full p-1 border rounded text-sm bg-slate-50">
                        </div>
                    </div>
                </div>

                <button type="submit" name="action" value="alicia_process" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-4 rounded transition shadow-md">
                    Exportar Archivo (mensaje_salida.txt)
                </button>
            </div>

            <!-- BETITO (RECEPTOR) -->
            <div class="bg-green-50 p-6 rounded-lg border border-green-200 shadow-sm">
                <h2 class="text-xl font-semibold text-green-800 mb-4 border-b border-green-200 pb-2">🧑‍💻 Betito (Receptor)</h2>
                
                <div class="bg-white p-4 rounded border mb-4">
                    <h3 class="text-sm font-bold text-slate-800 mb-2">Secretos Diffie-Hellman (Betito)</h3>
                    <div class="grid grid-cols-2 gap-2">
                        <div>
                            <label class="text-xs text-slate-500">Secreto 'b'</label>
                            <input type="number" name="betito_b" value="15" class="w-full p-1 border rounded text-sm bg-slate-50">
                        </div>
                        <div>
                            <label class="text-xs text-slate-500">Secreto 'd'</label>
                            <input type="number" name="betito_d" value="7" class="w-full p-1 border rounded text-sm bg-slate-50">
                        </div>
                    </div>
                </div>

                <div class="mb-4 bg-white p-4 rounded border space-y-3">
                    <label class="block text-sm font-bold text-slate-800 mb-1">Archivos Recibidos</label>
                    
                    <div>
                        <p class="text-xs text-slate-500 font-semibold mb-1">1. Sube el paquete recibido (mensaje_salida.txt)</p>
                        <input type="file" name="archivo_recibido" accept=".txt" class="w-full text-sm text-slate-500 file:mr-4 file:py-1 file:px-2 file:rounded file:border-0 file:text-xs file:bg-green-50 file:text-green-700">
                    </div>

                    <div class="border-t pt-2">
                        <p class="text-xs text-slate-500 font-semibold mb-1">2. Llave Pública de Alicia (.txt) [Solo si incluyó firma]</p>
                        <input type="file" name="friend_pub_key" accept=".txt" class="w-full text-sm text-slate-500 file:mr-4 file:py-1 file:px-2 file:rounded file:border-0 file:text-xs file:bg-green-50 file:text-green-700">
                    </div>
                </div>

                <button type="submit" name="action" value="betito_process" class="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-3 px-4 rounded transition shadow-md">
                    Descifrar / Verificar Archivo
                </button>

                {% if results %}
                    <div class="mt-6 p-4 bg-white border-2 border-green-300 rounded-lg shadow-inner">
                        <h3 class="font-bold text-green-800 mb-3 border-b pb-1">Resultados de la Recepción:</h3>
                        
                        <div class="space-y-3 text-sm mb-4">
                            {% if results.ciphertext_status %}
                            <div class="flex items-center bg-slate-50 p-2 rounded border">
                                <span class="mr-2 text-lg">🔓</span> 
                                <div>
                                    <p class="font-semibold text-slate-700">Descifrado AES:</p>
                                    <p class="text-green-600 font-bold">{{ results.ciphertext_status }}</p>
                                </div>
                            </div>
                            {% endif %}
                            
                            {% if results.signature_status %}
                            <div class="flex items-center bg-slate-50 p-2 rounded border">
                                <span class="mr-2 text-lg">✍️</span> 
                                <div>
                                    <p class="font-semibold text-slate-700">Verificación de Firma:</p>
                                    <p class="font-bold {{ 'text-green-600' if 'Válida' in results.signature_status else 'text-red-600' }}">
                                        {{ results.signature_status }}
                                    </p>
                                </div>
                            </div>
                            {% endif %}
                        </div>

                        <div>
                            <span class="text-sm font-bold text-slate-700">Contenido Recuperado:</span>
                            <div class="mt-1 p-3 bg-slate-800 text-green-400 font-mono text-xs rounded overflow-auto max-h-40 break-words">
                                {{ results.decrypted_preview }}
                            </div>
                            
                            <!-- BOTÓN DE DESCARGA -->
                            {% if results.download_b64 %}
                            <div class="mt-4 pt-3 border-t border-slate-600">
                                <a href="data:application/octet-stream;base64,{{ results.download_b64 }}" download="archivo_recuperado{{ results.download_ext }}" class="inline-flex items-center bg-green-500 hover:bg-green-600 text-white font-bold py-2 px-4 rounded transition">
                                    ⬇️ Descargar Archivo Completo
                                </a>
                                <p class="text-[10px] text-slate-400 mt-1">Si el formato es desconocido, puedes renombrarlo y ponerle su extensión manual (ej. .pdf o .docx).</p>
                            </div>
                            {% endif %}
                        </div>
                    </div>
                {% endif %}
            </div>
        </form>
    </div>
</body>
</html>
"""

# ==========================================
# RUTAS FLASK
# ==========================================
@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    error = None
    success_msg = None

    if request.method == "POST":
        action = request.form.get("action")
        
        a = int(request.form.get("alice_a", 6))
        c = int(request.form.get("alice_c", 8))
        b = int(request.form.get("betito_b", 15))
        d = int(request.form.get("betito_d", 7))

        Ka_public = dh_exchange(DH_G, a, DH_N)
        Kc_public = dh_exchange(DH_G, c, DH_N)
        Kb_public = dh_exchange(DH_G, b, DH_N)
        Kd_public = dh_exchange(DH_G, d, DH_N)

        alice_aes_key, alice_aes_iv = derive_aes_params(dh_exchange(Kb_public, a, DH_N), dh_exchange(Kd_public, c, DH_N))
        betito_aes_key, betito_aes_iv = derive_aes_params(dh_exchange(Ka_public, b, DH_N), dh_exchange(Kc_public, d, DH_N))

        try:
            # ==============================================
            # ACCIÓN: ALICIA (Generar y guardar archivo único)
            # ==============================================
            if action == "alicia_process":
                data_bytes = b""
                uploaded_file = request.files.get("file_to_encrypt")
                
                if uploaded_file and uploaded_file.filename != '':
                    data_bytes = uploaded_file.read()
                else:
                    message = request.form.get("message", "")
                    if not message:
                        raise ValueError("Alicia debe ingresar un mensaje o subir un archivo.")
                    data_bytes = message.encode('utf-8')

                apply_signature = request.form.get("apply_signature") == "on"
                
                ciphertext = encrypt_aes_cbc(data_bytes, alice_aes_key, alice_aes_iv)
                output_content = ciphertext

                if apply_signature:
                    alice_key_file = request.files.get("alice_priv_key")
                    if not alice_key_file or alice_key_file.filename == '':
                        raise ValueError("Seleccionaste firmar, pero no subiste tu archivo privada.txt")
                    
                    content = alice_key_file.read().decode('utf-8').splitlines()
                    lines = [line.strip() for line in content if line.strip()]
                    priv_d, priv_n = int(lines[0]), int(lines[1])
                    
                    signature = sign_raw_rsa(data_bytes, priv_d, priv_n)
                    output_content += "\n" + signature

                with open("mensaje_salida.txt", "w") as f:
                    f.write(output_content)

                if apply_signature:
                    success_msg = "Se generó 'mensaje_salida.txt' (Contiene cifrado y firma)."
                else:
                    success_msg = "Se generó 'mensaje_salida.txt' (Contiene solo cifrado)."

            # ==============================================
            # ACCIÓN: BETITO (Leer archivo único y descifrar)
            # ==============================================
            elif action == "betito_process":
                results = {}
                archivo_recibido = request.files.get("archivo_recibido")
                
                if not archivo_recibido or archivo_recibido.filename == '':
                    raise ValueError("Betito debe subir un archivo .txt para operar.")
                
                content = archivo_recibido.read().decode('utf-8').strip().split('\n')
                ciphertext_b64 = content[0].strip()
                firma_str = content[1].strip() if len(content) > 1 else None

                # Betito Descifra
                try:
                    decrypted_bytes = decrypt_aes_cbc(ciphertext_b64, betito_aes_key, betito_aes_iv)
                    results['ciphertext_status'] = "¡Datos recuperados con éxito!"
                except Exception:
                    raise ValueError("Error al descifrar. ¿Los secretos de Diffie-Hellman coinciden?")

                # Previsualización en pantalla
                try:
                    preview = decrypted_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    preview = f"[Archivo Binario Detectado] - {len(decrypted_bytes)} bytes."
                results['decrypted_preview'] = preview[:500] + ("..." if len(preview) > 500 else "")

                # NUEVO: Preparar los bytes descifrados para la descarga web
                results['download_b64'] = base64.b64encode(decrypted_bytes).decode('utf-8')
                results['download_ext'] = detectar_extension(decrypted_bytes)

                # Betito Verifica Firma
                if firma_str:
                    friend_key_file = request.files.get("friend_pub_key")
                    
                    if not friend_key_file or friend_key_file.filename == '':
                        results['signature_status'] = "El archivo contenía una firma, pero no subiste la llave pública de Alicia para verificarla. ⚠️"
                    else:
                        pub_content = friend_key_file.read().decode('utf-8').splitlines()
                        pub_lines = [line.strip() for line in pub_content if line.strip()]
                        val1, val2 = int(pub_lines[0]), int(pub_lines[1])
                        n_amigo, e_amigo = max(val1, val2), min(val1, val2)
                        
                        is_valid = verify_raw_rsa(decrypted_bytes, firma_str, e_amigo, n_amigo)
                        results['signature_status'] = "Válida ✅" if is_valid else "Inválida ❌"
                else:
                    results['signature_status'] = "El mensaje no venía firmado."

        except Exception as e:
            error = str(e)

    return render_template_string(HTML_TEMPLATE, results=results, error=error, success_msg=success_msg)

if __name__ == "__main__":
    app.run(debug=True, port=5000)

    