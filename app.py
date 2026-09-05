from flask import Flask, render_template, request
import base64
import secrets

# Importaciones modulares de tu propio código
from criptografia.diffie_hellman import dh_exchange, DH_G, DH_N
from criptografia.aes_cbc import derive_aes_params, encrypt_aes_cbc, decrypt_aes_cbc
from criptografia.rsa_math import sign_raw_rsa, verify_raw_rsa
from utils.archivos import detectar_extension

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    error = None
    success_msg = None

    if request.method == "POST":
        action = request.form.get("action")

        try:
            # ==============================================
            # ACCIÓN: ALICIA (Generar archivos)
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
                
                # --- SIMULACIÓN DE DIFFIE-HELLMAN ---
                a = secrets.randbelow(DH_N - 2) + 2
                c = secrets.randbelow(DH_N - 2) + 2
                b = secrets.randbelow(DH_N - 2) + 2
                d = secrets.randbelow(DH_N - 2) + 2

                Ka_public = dh_exchange(DH_G, a, DH_N)
                Kc_public = dh_exchange(DH_G, c, DH_N)
                Kb_public = dh_exchange(DH_G, b, DH_N)
                Kd_public = dh_exchange(DH_G, d, DH_N)

                alice_aes_key, alice_aes_iv = derive_aes_params(
                    dh_exchange(Kb_public, a, DH_N), 
                    dh_exchange(Kd_public, c, DH_N)
                )

                # Exportamos las llaves AES
                k_b64 = base64.b64encode(alice_aes_key).decode('utf-8')
                iv_b64 = base64.b64encode(alice_aes_iv).decode('utf-8')
                
                with open("parametros_aes.txt", "w") as f:
                    f.write(f"{k_b64}\n{iv_b64}")

                # Cifrado
                ciphertext = encrypt_aes_cbc(data_bytes, alice_aes_key, alice_aes_iv)
                output_content = ciphertext

                # Firma Digital
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

                success_msg = "¡Archivos listos!\n1. mensaje_salida.txt\n2. parametros_aes.txt"

            # ==============================================
            # ACCIÓN: BETITO (Leer archivos y descifrar)
            # ==============================================
            elif action == "betito_process":
                results = {}
                archivo_recibido = request.files.get("archivo_recibido")
                archivo_parametros = request.files.get("archivo_parametros")
                
                if not archivo_recibido or archivo_recibido.filename == '':
                    raise ValueError("Betito debe subir el archivo 'mensaje_salida.txt'.")
                    
                if not archivo_parametros or archivo_parametros.filename == '':
                    raise ValueError("Betito debe subir el archivo 'parametros_aes.txt' para obtener las llaves.")

                param_content = archivo_parametros.read().decode('utf-8').splitlines()
                if len(param_content) < 2:
                    raise ValueError("El archivo parametros_aes.txt está corrupto o incompleto.")
                    
                betito_aes_key = base64.b64decode(param_content[0].strip())
                betito_aes_iv = base64.b64decode(param_content[1].strip())
                
                content = archivo_recibido.read().decode('utf-8').strip().split('\n')
                ciphertext_b64 = content[0].strip()
                firma_str = content[1].strip() if len(content) > 1 else None

                # Descifrado AES
                try:
                    decrypted_bytes = decrypt_aes_cbc(ciphertext_b64, betito_aes_key, betito_aes_iv)
                    results['ciphertext_status'] = "¡Datos recuperados con éxito!"
                except Exception:
                    raise ValueError("Error al descifrar. El archivo de parámetros AES no coincide con el criptograma.")

                try:
                    preview = decrypted_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    preview = f"[Archivo Binario Detectado] - {len(decrypted_bytes)} bytes."
                results['decrypted_preview'] = preview[:500] + ("..." if len(preview) > 500 else "")

                results['download_b64'] = base64.b64encode(decrypted_bytes).decode('utf-8')
                results['download_ext'] = detectar_extension(decrypted_bytes)

                # Verificación de Firma RSA
                if firma_str:
                    friend_key_file = request.files.get("friend_pub_key")
                    
                    if not friend_key_file or friend_key_file.filename == '':
                        results['signature_status'] = "El archivo contenía una firma, pero no subiste la llave pública para verificarla. ⚠️"
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

    # Nota: render_template_string se cambió por render_template
    return render_template("index.html", results=results, error=error, success_msg=success_msg)

if __name__ == "__main__":
    app.run(debug=True, port=5000)