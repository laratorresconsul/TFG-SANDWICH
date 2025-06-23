# auth.py

# Autor/a: Lara Sofía Torres Cónsul

# 1. IMPORTS

import os
import json
import hashlib
import secrets
import logging
from datetime import datetime, timedelta

# 2. CONFIGURACIÓN GLOBAL

USERS_FILE = "users.json"
MAX_ATTEMPTS = 3
BLOQUEO_MINUTOS = 5

# 3. FUNCIONES DE GESTIÓN DE USUARIOS

def load_users():
    '''
    Carga los usuarios desde el archivo JSON.
    '''
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    '''
    Guarda los usuarios en el archivo JSON con indentación.
    '''
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

# 4. FUNCIONES DE SEGURIDAD

def is_password_valid(password):
    """
    Valida que tenga al menos 8 caracteres, una mayúscula y un número.
    """
    return (
        len(password) >= 8
        and any(c.isupper() for c in password)
        and any(c.isdigit() for c in password)
    )

def generate_salt():
    '''
    Genera un salt criptográficamente seguro de 16 bytes en hexadecimal.
    '''
    return secrets.token_hex(16)

def hash_password(password, salt):
    '''
    Devuelve el hash SHA256 de la contraseña + salt.
    '''
    return hashlib.sha256((password + salt).encode()).hexdigest()

# 5. FUNCIONES PRINCIPALES DE AUTENTICACIÓN

def register_user(username, password):
    '''
    Registra un nuevo usuario si la contraseña es válida.

    - Valida que la contraseña cumpla requisitos de seguridad.
    - Genera un salt aleatorio y guarda la contraseña hasheada.
    - Guarda la información del usuario en disco.

    Parámetros:
    - username (str): nombre de usuario único.
    - password (str): contraseña proporcionada por el usuario.

    Return:
    - "exito" si se ha registrado correctamente.
    - "password_invalida" si la contraseña no cumple requisitos.
    - "error" si ocurre otro problema al guardar.
    '''
    users = load_users()

    # Verificar si el usuario ya existe
    if username in users:
        return "usuario_duplicado"

    # Validar la contraseña
    if not is_password_valid(password):
        return "password_invalida"

    # Generar un salt y cifrar la contraseña
    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    # Registro exitoso, se guarda:
    users[username] = {
        "salt": salt,
        "password": hashed_password,
        "attempts": 0,
        "last_attempt": None
    }

    # Solo mostrar mensaje si el usuario se guarda correctamente
    save_users(users)
    return "exito"

def verify_login(username, password):
    '''
    Verifica si las credenciales coinciden con el usuario almacenado.
    '''
    users = load_users()
    if username not in users:
        return False

    salt = users[username]["salt"]
    stored_hash = users[username]["password"]
    return stored_hash == hash_password(password, salt)

def login_user(username, password):
    """
    Autenticar a un usuario.

    Argumentos:
        username (string): El nombre de usuario que intenta iniciar sesión.
        password (string): La contraseña del usuario.

    Devuelve:
        (True, None): login correcto
        (False, intentos_restantes): contraseña incorrecta
        (False, "no_existe"): usuario no encontrado
        (False, "bloqueado"): usuario bloqueado temporalmente
    """
    users = load_users()

    # Verificar si el usuario existe
    if username not in users:
        return False, "no_existe"

    user = users[username]

    # Gestión de bloqueo
    if user["attempts"] >= MAX_ATTEMPTS:
        last = user.get("last_attempt")
        if last:
            last_time = datetime.fromisoformat(last)
            if datetime.now() - last_time < timedelta(minutes=BLOQUEO_MINUTOS):
                return False, "bloqueado"
            else:
                user["attempts"] = 0
                user["last_attempt"] = None
        else:
            user["last_attempt"] = datetime.now().isoformat()
            save_users(users)
            return False, "bloqueado"

    # Verificar si la contraseña coincide con la almacenada
    hashed = hash_password(password, user["salt"])

    if hashed == user["password"]:
        user["attempts"] = 0
        user["last_attempt"] = None
        save_users(users)
        return True, None
    else:
        # Incrementar el contador de intentos fallidos
        user["attempts"] += 1
        user["last_attempt"] = datetime.now().isoformat()
        save_users(users)

        if user["attempts"] >= MAX_ATTEMPTS:
            return False, "bloqueado"
        else:
            intentos_restantes = MAX_ATTEMPTS - user["attempts"]
            return False, intentos_restantes
