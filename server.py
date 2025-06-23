# server.py

# Autor/a: Lara Sofía Torres Cónsul
# Inspirado en el trabajo de SandboxAQ: Copyright (c) SandboxAQ. All rights reserved. SPDX-License-Identifier: AGPL-3.0-only


# 1.IMPORTS

import logging
import sys

from pysandwich.proto.api.v1 import (
    compliance_pb2 as Compliance,
    configuration_pb2 as SandwichTunnelProto,
    encoding_format_pb2 as EncodingFormat,
    listener_configuration_pb2 as ListenerAPI,
    verifiers_pb2 as SandwichVerifiers,
    tunnel_pb2
)

import pysandwich.io_helpers as SandwichIOHelpers
import pysandwich.tunnel as SandwichTunnel
import pysandwich.errors as SandwichErrors
from pysandwich import listener as SandwichListener
from pysandwich.sandwich import Sandwich
from pysandwich.proto.api.v1.tunnel_pb2 import TunnelConfiguration

from auth import (
    load_users,
    login_user,
    save_users,
    is_password_valid,
    generate_salt,
    hash_password,
    register_user,
    verify_login
)

from google.protobuf.wrappers_pb2 import BytesValue

# 2.CONFIGURACIONES GLOBALES

# Configuración de logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.handlers.clear()  # Limpia handlers previos si los hubiera

# Log en archivo
file_handler = logging.FileHandler("server.log", mode='a', encoding='utf-8')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# Log en consola (stderr)
console_handler = logging.StreamHandler(stream=sys.stderr)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(console_handler)

# Diccionario global de sesiones activas
sesiones_activas = {}

# Objeto Sandwich principal
sw = Sandwich()

# 3. FUNCIONES AUXILIARES

# configurar_tls_servidor

def configurar_tls_servidor(cert_path: str, key_path: str) -> SandwichTunnelProto:
    '''
    Configuración TLS para el servidor Sandwich.

    Parámetros:
    - cert_path: ruta al certificado público
    - key_path: ruta a la clave privada

    Return: objeto Configuration para contexto TLS
    '''
    conf = SandwichTunnelProto.Configuration()
    conf.impl = SandwichTunnelProto.IMPL_BORINGSSL_OQS

    # TLS 1.3
    tls13 = conf.server.tls.common_options.tls13
    tls13.ke.extend(["p256_kyber512", "prime256v1"])
    tls13.compliance.classical_choice = Compliance.CLASSICAL_ALGORITHMS_ALLOW

    # TLS 1.2
    tls12 = conf.server.tls.common_options.tls12
    ciphers = [
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
    ]
    tls12.ciphersuite.extend(ciphers)

    conf.server.tls.common_options.empty_verifier.CopyFrom(
        SandwichVerifiers.EmptyVerifier()
    )
    conf.server.tls.common_options.identity.certificate.static.data.filename = cert_path
    conf.server.tls.common_options.identity.certificate.static.format = (
        EncodingFormat.ENCODING_FORMAT_PEM
    )

    conf.server.tls.common_options.identity.private_key.static.data.filename = key_path
    conf.server.tls.common_options.identity.private_key.static.format = (
        EncodingFormat.ENCODING_FORMAT_PEM
    )

    return conf

# configurar_tunel_autenticacion
def configurar_tunel_autenticacion(cert_path: str) -> TunnelConfiguration:
    '''
    Configuración básica para el túnel Sandwich sin verificadores personalizados.
    '''

    tun_conf = TunnelConfiguration()

    with open(cert_path, "rb") as f:
        cert_bytes = f.read()

    tun_conf.verifier.empty_verifier.CopyFrom(SandwichVerifiers.EmptyVerifier())

    return tun_conf

# crear_socket_escucha_tcp
def crear_socket_escucha_tcp(hostname: str, port: int) -> SandwichListener.Listener:
    '''
    Crea y devuelve un Listener configurado para escuchar en host:puerto.
    '''
    conf = ListenerAPI.ListenerConfiguration()
    conf.tcp.addr.hostname = hostname
    conf.tcp.addr.port = port
    conf.tcp.blocking_mode = ListenerAPI.BLOCKINGMODE_BLOCKING

    return SandwichListener.Listener(conf)

# 4. COMUNICACIÓN CLIENTE-SERVIDOR

# manejar_cliente_conectado
def manejar_cliente_conectado(server_ctx_conf, swio: SandwichIOHelpers.SwTunnelIOWrapper, cert_path: str):
    '''
    Comunicación con un cliente: procesamiento de comandos, gestión de sesiones.

    Parámetros:
    - server_ctx_conf: contexto TLS configurado
    - swio: objeto SwTunnelIOWrapper para E/S segura
    '''
    server_tun_conf = configurar_tunel_autenticacion(cert_path)
    server = SandwichTunnel.Tunnel(server_ctx_conf, swio, server_tun_conf)

    server.handshake()
    logger.info("Servidor TLS iniciado y esperando conexiones...")
    state = server.state()
    assert (
        state == server.State.STATE_HANDSHAKE_DONE
    ), f"Expected state HANDSHAKE_DONE, got {state}"

    while True:
        try:
            data = b""
            while True:
                c = server.read(1)
                if not c:
                    raise SandwichErrors.RecordPlaneClosedException()
                data += c
                if c == b"\n":
                    break
        except SandwichErrors.RecordPlaneClosedException:
            logger.info("Cliente desconectado.")
            break

        mensaje = data.decode().strip()

        #REGISTRO

        #Validar username
        if mensaje.startswith("CHECK_USERNAME|"):
            username = mensaje.split("|", 1)[1]
            users = load_users()
            if username in users:
                logger.info("Entrando en rama de usuario duplicado")  # depuración
                server.write(b"USUARIO_DUPLICADO\n")
                logger.warning(f"Intento de registro con usuario ya existente: '{username}'")

            else:
                sesiones_activas[server] = username  # Guarda el usuario temporalmente
                server.write(b"OK\n")

        #Validar password
        elif mensaje.startswith("CHECK_PASSWORD|"):
            password = mensaje.split("|", 1)[1]
            username = sesiones_activas.get(server)  # obtener username activo
            if not username:
                server.write(b"NO_USERNAME\n")
                continue
            try:
                resultado = register_user(username, password)
            except Exception as e:
                logger.error(f"Error al registrar usuario: {e}")
                server.write(b"ERROR_REGISTRO\n")
                continue

            if resultado == "exito":
                logger.info(f"Usuario '{username}' registrado exitosamente.")
                server.write(b"REGISTRO_OK\n")
            elif resultado == "password_invalida":
                server.write(b"PASSWORD_INVALIDA\n")
                logger.warning(f"Contraseña inválida durante registro para usuario '{username}'")

            else:
                server.write(b"ERROR_REGISTRO\n")


        #LOGIN

        elif mensaje.startswith("LOGIN|"):
            try:
                _, username, password = mensaje.split("|", 2)
            except ValueError:
                server.write(b"ERROR_LOGIN_FORMAT\n")
                continue

            resultado, estado = login_user(username, password)

            #Validar username y password
            if resultado:
                sesiones_activas[server] = username  # guardar sesion activa
                logger.info(f"Usuario '{username}' ha iniciado sesión correctamente.")
                server.write(b"LOGIN_OK\n")
            elif estado == "no_existe":
                server.write(b"NO_EXISTE\n")
                logger.warning(f"Intento de login para usuario inexistente '{username}'")
            elif estado == "bloqueado":
                server.write(b"BLOQUEADO\n")
                logger.warning(f"Intento de login bloqueado para usuario '{username}'")
            elif isinstance(estado, int):
                server.write(f"INTENTOS_RESTANTES|{estado}\n".encode())
            else:
                server.write(b"ERROR_LOGIN\n")

        # SALIDA SISTEMA
        elif mensaje == "EXIT":
            logger.info("Cliente ha salido del sistema voluntariamente.")
            break

        # CONSULTAR USERNAME
        elif mensaje == "CONSULTAR_USERNAME":
            username = sesiones_activas.get(server)  # usar sesiones activas
            if username:
                server.write(f"USERNAME|{username}\n".encode())
            else:
                server.write(b"NO_SESION_ACTIVA\n")

        # ELIMINAR CUENTA
        elif mensaje == "ELIMINAR_CUENTA":
            username = sesiones_activas.get(server)  # usar sesiones activas
            if username:
                users = load_users()
                if username in users:
                    del users[username]
                    save_users(users)
                    del sesiones_activas[server]  # eliminar sesion
                    logger.warning(f"Usuario '{username}' eliminado del sistema.")
                    server.write(b"CUENTA_ELIMINADA_OK\n")
                else:
                    server.write(b"ERROR_USUARIO_NO_ENCONTRADO\n")
            else:
                server.write(b"NO_SESION_ACTIVA\n")

        # CAMBIAR CONTRASEÑA
        elif mensaje.startswith("CAMBIAR_PASSWORD|"):
            partes = mensaje.split("|", 2)
            if len(partes) != 3:
                server.write(b"ERROR_FORMATO\n")
                logger.error("Formato inválido en comando CAMBIAR_PASSWORD")
                continue

            actual, nueva = partes[1], partes[2]
            username = sesiones_activas.get(server)
            if not username:
                server.write(b"NO_SESION_ACTIVA\n")
                continue

            users = load_users()
            user_info = users.get(username)

            if not user_info:
                server.write(b"ERROR_USUARIO\n")
                continue

            # Verificar que la contraseña actual sea correcta
            hashed_actual = hash_password(actual, user_info["salt"])

            if hashed_actual != user_info["password"]:
                server.write(b"PASSWORD_INCORRECTA\n")
                logger.warning(f"Contraseña actual incorrecta para usuario '{username}'")

                continue

            # Validar nueva contraseña
            if not is_password_valid(nueva):
                server.write(b"PASSWORD_INVALIDA\n")
                logger.warning(f"Nueva contraseña no cumple requisitos para usuario '{username}'")
                continue

            logger.info(f"Contraseña válida. Actualizando...")

            # Actualizar la contraseña
            nuevo_salt = generate_salt()
            nuevo_hash = hash_password(nueva, nuevo_salt)
            user_info["salt"] = nuevo_salt
            user_info["password"] = nuevo_hash
            save_users(users)

            logger.info(f"Contraseña actualizada correctamente para '{username}'")
            server.write(b"CAMBIO_OK\n")

        # ENVIAR DATOS
        elif mensaje.startswith("ENVIAR_DATO|"):
            username = sesiones_activas.get(server)  # usar sesiones activas
            mensaje_usuario = mensaje.split("|", 1)[1]
            if username:
                users = load_users()
                user_info = users.get(username, {})
                historial = user_info.get("mensajes", [])
                historial.append(mensaje_usuario)
                user_info["mensajes"] = historial
                users[username] = user_info
                save_users(users)
                logger.debug(f"Mensaje recibido de '{username}': {mensaje_usuario}")

            respuesta = f"RECIBIDO: {mensaje_usuario}\n"
            server.write(respuesta.encode())

        else:
            server.write(b"ERROR_COMANDO_DESCONOCIDO\n")

    # CAMBIO: limpiar sesión al finalizar
    sesiones_activas.pop(server, None)
    server.close()

# 5. MAIN

def main(hostname: str, port: int, cert: str, key: str):
    '''
    Ejecuta el servidor y acepta conexiones indefinidamente.

    Parámetros:
    - hostname: dirección IP/host local
    - port: puerto de escucha
    - cert: ruta al certificado
    - key: ruta a la clave privada
    '''
    server_ctx_conf = SandwichTunnel.Context.from_config(
        sw, configurar_tls_servidor(cert, key)
    )
    listener = crear_socket_escucha_tcp(hostname, port)
    listener.listen()

    while True:
        server_io = listener.accept()
        manejar_cliente_conectado(server_ctx_conf, server_io, cert)

# 6. ENTRADA DEL SCRIPT

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(prog="Echo TLS server using Sandwich")
    parser.add_argument("-p", "--port", type=int, help="Listening port", required=True)
    parser.add_argument("--host", type=str, help="Listening host", default="127.0.0.1")
    parser.add_argument(
        "-k", "--key", type=str, help="Path to the server private key", required=True
    )
    parser.add_argument(
        "-c",
        "--cert",
        type=str,
        help="Path to the server public certificate",
        required=True,
    )
    args = parser.parse_args()

    main(args.host, args.port, args.cert, args.key)
