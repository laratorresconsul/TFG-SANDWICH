# client.py

# Autor/a: Lara Sofía Torres Cónsul
# Inspirado en el trabajo de SandboxAQ: Copyright (c) SandboxAQ. All rights reserved. SPDX-License-Identifier: AGPL-3.0-only

# 1. IMPORTS

import sys
import socket
import argparse
import getpass
from typing import BinaryIO
from multiprocessing.connection import Connection

from pysandwich.sandwich import Sandwich
import pysandwich.tunnel as SandwichTunnel
import pysandwich.io_helpers as SandwichIOHelpers
import pysandwich.errors as SandwichErrors
from pysandwich.proto.api.v1.tunnel_pb2 import TunnelConfiguration
from pysandwich.proto.api.v1 import tunnel_pb2, encoding_format_pb2 as EncodingFormat

from pysandwich.proto.api.v1 import (
    compliance_pb2 as Compliance,
    configuration_pb2 as SandwichTunnelProto,
    verifiers_pb2 as SandwichVerifiers,
)

# 2. FUNCIONES AUXILIARES INTERFAZ

def imprimir_bienvenida():
    print("\n" + "*" * 100)
    print("      Bienvenido/a al sistema seguro      ")
    print("*" * 100 + "\n")

def imprimir_separador(titulo=""):
    print("\n" + "-" * 100)
    if titulo:
        print(f" {titulo}")
        print("-" * 100)

def imprimir_opciones(opciones):
    for numero, descripcion in opciones.items():
        print(f"  {numero} - {descripcion}")
    print()

# 3. CONFIGURACIÓN TLS

#configurar_tls_cliente
def configurar_tls_cliente(tls: str, trusted_cert_path: str) -> SandwichTunnelProto.Configuration:
    '''
    Configuración TLS para el servidor Sandwich.

    Parámetros:
    - cert_path: ruta al certificado público
    - key_path: ruta a la clave privada

    Return: objeto Configuration para contexto TLS
    '''
    conf = SandwichTunnelProto.Configuration()
    conf.impl = SandwichTunnelProto.IMPL_BORINGSSL_OQS

    # Configuración TLS según versión
    match tls:
        case "tls13":
            tls13 = conf.client.tls.common_options.tls13
            tls13.ke.extend(["p256_kyber512", "prime256v1"])
            tls13.compliance.classical_choice = Compliance.CLASSICAL_ALGORITHMS_ALLOW
            tls13.ciphersuite.extend(["TLS_CHACHA20_POLY1305_SHA256"])
        case "tls12":
            tls12 = conf.client.tls.common_options.tls12
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
        case _:
            raise NotImplementedError("TLS version is not supported")

    # Cargar PEM del servidor
    with open(trusted_cert_path, "rb") as f:
        pem = f.read()

    # Construyo X509Verifier: certificado de confianza
    verifier = SandwichVerifiers.X509Verifier()
    cert = verifier.trusted_cas.add()
    cert.static.data.inline_bytes = pem
    cert.static.format = EncodingFormat.ENCODING_FORMAT_PEM

    # Aplicarlo al cliente
    conf.client.tls.common_options.x509_verifier.CopyFrom(verifier)

    return conf

def is_localhost(hostname: str):
    '''
    Comprueba si el host es localhost o una IP local.

    Return: True si es localhost, False en caso contrario
    '''
    try:
        # Get the IP address for the given hostname
        ip_address = socket.gethostbyname(hostname)

        # Check if the IP address is a localhost IP address
        return ip_address in ("127.0.0.1", "::1")
    except socket.gaierror:
        # If the hostname cannot be resolved, it's not localhost
        return False

# configurar_tunel_cliente
def configurar_tunel_cliente(hostname: str) -> TunnelConfiguration:
    '''
    Devuelve configuración básica para el túnel Sandwich sin verificadores personalizados.
    '''
    tun_conf = TunnelConfiguration()

    if not is_localhost(hostname):
        tun_conf.server_name_indication = hostname

        # Verificación del hostname mediante SANVerifier
        san_verifier = SandwichVerifiers.SANVerifier()
        san_verifier.alt_names.add(dns=hostname)
        tun_conf.verifier.san_verifier.CopyFrom(san_verifier)

    else:
        # Si es localhost, usar EmptyVerifier
        tun_conf.verifier.empty_verifier.CopyFrom(SandwichVerifiers.EmptyVerifier())

    return tun_conf


# 4. FUNCIONES ENCAPSULADAS: LOGIN Y LEER DEL SV

# PROCESO LOGIN
def proceso_login(client, client_io):
    '''
    Proceso completo de inicio de sesión con el servidor.
    Incluye submenú tras login exitoso.
    '''
    username = input("Nombre de usuario: ").strip()
    password = getpass.getpass("Contraseña: ").strip()
    mensaje_login = f"LOGIN|{username}|{password}\n".encode()

    client_io.setblocking(True)
    client.write(mensaje_login)
    client_io.setblocking(False)


    # LEER RESPUESTA DEL SERVIDOR
    respuesta_decodificada = leer_respuesta(client)


    # MENÚ POST-LOGIN
    if respuesta_decodificada == "LOGIN_OK":
        print("Inicio de sesión exitoso.")
        while True:
            imprimir_separador("Acciones disponibles")
            opciones_post = {
                "1": "Consultar username",
                "2": "Eliminar cuenta",
                "3": "Enviar datos",
                "4": "Cambiar contraseña",
                "5": "Cerrar sesión"
            }
            imprimir_opciones(opciones_post)
            subopcion = input("Opción: ").strip()

            # CONSULTAR USERNAME
            if subopcion == "1":
                client_io.setblocking(True)
                client.write(b"CONSULTAR_USERNAME\n")
                client_io.setblocking(False)
                respuesta = leer_respuesta(client)
                if respuesta.startswith("USERNAME|"):
                    print(f"Tu nombre de usuario es: {respuesta.split('|',1)[1]}")
                else:
                    print("[Servidor] Respuesta inesperada.")

            # ELIMINAR CUENTA
            elif subopcion == "2":
                confirmacion = input("¿Estás seguro de que deseas eliminar tu cuenta? (s/n): ").strip().lower()
                if confirmacion == "s":
                    client_io.setblocking(True)
                    client.write(b"ELIMINAR_CUENTA\n")
                    client_io.setblocking(False)

                    respuesta = leer_respuesta(client)
                    if respuesta == "CUENTA_ELIMINADA_OK":
                        print("Cuenta eliminada correctamente. Cerrando sesión...")
                    else:
                        print("Error al eliminar la cuenta. Inténtalo más tarde.")
                    client.close()
                    sys.exit(0)  # Finaliza el programa por completo

            # ENVIAR DATOS (chat continuo hasta que se escriba EXIT)
            elif subopcion == "3":
                print("Chat iniciado. Escribe tus mensajes. Escribe 'EXIT' para salir.")
                while True:
                    mensaje_usuario = input("Tú: ").strip()
                    if mensaje_usuario.upper() == "EXIT":
                        print("Saliendo del chat...")
                        break

                    mensaje = f"ENVIAR_DATO|{mensaje_usuario}\n".encode()

                    client_io.setblocking(True)
                    client.write(mensaje)
                    client_io.setblocking(False)
                    respuesta = leer_respuesta(client)
                    print(f"[Servidor] {respuesta}")

            # CAMBIAR CONTRASEÑA
            elif subopcion == "4":
                actual = getpass.getpass("Introduce tu contraseña actual: ").strip()
                nueva = getpass.getpass("Introduce tu nueva contraseña: ").strip()
                mensaje = f"CAMBIAR_PASSWORD|{actual}|{nueva}\n".encode()

                client_io.setblocking(True)
                client.write(mensaje)
                client_io.setblocking(False)

                respuesta = leer_respuesta(client)
                if respuesta == "CAMBIO_OK":
                    print("Contraseña actualizada con éxito.")
                elif respuesta == "PASSWORD_INVALIDA":
                    print("La nueva contraseña no cumple los requisitos.")
                elif respuesta == "PASSWORD_INCORRECTA":
                    print("La contraseña actual no es correcta.")
                else:
                    print("Error al cambiar la contraseña.")

            # CERRAR SESIÓN
            elif subopcion == "5":
                print("Sesión cerrada. Volviendo al menú principal.")
                break

            else:
                print("Opción no válida. Elige un número del 1 al 5.")

    elif respuesta_decodificada == "NO_EXISTE":
        print("El usuario no existe.")
    elif respuesta_decodificada == "BLOQUEADO":
        print("Usuario bloqueado temporalmente por múltiples fallos.")
    elif respuesta_decodificada.startswith("INTENTOS_RESTANTES|"):
        intentos = respuesta_decodificada.split("|")[1]
        print(f"Contraseña incorrecta. Te quedan {intentos} intento(s).")
    else:
        print("Error desconocido durante el inicio de sesión.")

# LEER RESPUESTAS BUCLE
def leer_respuesta(client):
    '''
    Lee datos del servidor hasta recibir una línea completa (terminada en '\n')
    '''
    respuesta = b""
    while True:
        try:
            c = client.read(1)
            if not c:
                break
            respuesta += c
            if c == b"\n":
                break
        except SandwichErrors.RecordPlaneWantReadException:
            continue
    return respuesta.decode().strip()

# 5. LÓGICA CLIENTE-SERVIDOR
def iniciar_cliente_tls(
    host: str,
    port: int,
    input_r: Connection | BinaryIO,
    output_w: Connection | BinaryIO,
    client_ctx_conf: SandwichTunnel.Context,
):
    '''
    Conexión con el servidor TLS Sandwich y muestra el menú principal del cliente.
    '''
    while True:
        try:
            client_io = socket.create_connection((host, port))
            break
        except ConnectionRefusedError:
            pass
    swio = SandwichIOHelpers.io_socket_wrap(client_io)
    client_tun_conf = configurar_tunel_cliente(host)

    client = SandwichTunnel.Tunnel(
        client_ctx_conf,
        swio,
        client_tun_conf,
    )
    assert client is not None

    client.handshake()
    state = client.state()
    assert (
        state == client.State.STATE_HANDSHAKE_DONE
    ), f"Expected state HANDSHAKE_DONE, got {state}"

    import time
    time.sleep(0.2)  # Espera breve para dejar al servidor imprimir su mensaje

    # MENÚ PRINCIPAL
    while True:
        imprimir_separador("Menú principal")
        opciones_menu = {
            "1": "Registrarse",
            "2": "Iniciar sesión",
            "3": "Salir"
        }
        imprimir_opciones(opciones_menu)
        print("\nOpción: ", end="", flush=True)

        if isinstance(input_r, Connection):
            data = input_r.recv_bytes(16)
        else:
            data = input_r.readline()
        if not data:
            continue

        opcion = data.decode().strip()

        # REGISTRO
        if opcion == "1":

            #PEDIR USERNAME:
            username = input("Nombre de usuario: ").strip()
            mensaje_usuario = f"CHECK_USERNAME|{username}\n".encode()

            client_io.setblocking(True)
            client.write(mensaje_usuario)
            client_io.setblocking(False)

            # LEER 1ª RESPUESTA DEL SV
            respuesta_decodificada = leer_respuesta(client)
            if respuesta_decodificada != "OK":
                print("Registro fallido: El nombre de usuario ya existe. Inténtalo de nuevo.")
                continue

            # PEDIR PASSWORD
            password = getpass.getpass("Contraseña: ").strip()
            mensaje_password = f"CHECK_PASSWORD|{password}\n".encode()

            client_io.setblocking(True)
            client.write(mensaje_password)
            client_io.setblocking(False)

            # LEER 2ª RESPUESTA DEL SV
            respuesta_decodificada = leer_respuesta(client)

            if respuesta_decodificada == "REGISTRO_OK":
                print("Usuario registrado con éxito.")

                #SUBMENU POST-REGISTRO
                while True:
                    imprimir_separador("Acciones disponibles")
                    print("  1 - Iniciar sesión")
                    print("  2 - Salir del sistema")
                    opcion_post = input("Opción: ").strip()

                    # INICIAR SESIÓN
                    if opcion_post == "1":
                            proceso_login(client, client_io)
                            break

                    # SALIR
                    elif opcion_post == "2":
                        mensaje = b"EXIT\n"
                        client_io.setblocking(True)
                        client.write(mensaje)
                        client_io.setblocking(False)
                        print("Cliente ha salido del sistema.")
                        client.close()
                        return
                    else:
                        print("Opción no válida. Elige 1 o 2.")
                        continue  # vuelve al submenú post-registro

            elif respuesta_decodificada == "PASSWORD_INVALIDA":
                print("Contraseña inválida. Debe tener al menos 8 caracteres, una mayúscula y un número.")
            else:
                print("Registro fallido por error desconocido.")
            continue  # Vuelve al menú principal

        # INICIO DE SESIÓN
        elif opcion == "2":
            proceso_login(client, client_io)
            continue

        # SALIR
        elif opcion == "3":
            mensaje = b"EXIT\n"
            client_io.setblocking(True)
            client.write(mensaje)
            client_io.setblocking(False)
            print("Cliente ha salido del sistema.")
            client.close()
            break

        else:
            print("Opción no válida. Elige 1, 2 o 3.")
            continue

# 6. MAIN
def main(
    hostname: str,
    port: int,
    trusted_cert_path: str,
    input_r: Connection | BinaryIO,
    output_w: Connection | BinaryIO,
):
    '''
    Inicializa el cliente TLS según los parámetros pasados por línea de comandos.
    '''

    imprimir_bienvenida()
    imprimir_separador("Selección del protocolo TLS")

    # ELECCION PROTOCOLO TLS

    print("Antes de comenzar, ¿qué protocolo desea usar?")
    print("1 - TLS 1.2")
    print("2 - TLS 1.3")
    opcion_tls = input("Seleccione una opción (1 o 2): ").strip()

    if opcion_tls == "1":
        tls = "tls12"
    elif opcion_tls == "2":
        tls = "tls13"
    else:
        print("Opción no válida. Usando TLS 1.3 por defecto.")
        tls = "tls13"

    print(f"Protocolo seleccionado: {tls.upper()}")

    sw = Sandwich()

    # Función que carga el certificado y configura TLS
    client_conf = configurar_tls_cliente(tls, trusted_cert_path)

    # Contexto seguro a partir de esa configuración
    client_ctx = SandwichTunnel.Context.from_config(sw, client_conf)

    #Conexión al servidor
    iniciar_cliente_tls(hostname, port, input_r, output_w, client_ctx)

# 7. ENTRADA DEL SCRIPT
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(prog="TLS client using Sandwich")
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        help="Port to connect to (defaults to 443)",
        default=443,
    )
    parser.add_argument("--host", type=str, help="Host to connect to", required=True)

    # Argumento para la ruta del certificado de confianza
    parser.add_argument(
        "--trusted-cert",
        type=str,
        help="Ruta al certificado del servidor para validación",
        required=True,
    )
    args = parser.parse_args()

    main(args.host, args.port, args.trusted_cert, sys.stdin.buffer, sys.stdout.buffer)
