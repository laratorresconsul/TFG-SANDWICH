# test_server.py

# Autor/a: Lara Sofía Torres Cónsul
import unittest
from server import (
    configurar_tls_servidor,
    configurar_tunel_autenticacion,
    crear_socket_escucha_tcp
)

class TestServerLogic(unittest.TestCase):
    def test_configurar_tls_servidor(self):
        '''
        Verifica que se puede crear la configuración TLS del servidor con rutas de clave y certificado.
        '''
        cert_path = "/home/lara/certificados/certificado.pem"
        key_path = "/home/lara/certificados/clave_privada.pem"

        conf = configurar_tls_servidor(cert_path, key_path)

        self.assertIsNotNone(conf)
        self.assertTrue(conf.HasField("server"))
        self.assertTrue(conf.server.tls.HasField("common_options"))
        self.assertEqual(
            conf.server.tls.common_options.identity.certificate.static.data.filename,
            cert_path
        )
        self.assertEqual(
            conf.server.tls.common_options.identity.private_key.static.data.filename,
            key_path
        )

    def test_configurar_tunel_autenticacion(self):
        '''
        Verifica que se puede crear correctamente una configuración de túnel del servidor.
        '''
        tun_conf = configurar_tunel_autenticacion()
        self.assertIsNotNone(tun_conf)
        self.assertTrue(tun_conf.HasField("verifier"))

    def test_crear_socket_escucha_tcp(self):
        '''
        Verifica que se puede crear un objeto Listener TCP con los parámetros especificados.
        '''
        hostname = "localhost"
        port = 12345
        listener = crear_socket_escucha_tcp(hostname, port)

        self.assertIsNotNone(listener)
        self.assertTrue(hasattr(listener, "accept"))


if __name__ == '__main__':
    unittest.main()
