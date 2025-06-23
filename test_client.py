# test_client.py

# Autor/a: Lara Sofía Torres Cónsul

import unittest
from client import configurar_tls_cliente, configurar_tunel_cliente


class TestLogicaCliente(unittest.TestCase):
    def test_configurar_tls_cliente_tls13(self):
        '''
        Verifica que se puede crear una configuración TLS 1.3 sin errores.
        '''
        conf = configurar_tls_cliente("tls13")
        self.assertIsNotNone(conf)
        self.assertTrue(conf.client.tls.HasField("common_options"))

    def test_configurar_tls_cliente_tls12(self):
        '''
        Verifica que se puede crear una configuración TLS 1.2 sin errores.
        '''
        conf = configurar_tls_cliente("tls12")
        self.assertIsNotNone(conf)
        self.assertTrue(conf.client.tls.HasField("common_options"))

    def test_configurar_tls_cliente_invalido(self):
        '''
        Verifica que se lanza una excepción si se pasa una versión TLS no válida.
        '''
        with self.assertRaises(NotImplementedError):
            configurar_tls_cliente("tls999")

    def test_configurar_tunel_cliente_localhost(self):
        '''
        Verifica que la configuración del túnel para localhost no incluye SNI.
        '''
        conf = configurar_tunel_cliente("localhost")
        self.assertEqual(conf.server_name_indication, "")

    def test_configurar_tunel_cliente_host_remoto(self):
        '''
        Verifica que la configuración del túnel para un host externo incluye SNI.
        '''
        conf = configurar_tunel_cliente("example.com")
        self.assertEqual(conf.server_name_indication, "example.com")


if __name__ == '__main__':
    unittest.main()
