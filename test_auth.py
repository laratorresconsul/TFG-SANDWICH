# test_auth.py

# Autor/a: Lara Sofía Torres Cónsul
import unittest
import os
import json
from auth import (
    register_user,
    login_user,
    is_password_valid,
    generate_salt,
    hash_password,
    load_users,
    save_users,
    verify_login,
    USERS_FILE
)

class TestAuthLogic(unittest.TestCase):

    def setUp(self):
        '''
        Configura un entorno limpio antes de cada test, eliminando el archivo de usuarios si existe.
        '''
        if os.path.exists(USERS_FILE):
            os.remove(USERS_FILE)

    def tearDown(self):
        '''
        Limpia el entorno tras cada test eliminando el archivo de usuarios creado.
        '''
        if os.path.exists(USERS_FILE):
            os.remove(USERS_FILE)

    def test_is_password_valid(self):
        '''
        Verifica que la validación de contraseñas funcione correctamente según los requisitos establecidos.
        '''
        self.assertTrue(is_password_valid("Password1"))
        self.assertFalse(is_password_valid("password"))
        self.assertFalse(is_password_valid("12345678"))
        self.assertFalse(is_password_valid("Short1"))

    def test_register_user_success(self):
        '''
        Prueba que un usuario nuevo puede registrarse correctamente con una contraseña válida.
        '''
        result = register_user("usuario_test", "Password1")
        self.assertEqual(result, "exito")

        users = load_users()
        self.assertIn("usuario_test", users)

    def test_register_user_duplicate(self):
        '''
        Comprueba que no se permite registrar dos veces el mismo nombre de usuario.
        '''
        register_user("usuario_test", "Password1")
        result = register_user("usuario_test", "Password1")
        self.assertEqual(result, "usuario_duplicado")

    def test_register_user_invalid_password(self):
        '''
        Verifica que no se pueda registrar un usuario con una contraseña inválida.
        '''
        result = register_user("usuario_test", "weak")
        self.assertEqual(result, "password_invalida")

    def test_login_successful(self):
        '''
        Verifica que el inicio de sesión funcione correctamente con credenciales válidas.
        '''
        register_user("usuario_test", "Password1")
        success, estado = login_user("usuario_test", "Password1")
        self.assertTrue(success)
        self.assertIsNone(estado)

    def test_login_wrong_password(self):
        '''
        Comprueba que se detecta una contraseña incorrecta y se maneja el número de intentos.
        '''
        register_user("usuario_test", "Password1")
        success, estado = login_user("usuario_test", "WrongPass1")
        self.assertFalse(success)
        self.assertIsInstance(estado, int)

    def test_login_user_not_found(self):
        '''
        Verifica que el sistema retorna correctamente un error al intentar iniciar sesión con un usuario inexistente.
        '''
        success, estado = login_user("no_existe", "Password1")
        self.assertFalse(success)
        self.assertEqual(estado, "no_existe")

    def test_hash_password_consistency(self):
        '''
        Verifica que el mismo password y salt generan el mismo hash, y que cambiar el salt cambia el hash.
        '''
        salt = generate_salt()
        pw = "Password1"
        hash1 = hash_password(pw, salt)
        hash2 = hash_password(pw, salt)
        self.assertEqual(hash1, hash2)

        salt2 = generate_salt()
        hash3 = hash_password(pw, salt2)
        self.assertNotEqual(hash1, hash3)


if __name__ == "__main__":
    unittest.main()
