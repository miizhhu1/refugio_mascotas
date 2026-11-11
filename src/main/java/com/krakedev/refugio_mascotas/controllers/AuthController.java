package com.krakedev.refugio_mascotas.controllers;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.krakedev.refugio_mascotas.entidades.Usuario;
import com.krakedev.refugio_mascotas.repositories.UsuarioRepository;
import com.krakedev.refugio_mascotas.services.TokenBlackListService;
import com.krakedev.refugio_mascotas.services.UsuarioService;
import com.krakedev.refugio_mascotas.utils.JwtUtil;

@RestController
@RequestMapping("/auth")
public class AuthController {
	private final UsuarioService usuarioService;
	private final UsuarioRepository usuarioRepository;
	private final TokenBlackListService blackListService;

	public AuthController(UsuarioService usuarioService, UsuarioRepository usuarioRepository,
			TokenBlackListService blackListService) {
		super();
		this.usuarioService = usuarioService;
		this.usuarioRepository = usuarioRepository;
		this.blackListService = blackListService;
	}

	// registrar usuario
	@PostMapping("/registrar")
	public ResponseEntity<?> registar(@RequestBody Usuario usuario) {
		try {
			Usuario usuarioNuevo = usuarioService.guardar(usuario);
			return ResponseEntity.status(HttpStatus.CREATED).body(usuarioNuevo);
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("Error al registrar usuario: " + e.getMessage());
		}
	}

	// crear login
	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody Map<String, String> credenciales) {
		// obtenemos usuario y contraseña de postman
		String username = credenciales.get("username");
		String password = credenciales.get("password");

		boolean autenticado = usuarioService.autenticar(username, password);

		if (autenticado) {
			Usuario usuario = usuarioRepository.findByUsername(username).get();

			String token = JwtUtil.generarToken(usuario.getUsername(), usuario.getRol());

			return ResponseEntity.ok(Map.of("token", token));
		} else {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuario o contraseña incorrecta");
		}

	}

	// entrada a un perfil
	@GetMapping("/perfil")
	public ResponseEntity<?> perfil(@RequestHeader(value = "Authorization", required = false) String authHeader) {

		// 1. Verificar que exista la cabecera Authorization
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			return ResponseEntity.status(401).body("Token no proporcionado o formato incorrecto");
		}

		// 2. Extraer el token eliminando la palabra Bearer
		String token = authHeader.substring(7);
		
		 //Verificar si el token fue invalidado
		 if (blackListService.estaInvalidado(token)) {
		     return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
		             .body("Acceso denegado: la sesión fue cerrada");
		 }

		// Validar el token
		DecodedJWT datosToken = JwtUtil.validarToken(token);

		if (datosToken == null) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
		            .body("Token inválido o expirado");
		}

		// Obtener los datos del token
		String usuario = datosToken.getSubject();
		String rol = datosToken.getClaim("rol").asString();

		// Crear un saludo según el rol
		return ResponseEntity.ok(Map.of("Mensaje", "Bienvenido al sistema protegido por jwt:", "Usuario: ", usuario,
				"Rol: ", rol, "Estatus", "Auntenticad existoso"));
	}

	@PostMapping("/logout")
	public ResponseEntity<?> logout(@RequestHeader(value = "Authorization", required = false) String authHeader) {
		if (authHeader != null &&  authHeader.startsWith("Bearer ")) {
			String token = authHeader.substring(7);

			// invalidamos token
			blackListService.invalidarToken(token);

			return ResponseEntity.ok(Map.of("Mensaje", "Sesión cerrada exitosamente. Token invalidado"));

		} else {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token no proporcionado");
		}
	}

}
