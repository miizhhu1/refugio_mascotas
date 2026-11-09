package com.krakedev.refugio_mascotas.services;

import java.util.Optional;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.stereotype.Service;

import com.krakedev.refugio_mascotas.entidades.Usuario;
import com.krakedev.refugio_mascotas.repositories.UsuarioRepository;

@Service
public class UsuarioService {

	private final UsuarioRepository usuarioRepository;

	// Inyección de dependencias por constructor
	public UsuarioService(UsuarioRepository usuarioRepository) {

		this.usuarioRepository = usuarioRepository;

	}

	// guardar usuario
	public Usuario guardar(Usuario usuario) {
		String contrasenaEncriptada = BCrypt.hashpw(usuario.getPassword(), BCrypt.gensalt());

		usuario.setPassword(contrasenaEncriptada);

		return usuarioRepository.save(usuario);
	}

	// autenticador usuario
	public boolean autenticar(String username, String password) {
		Optional<Usuario> usuarioOpt = usuarioRepository.findByUsername(username);
		if (usuarioOpt.isPresent()) {
			Usuario usuario = usuarioOpt.get();

			if (BCrypt.checkpw(password, usuario.getPassword())) {
				return true;
			}
		}
		return false;
	}

}
