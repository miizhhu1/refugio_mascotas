package com.krakedev.refugio_mascotas.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.krakedev.refugio_mascotas.entidades.Usuario;

public interface UsuarioRepository extends JpaRepository<Usuario, Integer> {
	Optional<Usuario> findByUsername(String username);	
}
