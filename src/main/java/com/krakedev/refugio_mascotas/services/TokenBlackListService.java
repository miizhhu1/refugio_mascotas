package com.krakedev.refugio_mascotas.services;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

@Service
public class TokenBlackListService {

	// set es un poco mas rapido

	// guardamos lista de token utilizados
	private final Set<String> blacklist = ConcurrentHashMap.newKeySet();

	// invalidamos el token
	public void invalidarToken(String token) {

		// agregamos a lista para poder invalidarlo
		blacklist.add(token);
	}

	// verificamos si el token existe

	public boolean estaInvalidado(String token) {
		return blacklist.contains(token);
	}
}
