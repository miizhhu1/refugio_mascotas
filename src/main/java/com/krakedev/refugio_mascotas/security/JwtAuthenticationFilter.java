package com.krakedev.refugio_mascotas.security;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.krakedev.refugio_mascotas.services.TokenBlackListService;
import com.krakedev.refugio_mascotas.utils.JwtUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component // component, esta clase es un componente especial
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final TokenBlackListService blacklistService;

	public JwtAuthenticationFilter(TokenBlackListService blacklistService) {
		super();
		this.blacklistService = blacklistService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// TODO Auto-generated method stub

		String authHeader = request.getHeader("Authorization");
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {

			//
			filterChain.doFilter(request, response);
		}

		// obtenmos el token
		String token = authHeader.substring(7);

		// no autorizado
		if (blacklistService.estaInvalidado(token)) {
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

			response.getWriter().write("Acceso denegado: Sesion cerrada");
			return;
		}

		DecodedJWT datosToken = JwtUtil.validarToken(token);

		if (datosToken != null) {
			String username = datosToken.getSubject();
			String rolOriginal = datosToken.getClaim("Rol").asString();

			String rolSpring = "ROLE_" + rolOriginal;

			SimpleGrantedAuthority authoriy = new SimpleGrantedAuthority(rolOriginal);
			UsernamePasswordAuthenticationToken authenticaion = new UsernamePasswordAuthenticationToken(username, null,
					Collections.singleton(authoriy));
			
			SecurityContextHolder.getContext().setAuthentication(authenticaion);
			

		}
		
		filterChain.doFilter(request, response);

	}

}
