package com.cibertec.oauth_server.Service;

import com.cibertec.oauth_server.DTO.UsuarioResponse;
import com.cibertec.oauth_server.Entity.UserEntity;
import com.cibertec.oauth_server.OAUTH.UsuarioNoEncontradoException;
import com.cibertec.oauth_server.Repository.UsuarioRepository;
import org.springframework.stereotype.Service;

<<<<<<< HEAD
import java.util.List;
import java.util.Set;
=======
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
>>>>>>> 3b7c06b (usuarios id)

@Service
public class UsuariosService {

    private final UsuarioRepository usuarioRepository;
    public UsuariosService(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }

    public UsuarioResponse usuarioPorId(Long id) {

        UserEntity user = usuarioRepository.findById(id)
                .orElseThrow(()-> new UsuarioNoEncontradoException("Usuario no encontrado"));
        UsuarioResponse usuarioResponse = new UsuarioResponse();
        usuarioResponse.setId(user.getId());
        usuarioResponse.setNombreCompleto(user.getNombreCompleto());
        return usuarioResponse;
    }

    public List<UsuarioResponse> getUsuarios(Set<Long> ids) {
        List<UserEntity> users = usuarioRepository.findAllById(ids);
        return users.stream().map(u -> new
                UsuarioResponse(u.getId(), u.getNombreCompleto())).toList();
    }
}
