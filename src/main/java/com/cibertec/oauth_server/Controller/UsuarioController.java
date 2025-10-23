package com.cibertec.oauth_server.Controller;

import com.cibertec.oauth_server.DTO.UsuarioResponse;
import com.cibertec.oauth_server.Service.UsuariosService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/user")
public class UsuarioController {

    private final UsuariosService  usuariosService;

    public UsuarioController(UsuariosService usuariosService) {
        this.usuariosService = usuariosService;
    }

    @GetMapping("/{id}")
    public ResponseEntity<UsuarioResponse> getUsuarioResponse(@PathVariable Long id) {
        UsuarioResponse usuarioResponse = usuariosService.usuarioPorId(id);
        return new ResponseEntity<>(usuarioResponse, HttpStatus.OK);
    }

    @PostMapping("/list")
    public ResponseEntity<List<UsuarioResponse>> getlistaUsuarios(@RequestBody  Set<Long> ids) {
        List<UsuarioResponse> users = usuariosService.getUsuarios(ids);
        return new ResponseEntity<>(users, HttpStatus.OK);
    }
}
