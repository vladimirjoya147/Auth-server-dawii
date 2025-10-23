package com.cibertec.oauth_server.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserIdResponse {
    private List<UsuarioResponse> usuarios;
}
