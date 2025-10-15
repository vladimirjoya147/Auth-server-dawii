package com.cibertec.oauth_server.Controller;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.ui.Model;
import com.cibertec.oauth_server.Entity.UserEntity;
import com.cibertec.oauth_server.Repository.RoleRepository;
import com.cibertec.oauth_server.Repository.UsuarioRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;
import java.util.Map;
import java.util.Set;

@Controller
public class AuthController {

    private final UsuarioRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final RegisteredClientRepository registeredClientRepository;
    private final AuthorizationServerSettings authorizationServerSettings;

    public AuthController(UsuarioRepository userRepository,
                          RoleRepository roleRepository,
                          PasswordEncoder passwordEncoder,
                          RegisteredClientRepository registeredClientRepository,
                          AuthorizationServerSettings authorizationServerSettings) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationServerSettings = authorizationServerSettings;
    }

    @GetMapping("/login")
    public String showLoginForm() {
        return "login";
    }

    @GetMapping("/auth/register")
    public String showRegistrationForm() {
        return "register";
    }


    @PostMapping("/auth/register")
    public String registerUser(@RequestParam String nombreCompleto,
                               @RequestParam String email,
                               @RequestParam String password,
                               Model model) {
        try {
            if (userRepository.existsByEmail(email)) {
                model.addAttribute("error", "El email ya está registrado");
                return "register";
            }

            UserEntity user = new UserEntity();
            user.setNombreCompleto(nombreCompleto);
            user.setEmail(email);
            user.setPassword(passwordEncoder.encode(password));
            user.setHabilitado(true);

            roleRepository.findByNombre("ROLE_USER")
                    .ifPresent(role -> user.setRoles(Set.of(role)));

            userRepository.save(user);

            model.addAttribute("success", "Usuario registrado exitosamente. Puede iniciar sesión.");
            return "login";

        } catch (Exception e) {
            model.addAttribute("error", "Error al registrar usuario: " + e.getMessage());
            return "register";
        }
    }
}