CREATE DATABASE auth_db CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE auth_db;

-- Tabla de roles
CREATE TABLE roles (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(50) NOT NULL UNIQUE
);

-- Tabla de usuarios
CREATE TABLE usuarios (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    nombre_completo VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    habilitado BOOLEAN DEFAULT TRUE,
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE usuarios_roles (
    usuario_id BIGINT NOT NULL,
    rol_id BIGINT NOT NULL,
    PRIMARY KEY (usuario_id, rol_id),
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
    FOREIGN KEY (rol_id) REFERENCES roles(id) ON DELETE CASCADE
);

-- Insertar roles base
INSERT INTO roles (nombre) VALUES
('ROLE_ADMIN'),
('ROLE_USER');

-- Insertar usuario
INSERT INTO usuarios (nombre_completo, email, password, habilitado)
VALUES ('Administrador General', 'admin@example.com', '$2a$10$Xq1XxRuq8o6t5Cj0WZn3eOKtGHiC5bYpnw3K7rfxsw7zMQ8lZhCe6', TRUE);

-- Asignar rol al usuario
INSERT INTO usuarios_roles (usuario_id, rol_id)
VALUES (1, 1); 

