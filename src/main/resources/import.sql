INSERT INTO users (email, password, username)
VALUES('admin@correo.com', '$2a$10$K2f97D6lKaFsohR.TgqLR.x0pgE/xZHaxTBxv5CnsBDveZCXLpM4K', 'admin');

INSERT INTO roles (name) VALUES ('ROLE_ADMIN');
INSERT INTO roles (name) VALUES ('ROLE_USER');

INSERT INTO users_roles (user_id, role_id) VALUES (1, 1);
INSERT INTO users_roles (user_id, role_id) VALUES (1, 2);