package com.michell.backend.usersapp.backendusersapp.services;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.michell.backend.usersapp.backendusersapp.models.IUser;
import com.michell.backend.usersapp.backendusersapp.models.dto.UserDto;
import com.michell.backend.usersapp.backendusersapp.models.dto.mapper.DtoMapperUser;
import com.michell.backend.usersapp.backendusersapp.models.entities.Role;
import com.michell.backend.usersapp.backendusersapp.models.entities.User;
import com.michell.backend.usersapp.backendusersapp.models.request.UserRequest;
import com.michell.backend.usersapp.backendusersapp.repositories.RoleRepository;
import com.michell.backend.usersapp.backendusersapp.repositories.UserRepository;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository repository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    @Transactional(readOnly = true)
    public List<UserDto> findAll() {
        List<User> users = (List<User>) repository.findAll();

        return users
                .stream()
                .map(u -> DtoMapperUser.builder().setUser(u).build())
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<UserDto> findById(Long id) {
        return repository.findById(id)
                .map(u -> DtoMapperUser.builder().setUser(u).build());
    }

    @Override
    @Transactional
    public UserDto save(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRoles(getRoles(user));

        return DtoMapperUser.builder().setUser(repository.save(user)).build();
    }

    @Override
    @Transactional
    public Optional<UserDto> update(UserRequest user, Long id) {
        Optional<User> o = repository.findById(id);
        if (o.isPresent()) {
            User userDB = o.orElseThrow();
            userDB.setRoles(getRoles(user));
            userDB.setUsername(user.getUsername());
            userDB.setEmail(user.getEmail());
            return Optional.of(DtoMapperUser.builder().setUser(repository.save(userDB)).build());
        }
        return Optional.empty();
    }

    @Override
    @Transactional
    public void remove(Long id) {
        repository.deleteById(id);
    }

    private List<Role> getRoles(IUser user) {
        Optional<Role> ou = roleRepository.findByName("ROLE_USER");
        List<Role> roles = new ArrayList<>();

        if (ou.isPresent()) {
            roles.add(ou.orElseThrow());
        }

        if (user.isAdmin()) {
            Optional<Role> oa = roleRepository.findByName("ROLE_ADMIN");
            if (oa.isPresent()) {
                roles.add(oa.orElseThrow());
            }
        }
        return roles;
    }
}
