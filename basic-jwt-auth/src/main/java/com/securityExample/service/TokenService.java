package com.securityExample.service;

import com.securityExample.entity.Token;
import com.securityExample.repository.TokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class TokenService {
    private final TokenRepository repository;

    public Token save(Token token) {
        return repository.save(token);
    }

    public List<Token> findAllValidTokensByUserId(Long userId) {
        return repository.findAllValidTokensByUserId(userId);
    }

    public Optional<Token> findByToken(String token) {
        return repository.findByToken(token);
    }

    public List<Token> saveAll(List<Token> tokens) {
        return repository.saveAll(tokens);
    }

    public void deleteInvalidTokensByUserId(Long userId) {
        repository.deleteInvalidTokensByUserId(userId);
    }
}