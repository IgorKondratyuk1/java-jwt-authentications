package com.securityExample.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "\"user\"")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Size(min = 2, max = 16, message = "The username must be at least 2 "
            + "and no more than 16 characters long")
    private String userName;

    @Column(nullable = false)
    private String userEmail;

    @Column(nullable = false)
    @JsonIgnore
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Size(min = 10, max = 500, message = "Maximum number of characters for About 500")
    private String about;

    @OneToMany(mappedBy = "user")
    @JsonIgnore
    private List<Token> tokens;
}
