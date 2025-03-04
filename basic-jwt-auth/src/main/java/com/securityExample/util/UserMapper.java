package com.securityExample.util;

import com.securityExample.dto.UserDto;
import com.securityExample.entity.Role;
import com.securityExample.entity.User;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

@Component
public class UserMapper {
    public UserDto mapToDto(User user) {
        return new UserDto(
                user.getId(),
                user.getUserName(),
                user.getUserEmail(),
                "",
                user.getAbout()
        );
    }

    public User mapToModel(UserDto dto) {
        return new User(
                dto.getId(),
                dto.getUserName(),
                dto.getUserEmail(),
                dto.getPassword(),
                Role.USER,
                dto.getAbout(),
                new ArrayList<>()
        );
    }
}
