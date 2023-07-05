package com.nikiko.security.exception;

public class AuthException extends ApiException{
    public AuthException(String message, String code) {
        super(message, code);
    }
}
