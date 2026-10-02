package com.nids.threat3d.exception;

import org.springframework.http.HttpStatus;

public class ThreatApiException extends RuntimeException {
    private final HttpStatus status;

    public ThreatApiException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
