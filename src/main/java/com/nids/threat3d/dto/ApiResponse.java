package com.nids.threat3d.dto;

import java.time.Instant;

/**
 * Generic API response envelope used by all Phase 2 REST endpoints.
 *
 * @param <T> the payload type
 */
public final class ApiResponse<T> {

    private final boolean success;
    private final String  message;
    private final T       data;
    private final Instant timestamp;
    private final String  error;

    private ApiResponse(boolean success, String message, T data, String error) {
        this.success   = success;
        this.message   = message;
        this.data      = data;
        this.error     = error;
        this.timestamp = Instant.now();
    }

    /** Successful response with a data payload. */
    public static <T> ApiResponse<T> ok(T data) {
        return new ApiResponse<>(true, "OK", data, null);
    }

    /** Successful response with a custom message and data payload. */
    public static <T> ApiResponse<T> ok(String message, T data) {
        return new ApiResponse<>(true, message, data, null);
    }

    /** Error response. */
    public static <T> ApiResponse<T> error(String error) {
        return new ApiResponse<>(false, "ERROR", null, error);
    }

    public boolean isSuccess()  { return success; }
    public String  getMessage() { return message; }
    public T       getData()    { return data; }
    public Instant getTimestamp(){ return timestamp; }
    public String  getError()   { return error; }
}
