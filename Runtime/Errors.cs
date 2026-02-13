using System;

namespace Tuteliq
{
    /// <summary>
    /// Base exception for Tuteliq SDK errors.
    /// </summary>
    public class TuteliqException : Exception
    {
        public object Details { get; }

        public TuteliqException(string message, object details = null) : base(message)
        {
            Details = details;
        }
    }

    /// <summary>
    /// Thrown when API key is invalid or missing.
    /// </summary>
    public class AuthenticationException : TuteliqException
    {
        public AuthenticationException(string message, object details = null) : base(message, details) { }
    }

    /// <summary>
    /// Thrown when rate limit is exceeded.
    /// </summary>
    public class RateLimitException : TuteliqException
    {
        public RateLimitException(string message, object details = null) : base(message, details) { }
    }

    /// <summary>
    /// Thrown when request validation fails.
    /// </summary>
    public class ValidationException : TuteliqException
    {
        public ValidationException(string message, object details = null) : base(message, details) { }
    }

    /// <summary>
    /// Thrown when a resource is not found.
    /// </summary>
    public class NotFoundException : TuteliqException
    {
        public NotFoundException(string message, object details = null) : base(message, details) { }
    }

    /// <summary>
    /// Thrown when the server returns a 5xx error.
    /// </summary>
    public class ServerException : TuteliqException
    {
        public int StatusCode { get; }

        public ServerException(string message, int statusCode, object details = null) : base(message, details)
        {
            StatusCode = statusCode;
        }
    }

    /// <summary>
    /// Thrown when a request times out.
    /// </summary>
    public class TimeoutException : TuteliqException
    {
        public TimeoutException(string message, object details = null) : base(message, details) { }
    }

    /// <summary>
    /// Thrown when a network error occurs.
    /// </summary>
    public class NetworkException : TuteliqException
    {
        public NetworkException(string message, object details = null) : base(message, details) { }
    }
}
