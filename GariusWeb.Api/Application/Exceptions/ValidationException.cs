using System.Net;

namespace GariusWeb.Api.Application.Exceptions
{
    public class ValidationException : BaseException
    {
        public ValidationException(string message)
            : base(message, HttpStatusCode.BadRequest) { }

        protected ValidationException(string message, HttpStatusCode statusCode) : base(message, statusCode)
        {
        }

        public ValidationException() : base()
        {
        }

        public ValidationException(string? message, Exception? innerException) : base(message, innerException)
        {
        }
    }
}
