using System.Net;

namespace GariusWeb.Api.Application.Exceptions
{
    public class ForbiddenAccessException : BaseException
    {
        public ForbiddenAccessException(string message = "Você não tem permissão para acessar este recurso.")
            : base(message, HttpStatusCode.Forbidden) { }

        protected ForbiddenAccessException(string message, HttpStatusCode statusCode) : base(message, statusCode)
        {
        }

        public ForbiddenAccessException() : base()
        {
        }

        public ForbiddenAccessException(string? message, Exception? innerException) : base(message, innerException)
        {
        }
    }
}
