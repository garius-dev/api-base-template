using System.Net;

namespace GariusWeb.Api.Application.Exceptions
{
    public class UnauthorizedAccessAppException : BaseException
    {
        public UnauthorizedAccessAppException(string message = "Acesso não autorizado")
            : base(message, HttpStatusCode.Unauthorized) { }

        protected UnauthorizedAccessAppException(string message, HttpStatusCode statusCode) : base(message, statusCode)
        {
        }

        public UnauthorizedAccessAppException() : base()
        {
        }

        public UnauthorizedAccessAppException(string? message, Exception? innerException) : base(message, innerException)
        {
        }
    }
}
