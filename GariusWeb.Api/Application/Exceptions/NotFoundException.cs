using System.Net;

namespace GariusWeb.Api.Application.Exceptions
{
    public class NotFoundException : BaseException
    {
        public NotFoundException(string resource = "Recurso")
            : base($"{resource} não encontrado.", HttpStatusCode.NotFound) { }

        protected NotFoundException(string message, HttpStatusCode statusCode) : base(message, statusCode)
        {
        }

        public NotFoundException() : base()
        {
        }

        public NotFoundException(string? message, Exception? innerException) : base(message, innerException)
        {
        }
    }
}
