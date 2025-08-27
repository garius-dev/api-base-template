using System.Net;

namespace GariusWeb.Api.Application.Exceptions
{
    public class BadRequestException : BaseException
    {
        public BadRequestException(string message = "Requisição inválida")
            : base(message, HttpStatusCode.BadRequest) { }

        protected BadRequestException(string message, HttpStatusCode statusCode) : base(message, statusCode)
        {
        }

        public BadRequestException() : base()
        {
        }

        public BadRequestException(string? message, Exception? innerException) : base(message, innerException)
        {
        }
    }
}