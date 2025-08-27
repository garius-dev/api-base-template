using System.Net;

namespace GariusWeb.Api.Application.Exceptions
{
    public class InternalServerErrorAppException : BaseException
    {
        public InternalServerErrorAppException(string message = "Erro interno no servidor")
            : base(message, HttpStatusCode.InternalServerError) { }

        protected InternalServerErrorAppException(string message, HttpStatusCode statusCode) : base(message, statusCode)
        {
        }

        public InternalServerErrorAppException() : base()
        {
        }

        public InternalServerErrorAppException(string? message, Exception? innerException) : base(message, innerException)
        {
        }
    }
}
