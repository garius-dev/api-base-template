using System.Net;

namespace GariusWeb.Api.Application.Exceptions
{
    public class BaseException : Exception
    {
        public virtual HttpStatusCode StatusCode { get; }

        protected BaseException(string message, HttpStatusCode statusCode) : base(message)
        {
            StatusCode = statusCode;
        }

        public BaseException() : base()
        {
        }

        public BaseException(string? message) : base(message)
        {
        }

        public BaseException(string? message, Exception? innerException) : base(message, innerException)
        {
        }
    }
}
