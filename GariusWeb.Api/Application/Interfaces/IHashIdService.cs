namespace GariusWeb.Api.Application.Interfaces
{
    public interface IHashIdService
    {
        string EncodeGuid(Guid id);
        Guid DecodeGuid(string hash);
    }
}
