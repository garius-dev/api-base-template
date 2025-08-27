namespace GariusWeb.Api.Application.Dtos.Accounts
{
    public class UserSearchResultResponse
    {
        public Guid Id { get; set; }
        public string Fullname { get; set; }
        public string Email { get; set; }
        public ICollection<UserSearchRoleResultResponse> Roles { get; set; } = new List<UserSearchRoleResultResponse>();
    }

    public class UserSearchRoleResultResponse
    {
        public string Name { get; set; }
    }
}
