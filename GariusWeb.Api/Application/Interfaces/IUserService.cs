using GariusWeb.Api.Application.Dtos.Accounts;
using GariusWeb.Api.Domain.Abstractions;
using GariusWeb.Api.Domain.Entities.Identity;
using System.Security.Claims;

namespace GariusWeb.Api.Application.Interfaces
{
    public interface IUserService
    {
        

        Task<FtsPagedResult<UserSearchResultResponse, Guid>> SearchUsersAsync(
            string? searchTerm,
            int pageSize,
            SearchCursor<Guid>? cursor, CancellationToken cancellationToken = default);

        
    }
}
