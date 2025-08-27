using GariusWeb.Api.Application.Dtos.Accounts;
using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Domain.Abstractions;
using GariusWeb.Api.Domain.Entities.Identity;
using GariusWeb.Api.Infrastructure.Data;
using GariusWeb.Api.Infrastructure.Data.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace GariusWeb.Api.Application.Services
{
    public class UserService : IUserService
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;

        public UserService(UserManager<ApplicationUser> userManager, ApplicationDbContext context)
        {
            _userManager = userManager;
            _context = context;
        }

        public async Task GetUser()
        {
            const string ts = "'geo':* & 'lu':*"; // string que você monta no C#
            var results = await _userManager.Users
                .Where(u => u.SearchVector.Matches(EF.Functions.ToTsQuery("simple", ts)))
                .OrderByDescending(u => u.SearchVector.Rank(EF.Functions.ToTsQuery("simple", ts)))
                .ToListAsync().ConfigureAwait(false);
        }

        public async Task<FtsPagedResult<UserSearchResultResponse, Guid>> SearchUsersAsync(string? searchTerm, int pageSize, SearchCursor<Guid>? cursor, CancellationToken cancellationToken = default)
        {
            if (pageSize <= 0) pageSize = 10;
            if (pageSize > 50) pageSize = 50;

            var pagedResult = await _context.Users
                .AsSplitQuery()
                .SearchPageAsync(
                    tsVectorColumn: "SearchVector",
                    tsConfig: "simple_unaccent",
                    userInput: searchTerm,
                    keySelector: u => u.Id,
                    pageSize: pageSize,
                    cursor: cursor,
                    emailColumnForTrigram: "Email",
                    include: q => q.Include(u => u.UserRoles).ThenInclude(ur => ur.Role),
                    cancellationToken: cancellationToken).ConfigureAwait(false);

            var searchHitsDto = pagedResult.Items.Select(searchHit =>
                new SearchHit<UserSearchResultResponse>(
                    new UserSearchResultResponse
                    {
                        Id = searchHit.Item.Id,
                        Fullname = searchHit.Item.FullName,
                        Email = searchHit.Item.Email,
                        Roles = searchHit.Item.UserRoles
                                    .Select(ur => new UserSearchRoleResultResponse { Name = ur.Role.Name })
                                    .ToList()
                    },
                    searchHit.Rank
                )
            ).ToList();

            return new FtsPagedResult<UserSearchResultResponse, Guid>(
                searchHitsDto,
                pagedResult.NextCursor
            );

            //return pagedDtoResult;
        }
    }
}