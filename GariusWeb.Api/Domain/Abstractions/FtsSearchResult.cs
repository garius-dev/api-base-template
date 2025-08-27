using System.Runtime.InteropServices;

namespace GariusWeb.Api.Domain.Abstractions
{
    public readonly record struct SearchCursor<TKey>(float? LastRank, TKey? LastKey) where TKey : struct;
    public sealed record SearchHit<T>(T Item, float Rank);
    public sealed record FtsPagedResult<T, TKey>(IReadOnlyList<SearchHit<T>> Items, SearchCursor<TKey>? NextCursor) where TKey : struct;
}