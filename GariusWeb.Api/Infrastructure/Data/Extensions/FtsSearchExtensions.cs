using GariusWeb.Api.Domain.Abstractions;
using Microsoft.EntityFrameworkCore;
using NpgsqlTypes;
using System.Linq.Expressions;

namespace GariusWeb.Api.Infrastructure.Data.Extensions;

/// <summary>
/// Contém métodos de extensão para realizar buscas Full-Text Search (FTS) paginadas no PostgreSQL.
/// </summary>
public static class FtsSearchExtensions
{
    /// <summary>
    /// Executa uma busca FTS paginada usando o método de keyset pagination (cursor).
    /// Suporta fallback para busca por trigram/ILike e deduplicação de resultados.
    /// </summary>
    /// <typeparam name="T">O tipo da entidade a ser buscada.</typeparam>
    /// <typeparam name="TKey">O tipo da chave primária da entidade.</typeparam>
    /// <param name="source">O IQueryable da fonte de dados.</param>
    /// <param name="tsVectorColumn">O nome da coluna tsvector no banco de dados.</param>
    /// <param name="tsConfig">A configuração de idioma do FTS (ex: 'portuguese').</param>
    /// <param name="userInput">O termo de busca fornecido pelo usuário.</param>
    /// <param name="keySelector">Uma expressão para selecionar a chave primária da entidade.</param>
    /// <param name="pageSize">O número de itens por página.</param>
    /// <param name="cursor">O cursor da página anterior para continuar a busca.</param>
    /// <param name="emailColumnForTrigram">Opcional. Nome da coluna para fallback de busca com ILike.</param>
    /// <param name="include">Opcional. Uma função para aplicar includes na query final.</param>
    /// <param name="cancellationToken">O token de cancelamento.</param>
    /// <returns>Um resultado paginado contendo os itens da página e o cursor para a próxima.</returns>
    public static async Task<FtsPagedResult<T, TKey>> SearchPageAsync<T, TKey>(
        this IQueryable<T> source,
        string tsVectorColumn,
        string tsConfig,
        string? userInput,
        Expression<Func<T, TKey>> keySelector,
        int pageSize,
        SearchCursor<TKey>? cursor = null,
        string? emailColumnForTrigram = null,
        Func<IQueryable<T>, IQueryable<T>>? include = null,
        CancellationToken cancellationToken = default
    ) where T : class where TKey : struct, IComparable<TKey>
    {
        #region Inicialização e Preparação

        var searchTerm = (userInput ?? string.Empty).Trim();
        var prefixTsQuery = BuildPrefixTsQuery(searchTerm);
        var keyName = ((MemberExpression)keySelector.Body).Member.Name;
        var keySelectorCompiled = keySelector.Compile();

        #endregion Inicialização e Preparação

        #region Construção da Query de Busca

        // Query principal baseada em Full-Text Search
        var baseQuery = source.Select(e => new
        {
            Entity = e,
            Rank = string.IsNullOrWhiteSpace(searchTerm)
                ? 0f
                : EF.Property<NpgsqlTsVector>(e, tsVectorColumn).Rank(EF.Functions.ToTsQuery(tsConfig, prefixTsQuery))
        })
        .Where(x => string.IsNullOrWhiteSpace(searchTerm) ||
                    EF.Property<NpgsqlTsVector>(x.Entity, tsVectorColumn).Matches(EF.Functions.ToTsQuery(tsConfig, prefixTsQuery)));

        // Aplica o fallback de busca por email, se aplicável
        bool needsEmailFallback = !string.IsNullOrWhiteSpace(emailColumnForTrigram) && !string.IsNullOrWhiteSpace(searchTerm);
        if (needsEmailFallback)
        {
            var trigramQuery = source
                .Where(e => EF.Functions.ILike(EF.Property<string>(e, emailColumnForTrigram!), $"%{searchTerm}%"))
                .Select(e => new { Entity = e, Rank = 0.05f });

            baseQuery = baseQuery.Union(trigramQuery);
        }

        #endregion Construção da Query de Busca

        #region Deduplicação de Resultados

        // Agrupa os resultados por chave e seleciona o maior rank para evitar duplicatas
        var deduplicatedQuery = baseQuery
            .Select(x => new { Key = EF.Property<TKey>(x.Entity, keyName), x.Rank })
            .GroupBy(x => x.Key)
            .Select(g => new { g.Key, Rank = g.Max(x => x.Rank) });

        #endregion Deduplicação de Resultados

        #region Paginação (Keyset com Cursor)

        if (cursor?.LastKey != null)
        {
            var lastRank = cursor.Value.LastRank ?? float.MaxValue;
            var lastKey = cursor.Value.LastKey.Value;

            deduplicatedQuery = deduplicatedQuery.Where(x =>
                x.Rank < lastRank || (x.Rank == lastRank && x.Key.CompareTo(lastKey) > 0));
        }

        var orderedRankedKeysQuery = deduplicatedQuery
            .OrderByDescending(x => x.Rank)
            .ThenBy(x => x.Key);

        var keysAndRanksForPage = await orderedRankedKeysQuery
            .Take(pageSize + 1)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        #endregion Paginação (Keyset com Cursor)

        #region Busca Final das Entidades

        bool hasNextPage = keysAndRanksForPage.Count > pageSize;
        var currentPageKeysAndRanks = keysAndRanksForPage.Take(pageSize).ToList();

        if (currentPageKeysAndRanks.Count == 0)
        {
            return new FtsPagedResult<T, TKey>(new List<SearchHit<T>>(), null);
        }

        var pageKeys = currentPageKeysAndRanks.Select(x => x.Key).ToList();

        var finalQuery = source;
        if (include != null)
        {
            finalQuery = include(finalQuery);
        }

        var itemsForPage = await finalQuery
            .Where(e => pageKeys.Contains(EF.Property<TKey>(e, keyName)))
            .AsNoTracking()
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        #endregion Busca Final das Entidades

        #region Montagem do Resultado

        var rankMap = currentPageKeysAndRanks.ToDictionary(x => x.Key, x => x.Rank);

        var orderedItems = itemsForPage
            .OrderBy(item => pageKeys.IndexOf(keySelectorCompiled(item)))
            .ToList();

        var searchHits = orderedItems
            .Select(item => new SearchHit<T>(item, rankMap[keySelectorCompiled(item)]))
            .ToList();

        SearchCursor<TKey>? nextCursor = null;
        if (hasNextPage)
        {
            var lastHit = searchHits.LastOrDefault();
            if (lastHit != null)
            {
                nextCursor = new SearchCursor<TKey>(lastHit.Rank, keySelectorCompiled(lastHit.Item));
            }
        }

        return new FtsPagedResult<T, TKey>(searchHits, nextCursor);

        #endregion Montagem do Resultado
    }

    /// <summary>
    /// Constrói uma string de tsquery para busca por prefixo (ex: 'term1':* & 'term2':*).
    /// </summary>
    private static string BuildPrefixTsQuery(string? userInput)
    {
        if (string.IsNullOrWhiteSpace(userInput))
        {
            return string.Empty;
        }

        var tokens = userInput.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(t => $"'{t.Replace("'", "''", StringComparison.Ordinal)}':*");

        return string.Join(" & ", tokens);
    }
}