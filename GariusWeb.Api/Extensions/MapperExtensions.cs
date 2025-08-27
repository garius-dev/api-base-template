using AutoMapper;
using Microsoft.EntityFrameworkCore;

namespace GariusWeb.Api.Extensions
{
    public static class MapperExtensions
    {
        public static (bool changed, string[] modifiedProps) MapAndDetectChanges<TDto, TEntity>(
            this IMapper mapper,
            TDto dto,
            TEntity entity,
            DbContext db)
        where TEntity : class
        {
            // entity deve estar sendo trackeada (ex.: carregada do banco via DbContext)
            mapper.Map(dto!, entity);

            var entry = db.Entry(entity);

            // Propriedades escalares que mudaram
            var modifiedProps = entry.Properties
                .Where(p => p.IsModified)
                .Select(p => p.Metadata.Name)
                .ToArray();

            // Se quiser considerar navegações/coleções, veja nota abaixo.
            var changed = modifiedProps.Length > 0;

            return (changed, modifiedProps);
        }
    }
}
