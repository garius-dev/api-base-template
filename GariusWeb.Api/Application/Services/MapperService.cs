using AutoMapper;

namespace GariusWeb.Api.Application.Services
{
    public class MapperService
    {
        private readonly IMapper _mapper;

        public MapperService(IMapper mapper)
        {
            _mapper = mapper;
        }

        public TDestination Map<TSource, TDestination>(TSource source)
        {
            return _mapper.Map<TDestination>(source);
        }

        public IEnumerable<TDestination> MapList<TSource, TDestination>(IEnumerable<TSource> source)
        {
            return _mapper.Map<IEnumerable<TDestination>>(source);
        }

        public void MapTo<TSource, TDestination>(TSource source, TDestination destination)
        {
            _mapper.Map(source, destination);
        }
    }
}
