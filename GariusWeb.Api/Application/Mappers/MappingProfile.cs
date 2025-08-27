using AutoMapper;
using GariusWeb.Api.Application.Dtos.Tenants;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Domain.Entities;
using System.Reflection;

namespace GariusWeb.Api.Application.Mappers
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            ApplyMappingsFromAssembly(Assembly.GetExecutingAssembly());

            // --- CUSCOM ASSEMBLY MAPPINGS HERE ---
            CreateMap<Tenant, TenantResponse>();
        }

        private void ApplyMappingsFromAssembly(Assembly assembly)
        {
            var types = assembly.GetExportedTypes()
                .Where(t => t.GetInterfaces().Any(i =>
                    i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IMapFrom<>)))
                .ToList();

            foreach (var type in types)
            {
                var instance = Activator.CreateInstance(type);
                var methodInfo = type.GetMethod("Mapping")
                                ?? type.GetInterface("IMapFrom`1")?.GetMethod("Mapping");

                methodInfo?.Invoke(instance, new object[] { this });
            }
        }
    }
}