using GariusWeb.Api.Domain.Interfaces;
using Microsoft.Extensions.Caching.Distributed;
using Newtonsoft.Json;
using StackExchange.Redis;

namespace GariusWeb.Api.Infrastructure.Services
{
    public class RedisCacheService : ICacheService
    {
        private readonly IDistributedCache _cache;

        public RedisCacheService(IDistributedCache cache)
        {
            _cache = cache;
        }

        public async Task<T?> GetAsync<T>(string key)
        {
            var value = await _cache.GetStringAsync(key).ConfigureAwait(false);
            return value == null ? default : JsonConvert.DeserializeObject<T>(value);
        }

        public async Task SetAsync<T>(string key, T value, TimeSpan? expiration = null)
        {
            var json = JsonConvert.SerializeObject(value);
            var options = new DistributedCacheEntryOptions();
            if (expiration.HasValue)
                options.AbsoluteExpirationRelativeToNow = expiration;
            await _cache.SetStringAsync(key, json, options).ConfigureAwait(false);
        }

        public async Task RemoveAsync(string key)
        {
            await _cache.RemoveAsync(key).ConfigureAwait(false);
        }

        public async Task<bool> ExistsAsync(string key)
        {
            var value = await _cache.GetAsync(key).ConfigureAwait(false);
            return value != null;
        }

        public async Task SetPersistentAsync<T>(string key, T value)
        {
            var json = JsonConvert.SerializeObject(value);
            var options = new DistributedCacheEntryOptions
            {
                AbsoluteExpiration = null,
                SlidingExpiration = null
            };
            await _cache.SetStringAsync(key, json, options).ConfigureAwait(false);
        }
    }
}
