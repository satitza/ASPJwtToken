using System.Collections.Concurrent;

namespace JwtTokenExample.Services
{
    /// <summary>
    /// In-memory refresh token store with token family tracking.
    /// In production, replace with Redis or a database.
    /// </summary>
    public class RefreshTokenStore
    {
        private readonly ConcurrentDictionary<string, RefreshTokenEntry> _tokens = new();

        public void Store(string tokenId, string familyId, string userName, DateTime expiresAt)
        {
            _tokens[tokenId] = new RefreshTokenEntry
            {
                FamilyId = familyId,
                UserName = userName,
                ExpiresAt = expiresAt,
                IsRevoked = false
            };
        }

        public RefreshTokenEntry? Get(string tokenId)
        {
            _tokens.TryGetValue(tokenId, out var entry);
            return entry;
        }

        public void Revoke(string tokenId)
        {
            if (_tokens.TryGetValue(tokenId, out var entry))
                entry.IsRevoked = true;
        }

        /// <summary>
        /// Revoke all tokens in the same family (token theft detection).
        /// If someone reuses an old refresh token, we kill the entire family.
        /// </summary>
        public void RevokeFamily(string familyId)
        {
            foreach (var kvp in _tokens)
            {
                if (kvp.Value.FamilyId == familyId)
                    kvp.Value.IsRevoked = true;
            }
        }

        public void CleanupExpired()
        {
            var now = DateTime.UtcNow;
            foreach (var kvp in _tokens)
            {
                if (kvp.Value.ExpiresAt < now)
                    _tokens.TryRemove(kvp.Key, out _);
            }
        }
    }

    public class RefreshTokenEntry
    {
        public string FamilyId { get; set; } = default!;
        public string UserName { get; set; } = default!;
        public DateTime ExpiresAt { get; set; }
        public bool IsRevoked { get; set; }
    }
}
