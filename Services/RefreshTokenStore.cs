using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace JwtTokenExample.Services
{
    /// <summary>
    /// In-memory refresh token store with token family tracking.
    /// Stores only SHA-256 hashes — the raw token never touches the server after generation.
    /// In production, replace with Redis or a database.
    /// </summary>
    public class RefreshTokenStore
    {
        private readonly ConcurrentDictionary<string, RefreshTokenEntry> _tokens = new();

        /// <summary>
        /// Store a refresh token entry keyed by the SHA-256 hash of the raw token.
        /// </summary>
        public void Store(string tokenHash, string familyId, string userName, DateTime expiresAt)
        {
            _tokens[tokenHash] = new RefreshTokenEntry
            {
                FamilyId = familyId,
                UserName = userName,
                ExpiresAt = expiresAt,
                IsRevoked = false
            };
        }

        public RefreshTokenEntry? Get(string tokenHash)
        {
            _tokens.TryGetValue(tokenHash, out var entry);
            return entry;
        }

        public void Revoke(string tokenHash)
        {
            if (_tokens.TryGetValue(tokenHash, out var entry))
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

        /// <summary>
        /// SHA-256 hash of the raw refresh token string.
        /// We never store the plaintext — even if the store is compromised,
        /// attackers cannot reconstruct valid refresh tokens.
        /// </summary>
        public static string HashToken(string rawToken)
        {
            var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
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
