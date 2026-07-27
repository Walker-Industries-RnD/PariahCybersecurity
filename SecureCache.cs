using System.Collections.Concurrent;

namespace WISecureData
{
    // A simple cache whose values are protected. Every stored value is held as a
    // SecureData (AES-encrypted at rest in RAM, page-locked, wiped on eviction/expiry),
    // so "protect it all" is the default, not an add-on.
    //
    // The in-process implementation below is a thread-safe dictionary with TTLs. For a
    // single process it beats a remote Redis/Garnet server because there's no network
    // hop or serialization. If you need the cache SHARED across processes or machines,
    // that's when a distributed backend (Garnet/Redis) behind this same interface makes
    // sense - see the README for the tradeoff (a remote server holds your values in ITS
    // memory, which SecureData cannot protect).
    public interface ISecureCache : IDisposable
    {
        int Count { get; }

        void Set(string key, string value, TimeSpan? ttl = null);
        void SetBytes(string key, byte[] value, TimeSpan? ttl = null);
        void Set(string key, SecureData value, TimeSpan? ttl = null);

        // Returns a fresh, protected SecureData copy the caller owns (and should dispose).
        bool TryGet(string key, out SecureData value);

        // Convenience plaintext getters; return null on a miss or expiry.
        string? GetString(string key);
        byte[]? GetBytes(string key);

        bool Contains(string key);
        bool Remove(string key);
        void Clear();
    }

    // Fast, cross-platform, in-process implementation of ISecureCache.
    public sealed class SecureCache : ISecureCache
    {
        private sealed class Entry
        {
            public SecureData Value;
            public long ExpiryTicksUtc; // 0 = never expires
        }

        private readonly ConcurrentDictionary<string, Entry> _store = new(StringComparer.Ordinal);
        private readonly TimeSpan _defaultTtl;
        private readonly Timer? _sweeper;
        private int _disposed;

        // defaultTtl: applied when a Set call doesn't pass its own ttl (Zero = no expiry).
        // sweepInterval: how often expired entries are proactively wiped (Zero = only on access).
        public SecureCache(TimeSpan? defaultTtl = null, TimeSpan? sweepInterval = null)
        {
            _defaultTtl = defaultTtl ?? TimeSpan.Zero;

            TimeSpan interval = sweepInterval ?? TimeSpan.FromSeconds(30);
            if (interval > TimeSpan.Zero)
                _sweeper = new Timer(_ => SweepExpired(), null, interval, interval);
        }

        public int Count => _store.Count;

        public void Set(string key, string value, TimeSpan? ttl = null)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));
            SetInternal(key, new SecureData(System.Text.Encoding.UTF8.GetBytes(value)), ttl);
        }

        public void SetBytes(string key, byte[] value, TimeSpan? ttl = null)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));
            // Clone so SecureData wipes its own copy, not the caller's array.
            SetInternal(key, new SecureData((byte[])value.Clone()), ttl);
        }

        public void Set(string key, SecureData value, TimeSpan? ttl = null)
        {
            // Store an independent protected copy; the caller's SecureData is untouched.
            SetInternal(key, new SecureData(value.ConvertToBytes()), ttl);
        }

        private void SetInternal(string key, SecureData owned, TimeSpan? ttl)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            ThrowIfDisposed();

            var entry = new Entry { Value = owned, ExpiryTicksUtc = ComputeExpiry(ttl) };
            Entry? old = _store.TryGetValue(key, out var existing) ? existing : null;
            _store[key] = entry;
            old?.Value.Dispose(); // wipe the value we replaced
        }

        public bool TryGet(string key, out SecureData value)
        {
            value = default;
            if (key == null) return false;
            if (!_store.TryGetValue(key, out var entry)) return false;

            if (IsExpired(entry))
            {
                Evict(key, entry);
                return false;
            }

            try
            {
                value = new SecureData(entry.Value.ConvertToBytes());
                return true;
            }
            catch
            {
                // Raced with an eviction that wiped the value; treat it as a miss.
                return false;
            }
        }

        public string? GetString(string key)
        {
            if (TryGet(key, out var sd))
            {
                try { return sd.ConvertToString(); }
                finally { sd.Dispose(); }
            }
            return null;
        }

        public byte[]? GetBytes(string key)
        {
            if (TryGet(key, out var sd))
            {
                try { return sd.ConvertToBytes(); }
                finally { sd.Dispose(); }
            }
            return null;
        }

        public bool Contains(string key)
        {
            if (key == null) return false;
            if (!_store.TryGetValue(key, out var entry)) return false;
            if (IsExpired(entry)) { Evict(key, entry); return false; }
            return true;
        }

        public bool Remove(string key)
        {
            if (key == null) return false;
            if (_store.TryRemove(key, out var entry))
            {
                entry.Value.Dispose();
                return true;
            }
            return false;
        }

        public void Clear()
        {
            foreach (var kv in _store)
            {
                if (_store.TryRemove(kv.Key, out var entry))
                    entry.Value.Dispose();
            }
        }

        private long ComputeExpiry(TimeSpan? ttl)
        {
            TimeSpan effective = ttl ?? _defaultTtl;
            return effective > TimeSpan.Zero ? DateTime.UtcNow.Add(effective).Ticks : 0;
        }

        private static bool IsExpired(Entry e)
            => e.ExpiryTicksUtc != 0 && DateTime.UtcNow.Ticks > e.ExpiryTicksUtc;

        private void Evict(string key, Entry entry)
        {
            // Remove only if this exact entry is still mapped, so we never wipe a replacement.
            if (_store.TryRemove(new KeyValuePair<string, Entry>(key, entry)))
                entry.Value.Dispose();
        }

        private void SweepExpired()
        {
            foreach (var kv in _store)
            {
                if (IsExpired(kv.Value))
                    Evict(kv.Key, kv.Value);
            }
        }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
                throw new ObjectDisposedException(nameof(SecureCache));
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            _sweeper?.Dispose();
            Clear();
        }
    }
}
