using System;

namespace JwtAuthenticator
{
    public sealed class Optional<T>
    {
        private readonly T _value;

        public bool HasValue { get; }

        public T Value
        {
            get
            {
                if (!HasValue)
                    throw new InvalidOperationException($"Optional {typeof(T).Name} has no value.");
                return _value;
            }
        }

        public Optional()
        {
            HasValue = false;
        }

        public Optional(T value)
        {
            _value = value;
            HasValue = value != null;
        }

        public bool IsTrue(Predicate<T> condition)
        {
            return HasValue && condition(_value);
        }

        public bool IsFalse(Predicate<T> condition)
        {
            return HasValue && !condition(_value);
        }

        public override bool Equals(object other)
        {
            return other is Optional<T> ? Equals((Optional<T>)other) : other is T && Equals(new Optional<T>((T)other));
        }

        public bool Equals(Optional<T> other)
        {
            return HasValue ? other.HasValue && _value.Equals(other._value): !other.HasValue;
        }

        public override int GetHashCode()
        {
            return HasValue ? Value.GetHashCode(): int.MaxValue;
        }

        public override string ToString()
        {
            return HasValue ? Value.ToString(): "null";
        }
    }
}
