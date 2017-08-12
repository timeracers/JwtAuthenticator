using System;

public struct Optional<T>
{
    public bool HasValue { get; private set; }
    private T value;
    public T Value
    {
        get
        {
            if(!HasValue) throw new InvalidOperationException();
            return value;
        }
    }

    public Optional(T value)
    {
        this.value = value;
        HasValue = true;
    }

    public static implicit operator Optional<T>(T value)
    {
        return new Optional<T>(value);
    }

    public override bool Equals(object obj)
    {
        if (obj is Optional<T>)
            return this.Equals((Optional<T>)obj);
        else
            return false;
    }
    public bool Equals(Optional<T> other)
    {
        if (HasValue && other.HasValue)
            return value.Equals(other.value);
        else
            return HasValue == other.HasValue;
    }

    public override string ToString()
    {
        return HasValue ? Value.ToString() : "null";
    }

    public override int GetHashCode()
    {
        return HasValue ? int.MaxValue : value.GetHashCode(); 
    }
}