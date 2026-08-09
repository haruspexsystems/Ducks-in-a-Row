import { Search, X } from 'lucide-react';
import { useState, useCallback, useEffect, useRef } from 'react';

interface SearchBarProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}

export function SearchBar({ value, onChange, placeholder = 'Search certificates...' }: SearchBarProps) {
  const [localValue, setLocalValue] = useState(value);
  const timerRef = useRef<ReturnType<typeof setTimeout>>();

  // Debounce: update parent after 300ms of no typing
  const debouncedOnChange = useCallback(
    (val: string) => {
      if (timerRef.current) clearTimeout(timerRef.current);
      timerRef.current = setTimeout(() => onChange(val), 300);
    },
    [onChange]
  );

  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  // Sync external changes
  useEffect(() => {
    setLocalValue(value);
  }, [value]);

  const handleChange = (val: string) => {
    setLocalValue(val);
    debouncedOnChange(val);
  };

  return (
    <div className="relative">
      <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-faint" />
      <input
        type="text"
        value={localValue}
        onChange={(e) => handleChange(e.target.value)}
        placeholder={placeholder}
        className="w-full pl-10 pr-8 py-2 bg-surface border border-hairline-strong rounded-lg text-sm
                   placeholder:text-faint focus:outline-none focus:ring-2 focus:ring-certus-500
                   focus:border-certus-500 transition-colors"
      />
      {localValue && (
        <button
          onClick={() => handleChange('')}
          aria-label="Clear search"
          className="absolute right-2 top-1/2 -translate-y-1/2 p-0.5 rounded hover:bg-sunken-strong"
        >
          <X className="h-4 w-4 text-faint" />
        </button>
      )}
    </div>
  );
}
