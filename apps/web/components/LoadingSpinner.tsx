'use client';

export function LoadingSpinner({ label = 'Loading…', className = '' }: { label?: string; className?: string }) {
  return (
    <div className={`flex items-center justify-center gap-2 py-8 text-sm text-muted ${className}`}>
      <span
        className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-edge border-t-accent"
        aria-hidden
      />
      <span>{label}</span>
    </div>
  );
}

export function LoadingBlock({
  loading,
  label,
  children,
  minHeight = '6rem',
}: {
  loading: boolean;
  label?: string;
  children: React.ReactNode;
  minHeight?: string;
}) {
  if (loading) {
    return (
      <div style={{ minHeight }}>
        <LoadingSpinner label={label} />
      </div>
    );
  }
  return <>{children}</>;
}
