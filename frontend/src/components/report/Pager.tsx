export function Pager({ offset, limit, total, busy, onPage }: { offset: number; limit: number; total: number; busy: boolean; onPage: (offset: number) => void }) {
  if (total <= limit && offset === 0) {
    return <p className="muted pager-summary">{total === 1 ? "1 item" : `${total} items`}</p>;
  }
  const first = total === 0 ? 0 : offset + 1;
  const last = Math.min(offset + limit, total);
  return (
    <nav className="pager" aria-label="Pages">
      <span>
        Showing {first}&ndash;{last} of {total}
      </span>
      <button type="button" onClick={() => onPage(Math.max(0, offset - limit))} disabled={busy || offset === 0}>
        Previous
      </button>
      <button type="button" onClick={() => onPage(offset + limit)} disabled={busy || offset + limit >= total}>
        Next
      </button>
    </nav>
  );
}
