'use client';

import type { AdminTabId } from './AdminTabs';

/** Keeps tab content mounted and updating while hidden (no unmount on tab switch). */
export function AdminTabPanel({
  tab,
  active,
  children,
  className = 'space-y-4',
}: {
  tab: AdminTabId;
  active: AdminTabId;
  children: React.ReactNode;
  className?: string;
}) {
  const isActive = tab === active;
  return (
    <div
      id={`admin-tab-${tab}`}
      className={isActive ? className : 'hidden'}
      aria-hidden={!isActive}
      hidden={!isActive}
    >
      {children}
    </div>
  );
}
