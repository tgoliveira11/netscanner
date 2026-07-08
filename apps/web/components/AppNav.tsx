'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

const links = [
  { href: '/', label: 'Dashboard' },
  { href: '/topology/', label: 'Topology' },
  { href: '/relations/', label: 'Relations' },
  { href: '/admin/', label: 'Admin' },
] as const;

/** Primary navigation shared across dashboard, topology, relations, and admin. */
export function AppNav() {
  const pathname = usePathname();

  return (
    <nav className="flex flex-wrap items-center gap-1">
      {links.map((link) => {
        const active =
          link.href === '/'
            ? pathname === '/' || pathname === ''
            : pathname?.startsWith(link.href.replace(/\/$/, ''));
        return (
          <Link
            key={link.href}
            href={link.href}
            className={`btn btn-ghost text-xs ${active ? 'border-accent/40 bg-panelup text-slate-100' : ''}`}
          >
            {link.label}
          </Link>
        );
      })}
    </nav>
  );
}
