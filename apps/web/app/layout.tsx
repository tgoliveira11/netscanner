import type { Metadata } from 'next';
import { StoreBootstrap } from '../components/StoreBootstrap';
import './globals.css';

export const metadata: Metadata = {
  title: 'NetScanner — Local Network Device Scanner',
  description: 'Discover and classify every device on your local network in real time.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <StoreBootstrap />
        {children}
      </body>
    </html>
  );
}
