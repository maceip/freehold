export const metadata = {
  title: "Freehold + Next.js",
  description: "Next.js app exposed through Freehold relay",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
