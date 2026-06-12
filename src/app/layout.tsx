import type { Metadata } from "next";
import { IBM_Plex_Sans, Space_Grotesk, Geist_Mono } from "next/font/google";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";
import { TooltipProvider } from "@/components/ui/tooltip";
import { getPlatformSettings } from "@/lib/platform-settings";
import { PLATFORM_DEFAULTS } from "@/lib/constants";
import { hexToOklch } from "@/lib/color";

const plexSans = IBM_Plex_Sans({
  variable: "--font-plex-sans",
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
});

const spaceGrotesk = Space_Grotesk({
  variable: "--font-space-grotesk",
  subsets: ["latin"],
  weight: ["500", "600", "700"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export async function generateMetadata(): Promise<Metadata> {
  const settings = await getPlatformSettings();
  return {
    title: settings.siteName,
    description: "Threat detection & prevention rule library",
  };
}

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const settings = await getPlatformSettings();
  const accentOklch =
    settings.accentColor !== PLATFORM_DEFAULTS.accentColor
      ? hexToOklch(settings.accentColor)
      : null;

  return (
    <html
      lang="en"
      className={`${plexSans.variable} ${spaceGrotesk.variable} ${geistMono.variable} h-full antialiased`}
      suppressHydrationWarning
    >
      <body className="min-h-full flex flex-col">
        {accentOklch && (
          <style
            // Overrides the default cyan accent with the configured branding color.
            dangerouslySetInnerHTML={{
              __html: `:root, .dark { --primary: ${accentOklch}; --ring: ${accentOklch}; --chart-1: ${accentOklch}; --sidebar-primary: ${accentOklch}; --sidebar-ring: ${accentOklch}; }`,
            }}
          />
        )}
        <ThemeProvider
          attribute="class"
          defaultTheme="dark"
          enableSystem
          disableTransitionOnChange
        >
          <TooltipProvider delay={200}>{children}</TooltipProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
