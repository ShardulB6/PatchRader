import { Link } from "@tanstack/react-router";

export default function Header() {
  const links = [
    { to: "/", label: "Home" },
    { to: "/story", label: "Story" },
    // Hidden on the live site until the FastAPI backend is deployed behind Caddy.
    ...(import.meta.env.DEV ? ([{ to: "/ai", label: "AI Analyst" }] as const) : []),
  ] as const;

  return (
    <div>
      <div className="flex flex-row items-center justify-between px-2 py-1">
        <nav className="flex gap-4 text-lg" aria-label="Main navigation">
          {links.map(({ to, label }) => (
            <Link key={to} to={to} activeProps={{ className: "font-semibold underline" }}>
              {label}
            </Link>
          ))}
        </nav>
      </div>
      <hr />
    </div>
  );
}
