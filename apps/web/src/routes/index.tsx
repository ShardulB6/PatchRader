import { createFileRoute, redirect } from "@tanstack/react-router";

// There is no home page: the site opens on the story.
export const Route = createFileRoute("/")({
  beforeLoad: () => {
    throw redirect({ to: "/story" });
  },
});
