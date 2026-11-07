import { createFileRoute } from "@tanstack/react-router";

import { StoryPage } from "../features/story/story-page";

export const Route = createFileRoute("/story")({
  head: () => ({ meta: [{ title: "Before the breach | PatchRader" }] }),
  component: StoryPage,
});
