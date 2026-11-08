import { createFileRoute } from "@tanstack/react-router";

import { DocumentationPage } from "../features/documentation/documentation-page";

export const Route = createFileRoute("/documentation")({
  head: () => ({ meta: [{ title: "Documentation | PatchRader" }] }),
  component: DocumentationPage,
});
