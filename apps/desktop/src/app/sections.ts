/** The three primary sections. The constitution forbids adding a fourth; a test enforces it. */
export const SECTIONS = [
  { id: "claude", label: "CLAUDE", hint: "Research · architecture · Claude Code" },
  { id: "codex", label: "CODEX", hint: "Engineering · terminal · tests · Git" },
  { id: "brain", label: "BRAIN & WORKFLOW", hint: "Commander · providers · memory · security" },
] as const;

export type SectionId = (typeof SECTIONS)[number]["id"];
