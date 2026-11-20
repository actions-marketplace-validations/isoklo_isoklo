/**
 * Exit codes are part of Isoklo's contract with CI: GitHub Actions and other runners read them to allow or stop a merge.
 * Never reuse a code for a different meaning.
 */
export const ExitCode = {
  /** Every check passed. Safe to merge. */
  Passed: 0,
  /** Isoklo found a problem and the change must not merge as it is. */
  Blocked: 1,
  /** Isoklo could not do its job: bad arguments, unreadable repo, missing test command. Not a verdict on the change. */
  CouldNotRun: 2,
} as const;

export type ExitCode = (typeof ExitCode)[keyof typeof ExitCode];
