/** A changed file with its content on both sides, for rules that compare before and after. */
import type { FileDiff } from "../check/diff.js";

export interface FileChange {
  path: string;
  /** Path before the change (differs for renames). */
  oldPath: string;
  status: FileDiff["status"];
  diff: FileDiff;
  /** Content before the change (null if the file is new). */
  before: string | null;
  /** Content after the change (null if the file was deleted). */
  after: string | null;
}
