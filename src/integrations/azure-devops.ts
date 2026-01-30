import fs from "node:fs/promises";
import path from "node:path";
import type { Logger } from "../utils/logger";
import { createIntegrationHttpClient } from "../utils/http-factory";

export function isAzurePipelines(
  env: Record<string, string | undefined> = process.env,
): boolean {
  return !!(env.TF_BUILD || env.AZURE_HTTP_USER_AGENT);
}

export function vsoLogIssue(type: "error" | "warning", message: string): void {
  // Azure DevOps logging commands: https://learn.microsoft.com/azure/devops/pipelines/scripts/logging-commands
  // eslint-disable-next-line no-console
  console.log(`##vso[task.logissue type=${type}]${escapeVso(message)}`);
}

export function vsoUploadFile(filePath: string): void {
  // eslint-disable-next-line no-console
  console.log(`##vso[task.uploadfile]${escapeVso(filePath)}`);
}

export function vsoUploadSummary(filePath: string): void {
  // eslint-disable-next-line no-console
  console.log(`##vso[task.uploadsummary]${escapeVso(filePath)}`);
}

export function vsoSetVariable(
  name: string,
  value: string,
  opts?: { isOutput?: boolean; isSecret?: boolean },
): void {
  const props = [opts?.isOutput && "isOutput=true", opts?.isSecret && "issecret=true"].filter(Boolean);
  const propStr = props.length ? ";" + props.join(";") : "";
  // eslint-disable-next-line no-console
  console.log(`##vso[task.setvariable variable=${escapeVso(name)}${propStr}]${escapeVso(value)}`);
}

function escapeVso(s: string): string {
  return s.replace(/\r/g, "%0D").replace(/\n/g, "%0A").replace(/;/g, "%3B").replace(/]/g, "%5D");
}

export interface PullRequestCommentOptions {
  /** If true, do nothing if PR context is missing */
  bestEffort?: boolean;
  apiVersion?: string;
}

export async function postPullRequestComment(
  markdown: string,
  env: Record<string, string | undefined>,
  logger: Logger,
  opts: PullRequestCommentOptions = {},
): Promise<void> {
  const prId =
    env.SYSTEM_PULLREQUEST_PULLREQUESTID ||
    env.SYSTEM_PULLREQUEST_PULLREQUESTNUMBER;
  const repoId = env.BUILD_REPOSITORY_ID;
  const project = env.SYSTEM_TEAMPROJECT;
  const collectionUri = env.SYSTEM_COLLECTIONURI;
  const token = env.SYSTEM_ACCESSTOKEN;

  if (!prId || !repoId || !project || !collectionUri || !token) {
    if (!opts.bestEffort) {
      throw new Error(
        "Missing Azure DevOps PR context. Need SYSTEM_PULLREQUEST_PULLREQUESTID, BUILD_REPOSITORY_ID, SYSTEM_TEAMPROJECT, SYSTEM_COLLECTIONURI, SYSTEM_ACCESSTOKEN.",
      );
    }
    return;
  }

  const apiVersion = opts.apiVersion ?? "7.1-preview.1";
  const url = `${collectionUri}${project}/_apis/git/repositories/${repoId}/pullRequests/${prId}/threads?api-version=${apiVersion}`;

  const http = createIntegrationHttpClient(15000, logger, {
    Authorization: `Bearer ${token}`,
  });

  await http.postJson<unknown>(url, {
    comments: [{ parentCommentId: 0, content: markdown, commentType: 1 }],
    status: 1,
  }, { "content-type": "application/json" });
}

export async function writeAndUploadSummary(
  outputDir: string,
  basename: string,
  markdown: string,
): Promise<string> {
  const p = path.join(outputDir, `${basename}.summary.md`);
  await fs.writeFile(p, markdown, "utf-8");
  vsoUploadSummary(p);
  return p;
}
