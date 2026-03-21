/**
 * MCP tool definitions for the Job Ops server.
 *
 * Each tool calls existing service/repository functions directly.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { getPipelineStatus, runPipeline } from "@server/pipeline/index";
import * as jobsRepo from "@server/repositories/jobs";
import * as pipelineRepo from "@server/repositories/pipeline";
import { transitionStage } from "@server/services/applicationTracking";
import { getProfile } from "@server/services/profile";
import { getEffectiveSettings } from "@server/services/settings";
import * as visaSponsors from "@server/services/visa-sponsors/index";
import type { ApplicationStage, JobStatus } from "@shared/types";
import { z } from "zod";

const JOB_STATUSES: [string, ...string[]] = [
  "discovered",
  "processing",
  "ready",
  "applied",
  "in_progress",
  "skipped",
  "expired",
];

const APPLICATION_STAGE_VALUES: [string, ...string[]] = [
  "applied",
  "recruiter_screen",
  "assessment",
  "hiring_manager_screen",
  "technical_interview",
  "onsite",
  "offer",
  "closed",
];

export function registerTools(server: McpServer): void {
  // 1. list_jobs
  server.tool(
    "list_jobs",
    "List jobs with optional status filter and pagination",
    {
      status: z
        .array(z.enum(JOB_STATUSES))
        .optional()
        .describe("Filter by job status(es)"),
      limit: z
        .number()
        .int()
        .min(1)
        .max(200)
        .optional()
        .describe("Maximum number of jobs to return (default 50)"),
      offset: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe("Number of jobs to skip (default 0)"),
    },
    { readOnlyHint: true, destructiveHint: false },
    async ({ status, limit = 50, offset = 0 }) => {
      try {
        const items = await jobsRepo.getJobListItems(
          status as JobStatus[] | undefined,
        );
        const page = items.slice(offset, offset + limit);
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                { total: items.length, offset, limit, jobs: page },
                null,
                2,
              ),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Error listing jobs: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );

  // 2. get_job
  server.tool(
    "get_job",
    "Get a single job by ID with full details",
    {
      id: z.string().describe("The job ID"),
    },
    { readOnlyHint: true, destructiveHint: false },
    async ({ id }) => {
      try {
        const job = await jobsRepo.getJobById(id);
        if (!job) {
          return {
            content: [{ type: "text" as const, text: `Job not found: ${id}` }],
            isError: true,
          };
        }
        return {
          content: [
            { type: "text" as const, text: JSON.stringify(job, null, 2) },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Error getting job: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );

  // 3. update_job_stage
  server.tool(
    "update_job_stage",
    "Transition a job to a new application stage (applied, recruiter_screen, assessment, hiring_manager_screen, technical_interview, onsite, offer, closed)",
    {
      id: z.string().describe("The job ID"),
      stage: z
        .enum(APPLICATION_STAGE_VALUES)
        .describe("The target application stage"),
      note: z.string().optional().describe("Optional note for the transition"),
    },
    { readOnlyHint: false, destructiveHint: false },
    async ({ id, stage, note }) => {
      try {
        const event = transitionStage(
          id,
          stage as ApplicationStage,
          undefined,
          note ? { note, actor: "user" } : { actor: "user" },
        );
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(event, null, 2),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Error updating stage: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );

  // 4. run_pipeline
  server.tool(
    "run_pipeline",
    "Trigger a pipeline run to discover and process new jobs",
    {
      topN: z
        .number()
        .int()
        .min(1)
        .max(50)
        .optional()
        .describe("Max number of jobs to process"),
      minSuitabilityScore: z
        .number()
        .min(0)
        .max(100)
        .optional()
        .describe("Minimum suitability score threshold"),
    },
    { readOnlyHint: false, destructiveHint: false },
    async ({ topN, minSuitabilityScore }) => {
      try {
        const { isRunning } = getPipelineStatus();
        if (isRunning) {
          return {
            content: [
              {
                type: "text" as const,
                text: "Pipeline is already running. Use get_pipeline_status to check progress.",
              },
            ],
          };
        }

        // Start pipeline in background (same as the API route does)
        runPipeline({ topN, minSuitabilityScore }).catch(() => {
          // Pipeline errors are logged internally
        });

        return {
          content: [
            {
              type: "text" as const,
              text: "Pipeline started. Use get_pipeline_status to monitor progress.",
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Error starting pipeline: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );

  // 5. get_pipeline_status
  server.tool(
    "get_pipeline_status",
    "Get current pipeline status and recent runs",
    {},
    { readOnlyHint: true, destructiveHint: false },
    async () => {
      try {
        const { isRunning } = getPipelineStatus();
        const lastRun = await pipelineRepo.getLatestPipelineRun();
        const recentRuns = await pipelineRepo.getRecentPipelineRuns(5);
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({ isRunning, lastRun, recentRuns }, null, 2),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Error getting pipeline status: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );

  // 6. get_settings
  server.tool(
    "get_settings",
    "Get current application settings",
    {},
    { readOnlyHint: true, destructiveHint: false },
    async () => {
      try {
        const settings = await getEffectiveSettings();
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(settings, null, 2),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Error getting settings: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );

  // 7. get_profile
  server.tool(
    "get_profile",
    "Get the base resume profile from Reactive Resume",
    {},
    { readOnlyHint: true, destructiveHint: false },
    async () => {
      try {
        const profile = await getProfile();
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(profile, null, 2),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Error getting profile: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );

  // 8. search_visa_sponsors
  server.tool(
    "search_visa_sponsors",
    "Search the visa sponsor database by company name",
    {
      query: z.string().min(1).describe("Company name to search for"),
      limit: z
        .number()
        .int()
        .min(1)
        .max(200)
        .optional()
        .describe("Maximum number of results (default 50)"),
      minScore: z
        .number()
        .int()
        .min(0)
        .max(100)
        .optional()
        .describe("Minimum similarity score (default 30)"),
      country: z
        .string()
        .optional()
        .describe("Country code to restrict results to a specific provider"),
    },
    { readOnlyHint: true, destructiveHint: false },
    async ({ query, limit, minScore, country }) => {
      try {
        const results = await visaSponsors.searchSponsors(query, {
          limit,
          minScore,
          countryKey: country,
        });
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                { query, total: results.length, results },
                null,
                2,
              ),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Error searching sponsors: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}
