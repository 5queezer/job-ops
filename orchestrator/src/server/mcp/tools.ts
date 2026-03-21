/**
 * MCP tool definitions for the Job Ops server.
 *
 * Each tool calls existing service/repository functions directly.
 *
 * Uses ZodRawShapeCompat type assertion to work around Zod v3/v4
 * type compatibility issues with the MCP SDK.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ZodRawShapeCompat } from "@modelcontextprotocol/sdk/server/zod-compat.js";
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

/** Type assertion helper for Zod schemas to satisfy MCP SDK's ZodRawShapeCompat */
function shape<T extends Record<string, z.ZodTypeAny>>(
  s: T,
): ZodRawShapeCompat {
  return s as unknown as ZodRawShapeCompat;
}

function textResult(data: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}

function errorResult(prefix: string, error: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: `${prefix}: ${error instanceof Error ? error.message : String(error)}`,
      },
    ],
    isError: true,
  };
}

export function registerTools(server: McpServer): void {
  // 1. list_jobs
  server.tool(
    "list_jobs",
    "List jobs with optional status filter and pagination",
    shape({
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
    }),
    { readOnlyHint: true, destructiveHint: false },
    async (args) => {
      const {
        status,
        limit = 50,
        offset = 0,
      } = args as {
        status?: string[];
        limit?: number;
        offset?: number;
      };
      try {
        const items = await jobsRepo.getJobListItems(
          status as JobStatus[] | undefined,
        );
        const page = items.slice(offset, offset + limit);
        return textResult({ total: items.length, offset, limit, jobs: page });
      } catch (error) {
        return errorResult("Error listing jobs", error);
      }
    },
  );

  // 2. get_job
  server.tool(
    "get_job",
    "Get a single job by ID with full details",
    shape({
      id: z.string().describe("The job ID"),
    }),
    { readOnlyHint: true, destructiveHint: false },
    async (args) => {
      const { id } = args as { id: string };
      try {
        const job = await jobsRepo.getJobById(id);
        if (!job) {
          return errorResult("Job not found", id);
        }
        return textResult(job);
      } catch (error) {
        return errorResult("Error getting job", error);
      }
    },
  );

  // 3. update_job_stage
  server.tool(
    "update_job_stage",
    "Transition a job to a new application stage (applied, recruiter_screen, assessment, hiring_manager_screen, technical_interview, onsite, offer, closed)",
    shape({
      id: z.string().describe("The job ID"),
      stage: z
        .enum(APPLICATION_STAGE_VALUES)
        .describe("The target application stage"),
      note: z.string().optional().describe("Optional note for the transition"),
    }),
    { readOnlyHint: false, destructiveHint: false },
    async (args) => {
      const { id, stage, note } = args as {
        id: string;
        stage: string;
        note?: string;
      };
      try {
        const event = transitionStage(
          id,
          stage as ApplicationStage,
          undefined,
          note ? { note, actor: "user" } : { actor: "user" },
        );
        return textResult(event);
      } catch (error) {
        return errorResult("Error updating stage", error);
      }
    },
  );

  // 4. run_pipeline
  server.tool(
    "run_pipeline",
    "Trigger a pipeline run to discover and process new jobs",
    shape({
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
    }),
    { readOnlyHint: false, destructiveHint: false },
    async (args) => {
      const { topN, minSuitabilityScore } = args as {
        topN?: number;
        minSuitabilityScore?: number;
      };
      try {
        const { isRunning } = getPipelineStatus();
        if (isRunning) {
          return textResult(
            "Pipeline is already running. Use get_pipeline_status to check progress.",
          );
        }

        runPipeline({ topN, minSuitabilityScore }).catch(() => {
          // Pipeline errors are logged internally
        });

        return textResult(
          "Pipeline started. Use get_pipeline_status to monitor progress.",
        );
      } catch (error) {
        return errorResult("Error starting pipeline", error);
      }
    },
  );

  // 5. get_pipeline_status
  server.tool(
    "get_pipeline_status",
    "Get current pipeline status and recent runs",
    shape({}),
    { readOnlyHint: true, destructiveHint: false },
    async () => {
      try {
        const { isRunning } = getPipelineStatus();
        const lastRun = await pipelineRepo.getLatestPipelineRun();
        const recentRuns = await pipelineRepo.getRecentPipelineRuns(5);
        return textResult({ isRunning, lastRun, recentRuns });
      } catch (error) {
        return errorResult("Error getting pipeline status", error);
      }
    },
  );

  // 6. get_settings
  server.tool(
    "get_settings",
    "Get current application settings",
    shape({}),
    { readOnlyHint: true, destructiveHint: false },
    async () => {
      try {
        const settings = await getEffectiveSettings();
        return textResult(settings);
      } catch (error) {
        return errorResult("Error getting settings", error);
      }
    },
  );

  // 7. get_profile
  server.tool(
    "get_profile",
    "Get the base resume profile from Reactive Resume",
    shape({}),
    { readOnlyHint: true, destructiveHint: false },
    async () => {
      try {
        const profile = await getProfile();
        return textResult(profile);
      } catch (error) {
        return errorResult("Error getting profile", error);
      }
    },
  );

  // 8. search_visa_sponsors
  server.tool(
    "search_visa_sponsors",
    "Search the visa sponsor database by company name",
    shape({
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
        .describe("Country code to restrict results (e.g. 'gb')"),
    }),
    { readOnlyHint: true, destructiveHint: false },
    async (args) => {
      const { query, limit, minScore, country } = args as {
        query: string;
        limit?: number;
        minScore?: number;
        country?: string;
      };
      try {
        const results = await visaSponsors.searchSponsors(query, {
          limit,
          minScore,
          countryKey: country,
        });
        return textResult({ query, total: results.length, results });
      } catch (error) {
        return errorResult("Error searching sponsors", error);
      }
    },
  );
}
