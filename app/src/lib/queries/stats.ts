import { createQuery } from "@tanstack/svelte-query"
import { statsQueryDocument, transfersPerDayQueryDocument } from "$lib/graphql/queries/stats.ts"

import { request } from "graphql-request"
import { URLS } from "$lib/constants"

export const statsQuery = () =>
  createQuery({
    queryKey: ["stats"],
    queryFn: async () => (await request(URLS().GRAPHQL, statsQueryDocument, {})).v1_statistics,
    enabled: true,
    refetchInterval: 5_000,
    refetchOnWindowFocus: false
  })

export const transfersPerDayQuery = (limit: number) =>
  createQuery({
    queryKey: ["transfer-per-day"],
    queryFn: async () =>
      (await request(URLS().GRAPHQL, transfersPerDayQueryDocument, { limit })).v1_daily_transfers,
    enabled: true,
    refetchInterval: 6_000,
    refetchOnWindowFocus: false
  })
