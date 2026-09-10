import type { SelectOption } from "naive-ui"
import { computed, ref } from "vue"
import Api from "@/api"

/**
 * OpenSearch/Elasticsearch-shaped connectors ("Wazuh-Indexer", "Graylog-OpenSearch", …)
 * as naive-ui select options, for any "which cluster" picker (Event Source, Source
 * Configuration wizard, …).
 *
 * Uses `Api.connectors.getNames()` (admin+analyst, names only) rather than
 * `Api.connectors.getAll()` (admin-only, returns plaintext credentials) -- the latter
 * 403s for analysts, who own the create/update routes these pickers live on, and would
 * silently leave them stuck on the Wazuh-Indexer-only fallback with no way to know why.
 *
 * State is module-level for the same reason as `useCustomerOptions`: the list only
 * moves on operator action and several surfaces need the same options.
 */
const FALLBACK: SelectOption[] = [{ label: "Wazuh-Indexer", value: "Wazuh-Indexer" }]
const INDEXER_NAME_PATTERN = /indexer|opensearch/i

const options = ref<SelectOption[]>(FALLBACK)
const loading = ref(false)
let inflight: Promise<void> | null = null

function fetchConnectorNames(): Promise<void> {
	if (inflight) return inflight

	loading.value = true
	inflight = Api.connectors
		.getNames()
		.then(res => {
			const indexerConnectors = (res.data?.connectors || [])
				.filter(c => INDEXER_NAME_PATTERN.test(c.connector_name))
				.map(c => ({ label: c.connector_name, value: c.connector_name }))
			if (indexerConnectors.length) {
				options.value = indexerConnectors
			}
		})
		.catch(() => {
			// Keep the Wazuh-Indexer fallback option if the connector list can't be loaded.
		})
		.finally(() => {
			loading.value = false
			inflight = null
		})

	return inflight
}

export function useIndexerConnectorOptions() {
	/** Fetch once; a second caller reuses what the first one loaded. */
	function load() {
		if (options.value !== FALLBACK) return Promise.resolve()
		return fetchConnectorNames()
	}

	return {
		options: computed(() => options.value),
		loading: computed(() => loading.value),
		load
	}
}
