export type EventType = "EDR" | "EPP" | "Cloud Integration" | "Network Security"

export interface DisplayColumn {
	/** Field path in the event _source object (dotted, e.g. "agent.name"). */
	key: string
	/** Human-readable column header. */
	label: string
	/** Optional pixel width hint. */
	width?: number | null
}

export interface EventSource {
	id: number
	customer_code: string
	name: string
	index_pattern: string
	event_type: EventType
	time_field: string
	/** Name of the connector (in `connectors`) whose cluster hosts `index_pattern`. Defaults to "Wazuh-Indexer". */
	connector_name: string
	enabled: boolean
	displayed_columns?: DisplayColumn[] | null
	created_at: string
	updated_at: string
}
