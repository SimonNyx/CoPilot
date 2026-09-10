import type { Connector, ConnectorRequestPayload } from "@/types/connectors"
import type { FlaskBaseResponse } from "@/types/flask"
import { HttpClient } from "../http-client"

export default {
	getAll(signal?: AbortSignal) {
		return HttpClient.get<FlaskBaseResponse & { connectors: Connector[] }>("/connectors", { signal })
	},
	/**
	 * Names only, no credentials -- admin+analyst (unlike getAll(), which is admin-only
	 * since it returns plaintext connector_password/connector_api_key). Use this for any
	 * cluster/connector picker UI that must also work for the analyst role.
	 */
	getNames(signal?: AbortSignal) {
		return HttpClient.get<FlaskBaseResponse & { connectors: { connector_name: string }[] }>(
			"/connectors/names",
			{ signal }
		)
	},
	configure(connectorId: string | number, payload: ConnectorRequestPayload) {
		return HttpClient.post<FlaskBaseResponse & { connectors: Connector[] }>(`/connectors/${connectorId}`, payload)
	},
	update(connectorId: string | number, payload: ConnectorRequestPayload) {
		return HttpClient.put<FlaskBaseResponse & { connectors: Connector[] }>(`/connectors/${connectorId}`, payload)
	},
	verify(connectorId: string | number) {
		return HttpClient.post<FlaskBaseResponse & { connectionSuccessful: boolean }>(
			`/connectors/verify/${connectorId}`
		)
	},
	upload(connectorId: string | number, formData: FormData) {
		return HttpClient.post<FlaskBaseResponse & { connectors: Connector[] }>(
			`/connectors/upload/${connectorId}`,
			formData
		)
	}
}
