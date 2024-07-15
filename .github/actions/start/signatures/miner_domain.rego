package tracee.CUSTOM_MD
import data.tracee.helpers

__rego_metadoc__ := {
	"id": "CUSTOM_MD",
	"version": "0.1.0",
	"name": "miner_domain",
	"eventName": "miner_domain",
	"description": "Check for commom cryptominers domains access",
}

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
		"name": "net_packet_dns_request",
	}
}

domains := [
	"miner1.example.com",
    "miner2.example.com",
    "miner3.example.com",
]

tracee_match {
	input.eventName == "net_packet_dns_request"
	dns_questions := helpers.get_tracee_argument("dns_questions")
	domains[_] = dns_questions[_].query
}