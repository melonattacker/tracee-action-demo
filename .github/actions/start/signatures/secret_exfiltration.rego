package tracee.TRC_1003
import data.tracee.helpers

__rego_metadoc__ := {
	"id": "TRC_1003",
	"version": "0.1.0",
	"name": "secret_exfiltration",
	"eventName": "sendto",
	"description": "Detect exfiltration of secrets like GITHUB_TOKEN or Actions Secret",
}

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
		"name": "security_socket_sendmsg",
	}
}

tracee_match = res {
	input.eventName == "security_socket_sendmsg"
	data := helpers.get_tracee_argument("data")
	secrets := {"hoge"} 
	secret_found := false
	# secrets 内のどれかが data に含まれていれば secret_found を true にする
	secret_found = true {
		secret := secrets[_]
		contains(data, secret)
	}
	secret_found
}
