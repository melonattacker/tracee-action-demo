def getarg(name): .args[] | select(.name == "triggeredBy") | .value.args[] | select(.name == name);

def discard_items(dns): if dns | length > 0 then map(select([startswith(dns[])] | any | not)) else . end;

[
  .[] | getarg("dns_questions")
] | discard_items($config[0].dns_discard) | unique
