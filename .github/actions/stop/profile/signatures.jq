.[] |  
select( .eventName == "sched_process_exec" or .eventName == "net_packet_dns_request" or .eventName == "file_modification" | not )
