

# COA examples

## Malicious domain blocking rule -> could be translated to DNS block rule by CDO/OpenDNS
if sighting.Observable.verdict is MALICIOUS and sighting.Observable.type is "domain" then generateCOA where,
{"id":"generatedCOA-2017-02-22T22:43:02.489Z",
 "description":"COA for indicator - Remote Access Trojan (RAT) Sality Network Communications",
 "tlpLevel":$sighting.indicator.tlpLevel,
 "openC2COA":{
 	"action":"DENY",
 	"target":{
 		"type":domain,
 		"specifier":$sighting.Observable.value},
 	"actuator":{
 		"type":"NETWORK"},
 	"modifiers":{
 		"method":"BLACKLIST",
 		"location":"PERIMETER"}}}
 		
## Malicious IP blocking rule -> could be translated to firewall ACL by CDO
 	{
 	"id":"https://tenzin-beta.amp.cisco.com:443/ctia/coa/coa-db54bb35-7b28-48da-b3b9-d9620d8d8b98",
    "description":"COA for blocking a Command and control variant",
    "valid_time":{
      "start_time":"2016-12-09T16:46:39.608Z",
      "end_time":"2016-12-09T16:46:39.608Z"
    },
    "stage":"Remedy",
    "efficacy":"Medium",
    "type":"coa",
    "created":"2016-12-09T16:48:59.082Z",
    "coa_type":"Perimeter Blocking",
    "tlp":"white",
    "openC2COA":{
		    "id":"openc2-coa-1",
		    "action":"DENY",
		    "target":{
		    	"type":"ip",
		    	"specifiers":$sighting.Observable.value},
		    "actuator":{
		    	"type":"network.firewall"
		    },
		    "modifiers":{
				    "response":"acknowledge",
				    "method"="ACL",
				    "location"="PERIMETER",
				    "time":{"start_time":"2016-12-09T16:46:39.608Z","end_time":"2016-12-09T16:56:39.608Z"}
				}
    },
    "structured_coa_type":"openc2",
    "owner":"Unknown"
    }

## Malicious IP blocking rule -> could be translated to router ACL by APIC-EM
 	{
 	"id":"https://tenzin-beta.amp.cisco.com:443/ctia/coa/coa-db54bb35-7b28-48da-b3b9-d9620d8d8b98",
    "description":"COA for blocking a Command and control variant",
    "valid_time":{
      "start_time":"2016-12-09T16:46:39.608Z",
      "end_time":"2016-12-09T16:46:39.608Z"
    },
    "stage":"Remedy",
    "efficacy":"Medium",
    "type":"coa",
    "created":"2016-12-09T16:48:59.082Z",
    "coa_type":"Internal Blocking",
    "tlp":"white",
    "openC2COA":{
		    "id":"openc2-coa-2",
		    "action":"DENY",
		    "target":{
		    	"type":"ip",
		    	"specifiers":$sighting.Observable.value},
		    "actuator":{
		    	"type":"network.router"
		    },
		    "modifiers":{
				    "response":"acknowledge",
				    "method"="ACL",
				    "location"="INTERNAL",
				    "time":{"start_time":"2016-12-09T16:46:39.608Z","end_time":"2016-12-09T16:56:39.608Z"}
				}
    },
    "structured_coa_type":"openc2",
    "owner":"Unknown"
    }

