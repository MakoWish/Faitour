# Elastic Integration

## Notes

I will eventually get a Faitour integration pushed to the official Elastic repo, but for the time being, you can use the "Custom Logs" integration to collect logs. This basic walkthrough should help you to get all set up.

## Configuration

### Ingest Pipeline

You will find a file `logs-faitour.log@custom.json` in the `ingest_pipeline` folder. Navigate to Dev Tools within Kibana, and type the following in the left pane:

```bash
PUT _ingest/pipeline/logs-faitour.log@custom
```

Immediately below that line, paste the contents of the `logs-faitour.log@custom.json` file. With your cursor anywhere within the content you just created, either click the "play" button, or press `CTRL+ENTER`. On the right side of Dev Tools, you should see a confirmation:

```json
{
  "acknowledged": true
}
```

If you see any errors, you can open an Issue in the Faitour repo, and I will help see what is going on. 

### Elastic Integration

Within Kibana, click on the hamburger menu at the top left, then scroll down toward the bottom and click on "Fleet". Once on the Fleet dashboard, click on the "Agent Policies" tab. If you already have an Agent Policy you would like to use, click into that policy to modify it. If you want to create a new policy, click on the blue "Create agent policy" button toward the top right of the page. 

Once you have a policy created, click into the policy, then click the blue "Add integration" button. Search for "Custom Logs", and you will see a few options, but be sure to specifically select the "Custom Logs" integration. You will again see another blue button on the top right to "Add Custom Logs". Click on that, and you will be taken to a configuration page. Set the following details on this page:

> Integration name: Faitour Logs

> Log file path: /var/log/faitour/*

> Dataset name: faitour.log

Optionally, if you would like to retain the original JSON log in the Elasticsearch documents, expand the `Advanced options` link under "Custom log file", and you will see a field `Tags`. Enter `preserve_original_event` into this field. This will ensure the original log entry is preserved in the Elasticsearch field `event.original`.

Click the "Save and continue" button on the bottom right. You can optionally add other integrations like "Linux Metrics" to collect system metrics, or "System" to collect system logs. Once you are happy with your Agent Policy, click on the blue "Actions" button on the top right, then select "Add agent". Follow the steps to get Elastic Agent installed onto your honeypot, and you should be good to go! 

### Detection Rules

What good is a honeypot if you aren't alerted to activity against that honeypot?! I have provided two detection rules that can be imported into Kibana to be alerted of activity.

#### The Rules

1. Faitour HoneyPot Port Scan Detected (port_scan_detected.ndjson)
  a. This is an Event Correlation rule that watches for 10 or more SYN packets against various ports on your honeypot. This could indicate an overall network scan, or someone enumerating the honeypot itself. 
2. Faitour HoneyPot Trigger Detected (honeypot_triggered.ndjson)
  a. This rule is designed to alert you when somebody interacts with the services you have enabled on the honeypot. This could indicate an aggressive scan of the machine, or somebody actually interacting with the services.

#### Installation

To install one or both of these detection rules, open Kiban and click the hamburger menu on the top left. Scroll down to the Security section, and click on "Rules". Once on the Rules page, click on "Detection rules (SIEM)". On this page, click the blue link toward the top right that says "Import rules". You will be prompted with a "drag and drop" dialog to drop one of the rules at a time. Once you have added these rules, click into each one of them, edit the rule settings, and be sure to add an Action so you are alerted to honeypot activity. If you have a license for Elasticsearch, you can choose any of the available alert types. If you do not have a license, I would suggest using [ElastAlert2](https://github.com/jertel/elastalert2), but configuring that is beyond the scopy of this document.

### Testing

Once you have performed all the above steps, you should be ready to test out the alerts. Perform an nmap scan `nmap -T4 SystemName`, and you should receive an alert of a port scan against your honeypot. Take it one step further with `nmap -T4 -sV SystemName`, and you should receive an alert of activity against the hosted services.

### Contributing

If you think of any additional Detection Rules that would help alert to activity against these honeypots, please open a [Discussion](../../discussions) in the repo, and let's talk about it!
