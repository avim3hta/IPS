-- Snort 3.0 configuration

-- Setup the network addresses you are protecting
HOME_NET = 'any'
EXTERNAL_NET = 'any'

-- Set up the rule paths
RULE_PATH = '../rules'

-- Configure DAQ for inline mode
daq = {
    module_dirs = {
        '/usr/local/lib/daq',
    },
    modules = {
        {
            name = 'pcap',
            mode = 'inline'
        }
    }
}

-- Configure output
alert_fast = {
    file = true,
    packet = false
}

-- Configure alerts
alerts = {
    alert_with_interface_name = true,
    detection_filter_memcap = 1048576,
    event_filter_memcap = 1048576,
    log_references = true,
    order = 'drop reject sdrop alert log',
    rate_filter_memcap = 1048576
}

-- Configure inline mode
inline = {
    mode = 'tap',
    interface = 'wlo1'
}

-- Include rules
include = 'rules/local.rules' 