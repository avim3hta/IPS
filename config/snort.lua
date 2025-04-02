-- Snort 3.0 configuration

-- Network variables
HOME_NET = 'any'
EXTERNAL_NET = 'any'

-- Basic configuration
daq = {
    module_dirs = {
        '/usr/local/lib/daq'
    },
    modules = {
        {
            name = 'afpacket',
            mode = 'passive'
        }
    }
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

-- Define output formats
alert_fast = { 
    file = true,
    filename = 'alert_fast.txt'
}

-- Configure logging
packets = {
    limit = 100
}

-- Define packet processing
process = {
    all_traffic = true,
    show_year = true
}

-- Configure output plugins
output = {
    file = true,
    show_year = true
}

-- Include rules
include = 'rules/local.rules' 