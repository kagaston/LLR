#!/usr/bin/env bash

# TODO add functionality for usage if [[ $? == 0 ]]; see `help test`
# TODO create find command to blob all log files on the host
# TODO separate log files by compressed uncompressed
# TODO collect var log files
# TODO collect etc config files
# TODO collect history files for root and all other users
# TODO collect & hash all executable files
# TODO make loop to gather proc data

EVIDENCE_PATH="_findings"
LOG_PATH="data/"
HOSTNAME=$(hostname)
FILE_TIMESTAMP=$(TZ=":UTC" date +"%Y%m%d")

### SHARED FUNCTIONS:

# TODO update usage section
usage () {
  # This is used to print error to screen for script usage validation
  echo "This $0 script needs to be run as the root user, the current user is $(whoami), exiting script"
#  exit 1
}

get_utc_date () {
  # This sets the date command in a function to pull UTC timestamp
  DATE_UTC=$(TZ=":UTC" date)
  echo "$DATE_UTC"
}

create_directory () {
  # This function creates the directory if it does not already exist
  if [[ $# -eq 1 ]]
    then
      local LOCAL_PATH=$1
      [[ -d $LOCAL_PATH ]] || mkdir -p $LOCAL_PATH
    else
      echo "This function takes 1 positional argument(s)"
  fi
}

command_exists_run () {
  # This runs a if exist "0"  run else "1" continue to the next action
  local COMMAND=$1
  [ $(command -v $COMMAND ) ]
}

log_command_error_message () {
  # This function will create a JSON error message, if the command is not found in the current path
  if [[ $# -eq 1 ]]
    then
      local COMMAND=$1
      local MESSAGE="Failed to run $COMMAND, the command was not found in the path"
      local CONTEXT="{\"Timestamp\": \"$(get_utc_date)\", \"Command\": \"$COMMAND\", \"Message\": \"$MESSAGE\"}"
      create_directory $LOG_PATH
      echo $CONTEXT >> $LOG_PATH/error.log
    else
      echo "This function takes 1 positional argument"
  fi
}

# TODO review logging functionality
run_cmd () {
  # Performing command validation to ensure the command is in the path
  # TODO Make function and extract for a DRY approach
  local COMMAND=$1
  local FLAGS=$2
  if command_exists_run $COMMAND
    then
      local FULL_COMMAND="$COMMAND $FLAGS"
      $FULL_COMMAND 2>/dev/null
    else
      log_command_error_message $COMMAND
  fi
  }


### SYSTEM CONFIGURATIONS:

save_json () {
  # This function takes in 2 arguments to create a unique file path/name
  if [[ $# -eq 2 ]]
    then
      local SELF=$1
      local TYPE=$2
      create_directory "$EVIDENCE_PATH/$TYPE"
      echo "[$CONTEXT]" | tee "$EVIDENCE_PATH/$TYPE/$SELF$FILE_TIMESTAMP.json"
  else
    echo "This function takes 2 positional argument(s)"
  fi
}

get_system_info () {
  # This function is used to gather key information on the system
  if [[ $# -eq 0 ]]
    then
      local COMMAND='uname -snrmp'
      local TYPE="config"
      local SELF="system_info_"
      CONTEXT=$(run_cmd $COMMAND)
      CONTEXT=$(echo $CONTEXT | awk '{ print "{\"kernel\": \"" $1 "\",\"node\": \"" $2 "\",\"release\": \"" $3\
                                    "\",\"architecture\": \"" $4 "\",\"processor\": \"" $5 "\"}"}')
      echo "[$CONTEXT]" | save_json $SELF $TYPE
    else
      echo "This function takes 0 positional argument(s)"
  fi
  }

# TODO Create function
# TODO Map output to JSON object
# TODO Export JSON to file
get_network_information () {
#'ifconfig -a'
#'route'
#'netstat -rn'
  pass
}


# TODO Create function
# TODO Map output to JSON object
# TODO Export JSON to file
get_file_system_information () {
#'df'
#'mount'
  pass
}

### SYSTEM STATE INFORMATION:

get_running_process_information () {
  # This function collects data on the running processes
  if [[ $# -eq 0 ]]
    then
      local COMMAND='ps aux'
      local TYPE="state"
      local SELF="running_processes_"
      CONTEXT=$(run_cmd $COMMAND | awk '{ if ( NR > 1  ) { print "{\"guid\": \"" $1  "\",\"pid\": \"" $2\
                                "\",\"time\": \""  $9 "\",\"command\": \"" $11 "\"},"}}')
      echo "[$CONTEXT]" | save_json $SELF $TYPE
    else
      echo "This function takes 0 positional argument(s)"
  fi
  }

# TODO Create function
# TODO Map output to JSON object
# TODO Export JSON to file
get_open_port_information () {
#  This function collects the open port information on the host
#  'netstat -tulpn'
#  'ss -tulpn'
#  'lsof -Pni'
  pass
}

# TODO Create function
# TODO Map output to JSON object
# TODO Export JSON to file
get_user_information () {
#  'w'
#  'last'
#  'lastb'
  pass
}

# TODO Create function
# TODO Map output to JSON object
# TODO Export JSON to file
get_loaded_modules () {
#'kextstat'                # This will collect loaded modules
#lsmod
  pass
}

# Validates the script is run as the root user
[ "$EUID" == 0 ] || usage

get_system_info
get_running_process_information

