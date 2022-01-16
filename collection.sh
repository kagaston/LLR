#!/usr/bin/env bash

# TODO add functionality for usage if [[ $? == 0 ]]; see `help test`
# TODO add older check and creation
# TODO add function to create timestamp for file
# TODO add function to create file each command with unique file name
# TODO create find command to blob all log files on the host
# TODO separate log files by compressed uncompressed
# TODO collect etc config files
# TODO collect history files for root and all other users
# TODO collect & hash all executable files
# TODO make loop to gather proc data

LOG_PATH="data/"
EVIDENCE_PATH="_findings"


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

# This function brings in error checking and checks that the command is in the path
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

# TODO update filename to contain timestamp and system name
get_system_info () {
  # This function is used to gather key information on the system
  if [[ $# -eq 0 ]]
    then
      local COMMAND='uname -snrmp'
      local TYPE="config"
      CONTEXT=$(run_cmd $COMMAND)
      CONTEXT=$(echo $CONTEXT | awk '{ print "{\"kernel\": \"" $1 "\",\"node\": \"" $2 "\",\"release\": \"" $3\
                                    "\",\"architecture\": \"" $4 "\",\"processor\": \"" $5 "\"}"}')
      create_directory "$EVIDENCE_PATH/$TYPE"
      echo "[$CONTEXT]" | tee "$EVIDENCE_PATH/$TYPE/system_info.json"
    else
      echo "This function takes 0 positional argument(s)"
  fi
  }

# Gets network configurations
# TODO finish function and map to JSON object
get_network_information () {
#'ifconfig -a'
#'route'
#'netstat -rn'
  pass
}


# Files system information
# TODO finish function and map to JSON object
get_file_system_information () {
#'df'
#'mount'
  pass
}

### SYSTEM STATE INFORMATION:

# Running processes
# TODO update filename to contain timestamp and system name

get_running_process_information () {
  # This function collects data on the running processes
  if [[ $# -eq 0 ]]
    then
      local COMMAND='ps aux'
      local TYPE="state"
      CONTEXT=$(run_cmd $COMMAND | awk '{ if ( NR > 1  ) { print "{\"guid\": \"" $1  "\",\"pid\": \"" $2\
                                "\",\"time\": \""  $9 "\",\"command\": \"" $11 "\"},"}}')
      create_directory "$EVIDENCE_PATH/$TYPE"
      echo "[$CONTEXT]" | tee "$EVIDENCE_PATH/$TYPE/running_process.json"
    else
      echo "This function takes 0 positional argument(s)"
  fi
  }

# Open ports
# TODO finish function and map to JSON object
get_open_port_information () {
#  'netstat -tulpn'
#  'ss -tulpn'
#  'lsof -Pni'
  pass
}

# User context
# TODO finish function and map to JSON object
get_user_information () {
#  'w'
#  'last'
#  'lastb'
  pass
}

# Gets teh loaded kernel modules
# TODO finish function and map to JSON object
get_loaded_modules () {
#'kextstat'                # This will collect loaded modules
#lsmod
  pass
}

# Validates the script is run as the root user
[ "$EUID" == 0 ] || usage

get_system_info
get_running_process_information

