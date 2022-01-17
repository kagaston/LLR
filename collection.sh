#!/usr/bin/env bash

# TODO create find command to blob all log files on the host
# TODO separate log files by compressed uncompressed
# TODO collect var log files
# TODO collect etc config files
# TODO collect history files for root and all other users
# TODO collect & hash all executable files
# TODO make loop to gather proc data

# Setting global variables
EVIDENCE_PATH="_findings"
LOG_PATH="data/"
HOSTNAME=$(hostname)
FILE_TIMESTAMP=$(TZ=":UTC" date +"%Y%m%d")


usage () {
  # This is used to print error to screen for script usage validation

  echo "This $0 script needs to be run as the root user, the current user is $(whoami), exiting script"
  exit 1
}


time_it () {
  # This wrapper function calculates the time a function takes to run and prints to screen
  # Setting local variables
  if [[ $# -eq 1 ]]
    then
      # Setting local variables
      local FUNCTION=$1

      # Grabbing start time
      START_TIME=$(date +%s)
        $FUNCTION
      # Grabbing end time
      END_TIME=$(date +%s)

      # Calculating time to run
      RUNTIME=$((END_TIME - START_TIME))

      echo "The script completed in $RUNTIME"

    else
      echo "This function takes 1 positional argument(s) $# were provided"
  fi
}


get_utc_date () {
  # This function sets the date command in a function to pull UTC timestamp

  # Setting local variables
  local DATE_UTC=$(TZ=":UTC" date)

  echo "$DATE_UTC"
}


create_directory () {
  # This function creates the directory if it does not already exist

  if [[ $# -eq 1 ]]
    then
      # Setting local variables
      local LOCAL_PATH=$1

      # Uses "-d" directory test to check for file path
      [[ -d $LOCAL_PATH ]] || mkdir -p $LOCAL_PATH

    else
      echo "This function takes 1 positional argument(s) $# were provided"
  fi
}


command_exists_run () {
  # This function validates the command is in the path and runs the command if it exist

  if [[ $# -gt 0 ]]
    then
      # Setting local variables
      local COMMAND=$1

      # Uses the command to validate if the command is in the running shell's process PATH
      [ $(command -v $COMMAND ) ]

    else
      echo "This function takes 1 positional argument(s) $# were provided"
  fi
}


log_command_error_message () {
  # This function will create a JSON error message, if the command is not found in the current path

  if [[ $# -eq 1 ]]
    then
      # Setting local variables
      local COMMAND=$1
      local MESSAGE="Failed to run $COMMAND, the command was not found in the path"
      local CONTEXT="{\"Timestamp\": \"$(get_utc_date)\", \"Command\": \"$COMMAND\", \"Message\": \"$MESSAGE\"}"

      # This function creates the directory if it does not already exist
      create_directory $LOG_PATH

      echo $CONTEXT >> $LOG_PATH/error.log

    else
      echo "This function takes 1 positional argument(s) $# were provided"
  fi
}


# TODO review logging functionality
# TODO Make function and extract for a DRY approach
run_cmd () {
  # Performing command validation to ensure the command is in the path

  # Setting local variables
  local COMMAND=$1
  local FLAGS=$2

  # This function validates the command is in the path and runs the command if it exist
  if command_exists_run $COMMAND
    then
      # Setting local variables
      local FULL_COMMAND="$COMMAND $FLAGS"

      $FULL_COMMAND 2>/dev/null

    else
      # This function will create a JSON error message, if the command is not found in the current path
      log_command_error_message $COMMAND
  fi
  }


save_json () {
  # This function takes in 2 arguments to create a unique file path/name

  if [[ $# -eq 2 ]]
    then
      # Setting local variables
      local SELF=$1
      local TYPE=$2

      # This function creates the directory if it does not already exist
      create_directory "$EVIDENCE_PATH/$TYPE"

      echo "[$CONTEXT]" | tee "$EVIDENCE_PATH/$TYPE/$SELF$FILE_TIMESTAMP.json"

  else
    echo "This function takes 2 positional argument(s) $# were provided"
  fi
}


get_system_info () {
  # This function is used to gather key information on the system leveraging the "uname" command

  if [[ $# -eq 0 ]]
    then
      # Setting local variables
      local COMMAND='uname -snrmp'
      local TYPE="config"
      local SELF="system_info_"

      CONTEXT=$(run_cmd $COMMAND)

      CONTEXT=$(echo $CONTEXT | awk '{ print "{\"kernel\": \"" $1 "\",\"node\": \"" $2 "\",\"release\": \"" $3\
                                    "\",\"architecture\": \"" $4 "\",\"processor\": \"" $5 "\"}"}')

      echo "[$CONTEXT]" | save_json $SELF $TYPE

    else
      echo "This function takes 0 positional argument(s) $# were provided"
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


get_running_process_information () {
  # This function is used to collects the running processes using the "ps" command

  if [[ $# -eq 0 ]]
    then
      # Setting local variables
      local COMMAND='ps aux'
      local TYPE="state"
      local SELF="running_processes_"

      CONTEXT=$(run_cmd $COMMAND | awk '{ if ( NR > 1  ) { print "{\"guid\": \"" $1  "\",\"pid\": \"" $2\
                                         "\",\"time\": \""  $9 "\",\"command\": \"" $11 "\"},"}}')

      echo "[$CONTEXT]" | save_json $SELF $TYPE
    else
      echo "This function takes 0 positional argument(s) $# were provided"
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
# lsof field names: COMMAND     PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
  pass
}


# TODO Create function
# TODO Map output to JSON object
# TODO Export JSON to file
# TODO Create additional functionality that will leverage the "last" and "lastb" and save to same output file
# TODO dedup input from multiple commands
get_user_information () {
# This function is used to collect the current activity on the system using the "w" command

  if [[ $# -eq 0 ]]
    then
      # Setting local variables
      local COMMAND='w -hi'
      local TYPE="state"
      local SELF="user_information_"

      CONTEXT=$(run_cmd $COMMAND  | awk '{ print "{\"guid\": \"" $1  "\",\"tty\": \"" $2\
                                        "\",\"from\": \""  $3 "\",\"login\": \"" $4 "\"},"}')

      echo "[$CONTEXT]" | save_json $SELF $TYPE
    else
      echo "This function takes 0 positional argument(s) $# were provided"
  fi
}


get_loaded_modules () {
  # This function collects loaded kernel modules
  # lsmod could also be leveraged if the JSON output is updated

  if [[ $# -eq 0 ]]
    then
      # Setting local variables
      local COMMAND='kextstat -akl'
      local TYPE="state"
      local SELF="kernel_modules_"

      CONTEXT=$(run_cmd $COMMAND  | awk '{ print "{\"index\": \"" $1  "\",\"refs\": \"" $2 "\",\"address\": \""  $3\
                                          "\",\"size\": \"" $4 "\",\"wired\": \"" $5 "\",\"architecture\": \"" $6\
                                           "\",\"name\": \"" $7 "\"}"}')

      echo "[$CONTEXT]" | save_json $SELF $TYPE

    else
      echo "This function takes 0 positional argument(s) $# were provided"
  fi
}


main () {
  # This function test to see if the script is run as the root user or superuser \"[ "$EUID" == 0 ] || usage\"
  # then if the test passes the functions are executed else a usage statement is presented to the user

  if [ "$EUID" == 0 ]
    then

      # This function is used to gather key information on the system leveraging the "uname" command
      echo "Gathering system information with \"uname -snrmp\""
      get_system_info

      # This function is used to collects the running processes using the "ps" command
      echo "Gathering system information with \"ps -aux\""
      get_running_process_information

      # This function is used to collect the current activity on the system using the "w" command
      echo "Gathering system information with \"w -hi\""
      get_user_information

      # This function is used to collect the loaded kernel modules using the "kextstat" command
      echo "Gathering system information with \"kextstat -akl\""
      get_loaded_modules

    else

      # This function prints a usage statement to screen when the validation test fails
      usage
  fi
}

# This is the start of the program, this function executes the above commands
time_it main