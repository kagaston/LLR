#!/usr/bin/env bash

# TODO add functionality for usage if [[ $? == 0 ]]; then
# TODO add older check and creation
# TODO add function to create timestamp for file
# TODO add function to create file each command with unique file name
# TODO create array wth commands
# TODO create find command to blob all log files on the host
# TODO separate log files by compressed uncompressed
# TODO collect etc config files
# TODO collect history files for root and all other users
# TODO collect & hash all executable files
# TODO make loop to gather proc data

[ "$EUID" == 0 ] || echo "For full functionality this script needs to be run as root"

COMMANDS=('uname -pmnsr'            # This will collect the initial system information
          'ps -AaCcEefjlMmrSTvwx'   # This will collect the running processes
          'kextstat'                # This will collect loaded modules
          'lsmod'
          'df'
          'mount'
          'w'
          'last'
          'lastb'
          'ifconfig -a'
          'route'
          'netstat -tulpn'
          'ss -tulpn'
          'lsof -Pni'
          'netstat -rn'
)


get_utc_date () {
  DATE_UTC=$(TZ=":UTC" date)
  echo "$DATE_UTC"
}

run_commands () {
  # Looping through array of commands
  for command in "${COMMANDS[@]}"
    do
      # Validating the command is in the path
      # Skipping command if not in path
      [ $(command -v ${command/\s.*//} )  ] && echo "Running \"$command\" $(get_utc_date)" || continue
      $command
      echo
    done
}

get_logs (){
  # Create log directory if it does not exist in current working directory
  [ -d ./logs ] || mkdir -p ./logs

  # iterate through the results
  for dir in $(find / -type f -name "*.log*" 2> /dev/null)
    do
      cat $dir | grep "command"
    done
}


# Start running program::
run_commands
get_logs
