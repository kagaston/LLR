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

if_in_path_run (){
  local arg=$1
  # shellcheck disable=SC2046
  [ $(command -v "$arg") ] || continue
  return 0
}

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
for command in "${COMMANDS[@]}"
  do
#    Validating the command is in the path
    [ $(command -v ${command/\s.*//} )  ] || continue
#    Running the command on the host
    echo "Running $command at $(get_utc_date)"
    $command
  done
}


main () {
  run_commands
}

main