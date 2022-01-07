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
for full_command in "${COMMANDS[@]}"
  do
#    Validating the command is in the path
    command=${full_command/\s.*//}
    [ $(command -v $command )  ] || continue
#    Running the command on the host
    echo "Running $full_command at $(get_utc_date)"
    $full_command
  done
}


main () {
  run_commands
}

main