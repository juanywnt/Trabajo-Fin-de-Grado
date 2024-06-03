import boto3
from bckcompliance import *
#map with available commands
commands = {
    "comm": discovery_report
}
if __name__ == "__main__":
    while True:
        #wait for user command input
        command = input("tool>")
        #if command in map, execute command, else print invalid command
        if command in commands:
            #execute function in map
            commands[command]()
        else:
            print("Invalid command")
    

