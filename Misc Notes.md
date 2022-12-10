#### Linux Find command ####
+ Will search for a file and return the path to that file
+ `Find <path to search from> <file>`
	+ `-name` will search by file name
	+ `-iname` will be case insensitive 
		+ Though on mac this is equivalent 
	+ `2>/dev/null` Will dump non useful info 
	+ Putting `*<file>*` will check if what is inputed is anywhere in the name
https://www.youtube.com/watch?v=skTiK_6DdqU

#### scp ####
+ send a File: `scp file.txt remote_username@10.10.0.2:/remote/directory`
+ send a Directory: `scp -r /local/directory remote_username@10.10.0.2:/remote/directory`

+ get a File: `remote_username@10.10.0.2:/remote/file.txt /local/directory`
+ get a Directory: `scp -r remote_username@10.10.0.2:/remote/ /local/directory

#### tldr ####
+ Can prepend this to a command line tool to see example of usage 

#### Kali upkeep ####
+ `apt-get update && apt-get upgrade && apt-get dist-upgrade`
	+ Should usually run twice to see if anything else needs to be done, might have to do `apt autoremove` 
	+ Then `shutdown -r now`

#### SSH Key ####
+ `ssh-keygen -t ed25519 -C "your_email@example.com"`