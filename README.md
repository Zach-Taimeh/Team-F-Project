# teamF
- Database Fill Script contains the Python script (VT.py) that allows you to fill the database with hash values and metadata from Virus Total. It also contains vs0.txt is a text file containing over 1mil virus hashes. Please use another hash file from https://virusshare.com/hashes to fill the database since document 0 is already in use by Devon. 
- The templates folder contains the HTML web pages
- 447_Project.py is the main backend with Flask and MongoDB connections
- Templates folder contains the following files: Homepage.html, Viewhash.html,Login.html 
- Tempaltes folder files are the HTML tempaltes used for styling purposes for each portion of our application
- User.py : This is the file used for user account managment in regard to creating a user account, keeping track of most recent searches for a user
- user.py mongo 
- Config.json: contains information such as the API key,mongodb password,Virustotal Api key,port and secret_key
- Hashmanager.py - this file ismanaging the hashes i.e determing if the user has put in valid input, if the hash is malicous,as well as retriving detection information based on the user input
